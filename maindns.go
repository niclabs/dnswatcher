package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/niclabs/Observatorio/dnsUtils"
	"golang.org/x/net/idna"
)

type DNSResult struct {
	Server         string  `json:"server"`
	Serial         *uint32 `json:"serial,omitempty"`
	SerialSync     *bool   `json:"serial_sync,omitempty"`
	Authority      *bool   `json:"authority,omitempty"`
	RecursivityOff *bool   `json:"recursivity_off,omitempty"`
	TCP            *bool   `json:"tcp,omitempty"`
	Error          string  `json:"error,omitempty"`
}

func main() {
	// Verificar si se pasó el dominio como argumento
	if len(os.Args) < 2 {
		fmt.Println("Uso: go run maindns.go <dominio>")
		return
	}

	domain := os.Args[1]

	// Verificar formato correcto
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	results, err := analyzeDomain(domain)
	if err != nil {
		// Guardar error en archivo JSON
		fmt.Println("Error:", err)
		saveErr := saveErrorToFile(domain, err.Error())
		if saveErr != nil {
			fmt.Println("Error guardando resultados de error:", saveErr)
		}
		return
	}

	// Imprimir resultados como JSON
	output, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(output))

	// Guardar resultados en archivo JSON
	err = saveResultsToFile(domain, results)
	if err != nil {
		fmt.Println("Error guardando resultados:", err)
	}
}

func analyzeDomain(domain string) ([]DNSResult, error) {
	dnsClient := &dns.Client{Timeout: 5 * time.Second}
	dnsServers := []string{"8.8.8.8", "1.1.1.1"} // DNS públicos como respaldo

	// Obtener los servidores NS
	msg, _, err := dnsUtils.GetRecordSet(domain, dns.TypeNS, dnsServers, dnsClient)
	if err != nil {
		return nil, fmt.Errorf("error al consultar NS: %v", err)
	}

	// Almacenar los servidores NS
	var nsServers []string
	for _, answer := range msg.Answer {
		if ns, ok := answer.(*dns.NS); ok {
			nsServers = append(nsServers, strings.TrimSuffix(ns.Ns, "."))
		}
	}

	if len(nsServers) == 0 {
		return nil, fmt.Errorf("no se encontraron servidores NS para el dominio %s", domain)
	}

	serials := make(map[string]*uint32)
	var results []DNSResult

	for _, ns := range nsServers {
		result := DNSResult{Server: ns}
		hasCriticalError := false

		// Verificar SOA
		soaMsg, _, err := dnsUtils.GetRecordSet(domain, dns.TypeSOA, []string{ns}, dnsClient)
		if err != nil {
			result.Error = "NS no verificable: query timed out"
			hasCriticalError = true
		} else {
			if soaMsg.Rcode == dns.RcodeServerFailure {
				result.Error = "NS no verificable: SERVFAIL"
				hasCriticalError = true
			} else {
				var serial uint32
				var authoritative bool
				serialFound := false
				for _, answer := range soaMsg.Answer {
					if soa, ok := answer.(*dns.SOA); ok {
						serial = soa.Serial
						authoritative = soaMsg.Authoritative
						serialFound = true
					}
				}
				if serialFound {
					serials[ns] = &serial
					result.Serial = &serial
					result.Authority = &authoritative
				} else {
					hasCriticalError = true
				}
			}
		}

		// Verificar recursividad y EDNS SOLO si no hubo errores críticos
		if !hasCriticalError {
			recursivity, _ := checkRecursivityAndEDNS(domain, ns)
			recursivityOff := !recursivity
			result.RecursivityOff = &recursivityOff

			// Verificar soporte TCP
			tcpSupport := checkTCP(domain, ns)
			result.TCP = &tcpSupport
		}

		// Si hubo errores críticos, limpiar los campos
		if hasCriticalError {
			result.Serial = nil
			result.SerialSync = nil
			result.Authority = nil
			result.RecursivityOff = nil
			result.TCP = nil
		}

		results = append(results, result)
	}

	// Validar sincronización de seriales
	referenceSerial := getReferenceSerial(serials)
	for i := range results {
		if results[i].Serial != nil { // Solo comparamos seriales si el servidor tiene uno válido
			serialSync := *results[i].Serial == *referenceSerial
			results[i].SerialSync = &serialSync
		}

		unicodeName, err := idna.ToUnicode(results[i].Server)
		if err == nil {
			results[i].Server = unicodeName
		}
	}

	return results, nil
}

func checkTCP(domain string, server string) bool {
	client := &dns.Client{Timeout: 5 * time.Second, Net: "tcp"}

	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeSOA)

	_, _, err := client.Exchange(msg, server+":53")
	if err != nil {
		// fmt.Printf("Error verificando TCP en %s: %v\n", server, err)
		return false
	}
	return true
}

func checkRecursivityAndEDNS(domain string, server string) (bool, bool) {
	client := &dns.Client{Timeout: 5 * time.Second, Net: "udp"}
	msg := new(dns.Msg)
	msg.SetQuestion(domain, dns.TypeSOA)
	msg.RecursionDesired = true

	resp, _, err := client.Exchange(msg, server+":53")
	if err != nil {
		// fmt.Printf("Error verificando recursividad en %s: %v\n", server, err)
		return false, false
	}

	recursivity := resp.RecursionAvailable
	edns := resp.IsEdns0() != nil
	return recursivity, edns
}

func getReferenceSerial(serials map[string]*uint32) *uint32 {
	for _, serial := range serials {
		return serial // Usar el primer serial como referencia
	}
	return nil
}

func saveResultsToFile(domain string, results []DNSResult) error {
	// Crear carpeta JSONS si no existe
	dir := "JSONS"
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("no se pudo crear el directorio JSONS: %v", err)
	}

	// Crear archivo con timestamp
	filename := fmt.Sprintf("%s-%s.json", strings.TrimSuffix(domain, "."), time.Now().Format("20060102-150405"))
	filepath := filepath.Join(dir, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("no se pudo crear el archivo: %v", err)
	}
	defer file.Close()

	// Escribir resultados en el archivo
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("no se pudieron escribir los resultados: %v", err)
	}

	fmt.Printf("Resultados guardados en: %s\n", filepath)
	return nil
}

func saveErrorToFile(domain string, errorMsg string) error {
	// Crear carpeta JSONS si no existe
	dir := "JSONS"
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("no se pudo crear el directorio JSONS: %v", err)
	}

	// Crear archivo con timestamp
	filename := fmt.Sprintf("%s-%s-error.json", strings.TrimSuffix(domain, "."), time.Now().Format("20060102-150405"))
	filepath := filepath.Join(dir, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("no se pudo crear el archivo: %v", err)
	}
	defer file.Close()

	// Estructura del error
	errorResult := map[string]string{
		"domain": domain,
		"error":  errorMsg,
	}

	// Escribir error en el archivo
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(errorResult); err != nil {
		return fmt.Errorf("no se pudieron escribir los resultados: %v", err)
	}

	fmt.Printf("Resultados guardados en: %s\n", filepath)
	return nil
}

func getParentNS(domain string, client *dns.Client) ([]string, error) {
	parentDomain := strings.Join(strings.Split(domain, ".")[1:], ".") // Obtener el dominio superior
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(parentDomain), dns.TypeNS)

	resp, _, err := client.Exchange(msg, "8.8.8.8:53") // Consultar a un servidor público como referencia
	if err != nil {
		return nil, err
	}

	var nsRecords []string
	for _, ans := range resp.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			nsRecords = append(nsRecords, strings.TrimSuffix(ns.Ns, "."))
		}
	}
	return nsRecords, nil
}

func getPrimaryNS(domain string, client *dns.Client) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)

	resp, _, err := client.Exchange(msg, "8.8.8.8:53") // Consultar registros NS del dominio
	if err != nil {
		return nil, err
	}

	var nsRecords []string
	for _, ans := range resp.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			nsRecords = append(nsRecords, strings.TrimSuffix(ns.Ns, "."))
		}
	}
	return nsRecords, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
