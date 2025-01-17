package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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
	// Iniciar servidor web con Gin
	r := gin.Default()

	// Ruta para analizar un dominio
	r.GET("/analyze/:domain", func(c *gin.Context) {
		domain := c.Param("domain")

		// Verificar formato correcto
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}

		results, err := analyzeDomain(domain)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Responder con resultados en JSON
		c.JSON(http.StatusOK, results)
	})

	// Iniciar servidor en el puerto 8080
	r.Run(":8080")
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
