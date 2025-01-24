package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/miekg/dns"
	"github.com/niclabs/Observatorio/dnsUtils"
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

type DNSResponse struct {
	Results       []DNSResult `json:"results"`
	Discrepancies []string    `json:"discrepancies"`
}

func main() {
	app := fiber.New()

	// Middleware para registrar solicitudes
	app.Use(func(c *fiber.Ctx) error {
		fmt.Printf("Solicitud recibida: %s %s\n", c.Method(), c.OriginalURL())
		return c.Next()
	})

	// Ruta para analizar un dominio
	app.Get("/DrDNS/:domain", func(c *fiber.Ctx) error {
		domain := c.Params("domain")

		// Verificar formato correcto
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}

		response, err := analyzeDomain(domain)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

		// Responder con resultados en JSON
		return c.JSON(response)
	})

	// Iniciar el servidor en el puerto 8082
	log.Println("Servidor iniciado en http://localhost:8082")
	log.Fatal(app.Listen(":8082"))
	//log.Fatal(app.Listen(":8082"))
}

func analyzeDomain(domain string) (DNSResponse, error) {
	dnsClient := &dns.Client{Timeout: 10 * time.Second}
	dnsServers := []string{"8.8.8.8", "1.1.1.1"} // DNS públicos como respaldo

	// Obtener los servidores NS del dominio (zona primaria)
	msg, _, err := dnsUtils.GetRecordSet(domain, dns.TypeNS, dnsServers, dnsClient)
	if err != nil {
		return DNSResponse{}, fmt.Errorf("error al consultar NS: %v", err)
	}

	var nsServers []string
	for _, answer := range msg.Answer {
		if ns, ok := answer.(*dns.NS); ok {
			nsServers = append(nsServers, strings.TrimSuffix(ns.Ns, "."))
		}
	}

	if len(nsServers) == 0 {
		return DNSResponse{}, fmt.Errorf("No se encontraron servidores NS para el dominio %s", domain)
	}

	// Obtener los servidores NS del servidor padre
	parentNS, err := getParentNS(domain)
	if err != nil {
		return DNSResponse{}, fmt.Errorf("error al consultar el servidor padre: %v", err)
	}

	// Comparar las listas: zona primaria vs servidor padre
	missingInZone := []string{} // Servidores en el padre, pero no en la zona primaria

	zoneNSSet := make(map[string]bool)
	for _, ns := range nsServers {
		zoneNSSet[ns] = true
	}

	for _, ns := range parentNS {
		if !zoneNSSet[ns] {
			missingInZone = append(missingInZone, ns)
		}
	}

	// Generar advertencias solo para servidores del servidor padre no presentes en la zona primaria
	var discrepancies []string
	for _, ns := range missingInZone {
		discrepancies = append(discrepancies, ns)
	}

	if len(discrepancies) == 0 {
		discrepancies = append(discrepancies, "Sin errores")
	}

	// Continuar con el análisis adicional (SOA, TCP, etc.)
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

	// fmt.Println("Servidores NS en la zona primaria:", nsServers)
	// fmt.Println("Servidores NS en el servidor padre:", parentNS)

	// Validar sincronización de seriales
	referenceSerial := getReferenceSerial(serials)
	for i := range results {
		if results[i].Serial != nil { // Solo comparamos seriales si el servidor tiene uno válido
			serialSync := *results[i].Serial == *referenceSerial
			results[i].SerialSync = &serialSync
		}
	}

	// Devolver resultados
	return DNSResponse{
		Results:       results,
		Discrepancies: discrepancies,
	}, nil
}

// contains verifica si un elemento está en una lista
func contains(list []string, item string) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
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

func getParentNS(domain string) ([]string, error) {
	dnsClient := &dns.Client{Timeout: 10 * time.Second}
	rootServers := []string{"198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10"} // Ejemplo de servidores raíz

	// Asegurar que el dominio sea un FQDN
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}

	// Paso 1: Consultar los servidores autoritativos para el TLD
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("dominio inválido")
	}
	tld := parts[len(parts)-2] // El penúltimo elemento es el TLD

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(tld+"."), dns.TypeNS)

	var tldServers []string
	for _, rootServer := range rootServers {
		// fmt.Println("Consultando el servidor raíz:", rootServer)
		resp, _, err := dnsClient.Exchange(msg, rootServer+":53")
		if err != nil {
			fmt.Printf("Error consultando el servidor raíz %s: %v\n", rootServer, err)
			continue
		}

		// Extraer servidores TLD de la sección Ns
		for _, answer := range resp.Ns {
			if ns, ok := answer.(*dns.NS); ok {
				tldServers = append(tldServers, strings.TrimSuffix(ns.Ns, "."))
			}
		}

		if len(tldServers) > 0 {
			break
		}
	}

	if len(tldServers) == 0 {
		return nil, fmt.Errorf("no se encontraron servidores TLD para el TLD %s", tld)
	}
	// fmt.Println("Servidores TLD obtenidos:", tldServers)

	// Paso 2: Consultar los servidores TLD para obtener los NS del dominio
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)

	var parentNS []string
	for _, tldServer := range tldServers {
		// fmt.Println("Consultando el servidor TLD:", tldServer)
		resp, _, err := dnsClient.Exchange(msg, tldServer+":53")
		if err != nil {
			fmt.Printf("Error consultando el servidor TLD %s: %v\n", tldServer, err)
			continue
		}

		// Extraer servidores NS del dominio de la sección Authority
		for _, answer := range resp.Ns {
			if ns, ok := answer.(*dns.NS); ok {
				parentNS = append(parentNS, strings.TrimSuffix(ns.Ns, "."))
			}
		}

		if len(parentNS) > 0 {
			break
		}
	}

	if len(parentNS) == 0 {
		return nil, fmt.Errorf("no se pudieron obtener los servidores NS del servidor padre para el dominio %s", domain)
	}
	// fmt.Println("Servidores NS del servidor padre obtenidos:", parentNS)
	return parentNS, nil
}

// Resolver las direcciones IP de los servidores TLD
func resolveServerIPs(servers []string) []string {
	var ips []string
	for _, server := range servers {
		fmt.Println("Resolviendo IP para:", server)
		addrs, err := net.LookupHost(server)
		if err != nil {
			fmt.Printf("Error resolviendo %s: %v\n", server, err)
			continue
		}
		ips = append(ips, addrs[0]) // Usar la primera dirección IP
	}
	return ips
}
