package main

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors" // Importar el middleware CORS
	"github.com/miekg/dns"
	"github.com/niclabs/Observatorio/dnsUtils"
	"golang.org/x/net/idna"
)

type DNSResult struct {
	Server          string  `json:"server"`
	Serial          *uint32 `json:"serial,omitempty"`
	SerialReference *uint32 `json:"serial_reference,omitempty"`
	SerialSync      *bool   `json:"serial_sync,omitempty"`
	Authority       *bool   `json:"authority,omitempty"`
	RecursivityOff  *bool   `json:"recursivity_off,omitempty"`
	TCP             *bool   `json:"tcp,omitempty"`
	Error           string  `json:"error,omitempty"`
}

type DNSResponse struct {
	Results              []DNSResult          `json:"results"`
	DelegationDiagnosis  map[string]interface{} `json:"delegation_diagnosis"`
}

func main() {
	app := fiber.New()

	// Configuración de CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",             // Lista de URLs permitidas, escribir el dominio en forma http://example.cl y separados por una coma, por ejemplo "http://example.com, http://localhost:8082"
		AllowMethods: "GET,POST,HEAD", // Métodos permitidos
	}))

	// Middleware para registrar solicitudes
	app.Use(func(c *fiber.Ctx) error {
		fmt.Printf("Solicitud recibida: %s %s\n", c.Method(), c.OriginalURL())
		return c.Next()
	})

	// Ruta para analizar un dominio
	app.Get("/DrDNS/:domain", func(c *fiber.Ctx) error {
		domain := c.Params("domain")

		// Decodificar el dominio si está en formato URL-encoded
		decodedDomain, err := url.QueryUnescape(domain)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("Error al decodificar el dominio: %v", err),
			})
		}

		// Convertir el dominio a ACE (formato ASCII Compatible Encoding)
		punycode := idna.New()
		aceDomain, err := punycode.ToASCII(decodedDomain)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("Error al convertir el dominio a ACE: %v", err),
			})
		}

		// Verificar formato correcto (FQDN)
		if !strings.HasSuffix(aceDomain, ".") {
			aceDomain += "."
		}

		response, err := analyzeDomain(aceDomain)
		if err != nil {
			// Manejar errores específicos
			if strings.Contains(err.Error(), "No se encontraron servidores NS") {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": err.Error(),
				})
			}
			if strings.Contains(err.Error(), "dominio inválido") {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": err.Error(),
				})
			}
			// Errores internos
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		// Responder con resultados en JSON
		return c.JSON(response)
	})

	// Iniciar el servidor en el puerto 8082
	log.Println("Servidor iniciado en http://localhost:8082")
	log.Fatal(app.Listen(":8082"))
}

func analyzeDomain(domain string) (DNSResponse, error) {
	// Validar que el dominio sea válido
	if len(domain) < 3 || !strings.Contains(domain, ".") {
		return DNSResponse{}, fmt.Errorf("dominio inválido: %s", domain)
	}

	// Convertir el dominio a ACE (formato ASCII)
	punycode := idna.New()
	aceDomain, err := punycode.ToASCII(domain)
	if err != nil {
		return DNSResponse{}, fmt.Errorf("error al convertir el dominio a ACE: %v", err)
	}

	dnsClient := &dns.Client{Timeout: 3 * time.Second}
	dnsServers := []string{"8.8.8.8", "1.1.1.1"} // DNS públicos como respaldo

	// Obtener los servidores NS del dominio (zona primaria)
	msg, _, err := dnsUtils.GetRecordSet(aceDomain, dns.TypeNS, dnsServers, dnsClient)
	if err != nil {
		return DNSResponse{}, fmt.Errorf("error al consultar NS: %v", err)
	}

	if msg == nil || len(msg.Answer) == 0 {
		cleanDomain := strings.TrimSuffix(domain, ".")

		switch msg.Rcode {
		case dns.RcodeNameError:
			return DNSResponse{}, fmt.Errorf("NXDOMAIN: el dominio %s no existe", cleanDomain)
		case dns.RcodeServerFailure:
			return DNSResponse{}, fmt.Errorf("SERVFAIL: el servidor DNS no pudo procesar la solicitud para %s", cleanDomain)
		case dns.RcodeRefused:
			return DNSResponse{}, fmt.Errorf("REFUSED: el servidor DNS rechazó la consulta para %s", cleanDomain)
		default:
			return DNSResponse{}, fmt.Errorf("No se encontraron servidores NS para el dominio %s (Rcode: %s)", cleanDomain, dns.RcodeToString[msg.Rcode])
		}
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

	// Llamar a getParentNS con el dominio en formato ACE
	parentNS, err := getParentNS(aceDomain)
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
	delegationDiagnosis := make(map[string]interface{})
	if len(missingInZone) > 0 {
		delegationDiagnosis["status"] = "warning"
		delegationDiagnosis["message"] = fmt.Sprintf("Servidor de nombres %s presente en la zona padre, pero no en la lista de NS en el primario", strings.Join(missingInZone, ", "))
		delegationDiagnosis["missing_nameservers"] = missingInZone
	} else {
		delegationDiagnosis["status"] = "ok"
		delegationDiagnosis["message"] = "No se encontraron discrepancias en la delegación."
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
			result.Error = "NS no verificable: " + err.Error()
			hasCriticalError = true
		} else if soaMsg == nil {
			result.Error = "NS no verificable: respuesta nula"
			hasCriticalError = true
		} else if soaMsg.Rcode != dns.RcodeSuccess {
			rcodeText := dns.RcodeToString[soaMsg.Rcode]
			if rcodeText == "" {
				rcodeText = fmt.Sprintf("RCODE %d", soaMsg.Rcode)
			}
			result.Error = fmt.Sprintf("NS no verificable: %s", rcodeText)
			hasCriticalError = true
		} else {
			// Procesamiento normal si la respuesta es válida y exitosa
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
			if serialFound && authoritative {
				serials[ns] = &serial
				result.Serial = &serial
				result.Authority = &authoritative
			} else {
				result.Error = "NS no verificable: sin SOA autoritativo"
				hasCriticalError = true
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
		if results[i].Serial != nil {
			serialSync := *results[i].Serial == *referenceSerial
			results[i].SerialSync = &serialSync
			results[i].SerialReference = referenceSerial
		}
	}

	// Devolver resultados
	return DNSResponse{
		Results:       results,
		DelegationDiagnosis: delegationDiagnosis,
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
	punycode := idna.New()
	aceDomain, err := punycode.ToASCII(domain)
	if err != nil {
		log.Printf("Error al convertir dominio a ACE: %v\n", err)
		return false
	}

	client := &dns.Client{Timeout: 5 * time.Second, Net: "tcp"}
	msg := new(dns.Msg)
	msg.SetQuestion(aceDomain, dns.TypeSOA)

	_, _, err = client.Exchange(msg, server+":53")
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
		if serial != nil {
			return serial // primer serial encontrado
		}
	}
	return nil
}

func getParentNS(domain string) ([]string, error) {
	dnsClient := &dns.Client{Timeout: 3 * time.Second}
	rootServers := []string{
		//"1.1.1.1",    // Cloudflare
		//"8.8.8.8",    // Google
		//"9.9.9.9",    // Quad9
		//"198.41.0.4", // Root Server
		"a.root-servers.net",
		"b.root-servers.net",
		"c.root-servers.net",
		"d.root-servers.net",
		"e.root-servers.net",
		"f.root-servers.net",
		"g.root-servers.net",
		"h.root-servers.net",
		"i.root-servers.net",
		"j.root-servers.net",
		"k.root-servers.net",
		"l.root-servers.net",
		"m.root-servers.net",
	}

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
