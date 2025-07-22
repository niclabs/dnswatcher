package LISTADO

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Resultado extendido para puntos 5, 6 y 7
type DNSSECStats struct {
	Total         int
	Success       int
	Fail          int
	FailedDetails []string
}

// Ejecuta validación DS y tasa éxito/fallo
func RunDNSSECStats(domains []string) map[string]DNSSECStats {
	fmt.Println("\n=== Punto 5, 6 y 7 - DNSSEC Validation ===")
	result := make(map[string]DNSSECStats)

	for _, domain := range domains {
		fmt.Printf("\nDominio: %s\n", domain)
		tld := getTLD(domain)
		fmt.Printf(" TLD: %s\n", tld)

		// 1. Obtener DS record desde zona padre
		dsRecords := queryDS(domain)
		if len(dsRecords) == 0 {
			fmt.Println("No se encontró registro DS")
		} else {
			fmt.Printf("  DS encontrados: %d\n", len(dsRecords))
		}

		// 2. Obtener DNSKEY desde zona child
		dnskeyRecords := queryDNSKEY(domain)
		if len(dnskeyRecords) == 0 {
			fmt.Println("No se encontró DNSKEY")
		} else {
			fmt.Printf("  DNSKEY encontrados: %d\n", len(dnskeyRecords))
		}

		stats := DNSSECStats{}

		// 3. Para cada DS, intentar match con DNSKEY
		for _, ds := range dsRecords {
			stats.Total++
			match := false
			for _, dnskey := range dnskeyRecords {
				if verifyDSMatch(ds, dnskey) {
					match = true
					break
				}
			}
			if match {
				stats.Success++
			} else {
				stats.Fail++
				stats.FailedDetails = append(stats.FailedDetails,
					fmt.Sprintf("ERROR[DS_MISMATCH] DS KeyTag=%d no coincide con ninguna DNSKEY", ds.KeyTag))
			}
		}

		// 4. Si hay DNSKEY pero no hay DS (mala delegación)
		if len(dsRecords) == 0 && len(dnskeyRecords) > 0 {
			stats.Total++
			stats.Fail++
			stats.FailedDetails = append(stats.FailedDetails, "ERROR[NO_DS] Hay DNSKEY pero no DS en el padre")
		}

		// 5. Si hay DS pero no DNSKEY (posible rotura)
		if len(dsRecords) > 0 && len(dnskeyRecords) == 0 {
			stats.Total += len(dsRecords)
			stats.Fail += len(dsRecords)
			stats.FailedDetails = append(stats.FailedDetails, "ERROR[NO_DNSKEY] Hay DS pero no se pudo obtener ninguna DNSKEY")
		}

		// 6. Si no hay ni DS ni DNSKEY, no es error real
		if len(dsRecords) == 0 && len(dnskeyRecords) == 0 {
			stats.FailedDetails = append(stats.FailedDetails, "No hay DS ni DNSKEY: zona no firmada")
		}

		result[domain] = stats
	}

	return result
}

func resolveDomainNSIPs(domain string) []net.IP {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)

	client := &dns.Client{}
	resp, _, err := client.Exchange(m, "8.8.8.8:53")
	if err != nil || resp == nil {
		return nil
	}

	var ips []net.IP
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			nsName := ns.Ns
			ipRecords, err := net.LookupIP(nsName)
			if err == nil {
				ips = append(ips, ipRecords...)
			}
		}
	}
	return ips
}

// Consulta registros DS usando root servers
func queryDS(domain string) []*dns.DS {
	tld := getTLD(domain)
	nsIPs := resolveTLDServers(tld)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDS)

	client := &dns.Client{}
	var resp *dns.Msg

	for _, ip := range nsIPs {
		respTry, _, err := client.Exchange(m, net.JoinHostPort(ip.String(), "53"))
		if err == nil && respTry != nil && len(respTry.Answer) > 0 {
			resp = respTry
			break
		}
	}

	var results []*dns.DS
	if resp != nil {
		for _, rr := range resp.Answer {
			if ds, ok := rr.(*dns.DS); ok {
				results = append(results, ds)
			}
		}
	}
	return results
}

// Consulta registros DNSKEY directamente
func queryDNSKEY(domain string) []*dns.DNSKEY {
	nsIPs := resolveDomainNSIPs(domain)

	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)

	client := &dns.Client{}
	var resp *dns.Msg

	for _, ip := range nsIPs {
		respTry, _, err := client.Exchange(m, net.JoinHostPort(ip.String(), "53"))
		if err == nil && respTry != nil && len(respTry.Answer) > 0 {
			resp = respTry
			break
		}
	}

	var results []*dns.DNSKEY
	if resp != nil {
		for _, rr := range resp.Answer {
			if key, ok := rr.(*dns.DNSKEY); ok {
				results = append(results, key)
			}
		}
	}
	return results
}

// Verifica hash DS <-> DNSKEY (RFC 4034)
func verifyDSMatch(ds *dns.DS, key *dns.DNSKEY) bool {
	if ds.DigestType == dns.SHA1 {
		expected := key.ToDS(dns.SHA1).Digest
		return strings.EqualFold(ds.Digest, expected)
	} else if ds.DigestType == dns.SHA256 {
		expected := key.ToDS(dns.SHA256).Digest
		return strings.EqualFold(ds.Digest, expected)
	}
	return false
}
