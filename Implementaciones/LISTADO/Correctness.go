package LISTADO

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type CorrectnessStats struct {
	Total   int
	Success int
	Fail    int
}

var rootServers = []string{
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

// ✅ Versión que agrupa por TLD ÚNICO
func RunCorrectness(domains []string) map[string]CorrectnessStats {
	fmt.Println("\n=== Punto 4 - RSI Correctness (TLD Único) ===")

	result := make(map[string]CorrectnessStats)

	// 1. Agrupa TLDs únicos
	tldSet := map[string]bool{}
	for _, domain := range domains {
		tld := getTLD(domain)
		tldSet[tld] = true
	}

	fmt.Printf("TLDs detectados: %v\n", tldSet)

	// 2. Ejecuta solo una vez por TLD
	for tld := range tldSet {
		fmt.Printf("\nValidando TLD: %s\n", tld)

		ips := resolveTLDServers(tld)
		for _, ip := range ips {
			version := "-v4"
			if ip.To4() == nil {
				version = "-v6"
			}

			ipStr := ip.String()
			fmt.Printf(" Validando NS IP %s\n", ipStr)
			stats := validateAll(ipStr, tld, false)
			result[ipStr+version] = stats
		}
	}

	return result
}

func getTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "."
	}
	return parts[len(parts)-1] + "."
}

func resolveTLDServers(tld string) []net.IP {
	fmt.Printf(" Resolviendo NS de %s...\n", tld)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(tld), dns.TypeNS)

	client := &dns.Client{}

	var resp *dns.Msg
	var err error

	// Reintenta usando lista de root servers
	for _, root := range rootServers {
		ipRecords, _ := net.LookupIP(root)
		if len(ipRecords) == 0 {
			continue
		}
		rootIP := ipRecords[0].String()
		resp, _, err = client.Exchange(m, net.JoinHostPort(rootIP, "53"))
		if err == nil && resp != nil && len(resp.Ns) > 0 {
			break
		}
	}

	if resp == nil || len(resp.Ns) == 0 {
		fmt.Printf("  Error resolviendo NS para %s: %v\n", tld, err)
		return nil
	}

	var ips []net.IP
	for _, rr := range resp.Ns {
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

func validateAll(ip string, tld string, useTCP bool) CorrectnessStats {
	queries := []struct {
		name     string
		qtype    uint16
		expected string
	}{
		{tld, dns.TypeSOA, "positive"},
		{tld, dns.TypeNS, "positive"},
		{tld, dns.TypeDNSKEY, "positive"},
		{"doesnotexist." + tld, dns.TypeA, "negative"},
	}

	stats := CorrectnessStats{}
	for _, q := range queries {
		fmt.Printf("  Validando %s (%s) %d para IP %s\n", q.name, q.expected, q.qtype, ip)
		ok, err := validateCorrectness(ip, q.name, q.qtype, useTCP)

		stats.Total++
		if err == nil && ok {
			stats.Success++
		} else {
			stats.Fail++
		}
	}
	return stats
}

func validateCorrectness(ip, qname string, qtype uint16, useTCP bool) (bool, error) {
	m := new(dns.Msg)
	m.SetEdns0(1220, true)
	m.SetQuestion(dns.Fqdn(qname), qtype)

	client := &dns.Client{Timeout: 4 * time.Second}
	if useTCP {
		client.Net = "tcp"
	}
	resp, _, err := client.Exchange(m, net.JoinHostPort(ip, "53"))
	if err != nil || resp == nil {
		return false, fmt.Errorf("query failed: %v", err)
	}

	if resp.Rcode == dns.RcodeNameError {
		hasSOA, hasNSEC := false, false
		for _, rr := range resp.Ns {
			switch rr.Header().Rrtype {
			case dns.TypeSOA:
				hasSOA = true
			case dns.TypeNSEC, dns.TypeNSEC3:
				hasNSEC = true
			}
		}
		if hasSOA && hasNSEC {
			return true, nil
		}
		return false, fmt.Errorf("NXDOMAIN inválido")
	}

	switch qtype {
	case dns.TypeSOA:
		if !resp.Authoritative {
			return false, fmt.Errorf("SOA sin AA")
		}
		hasSOA, hasRRSIG := false, false
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype == dns.TypeSOA {
				hasSOA = true
			}
			if rr.Header().Rrtype == dns.TypeRRSIG {
				hasRRSIG = true
			}
		}
		if hasSOA && hasRRSIG {
			return true, nil
		}
		return false, fmt.Errorf("SOA incompleto")
	case dns.TypeNS:
		if !resp.Authoritative {
			return false, fmt.Errorf("NS sin AA")
		}
		hasNS, hasRRSIG := false, false
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype == dns.TypeNS {
				hasNS = true
			}
			if rr.Header().Rrtype == dns.TypeRRSIG {
				hasRRSIG = true
			}
		}
		if hasNS && hasRRSIG {
			return true, nil
		}
		return false, fmt.Errorf("NS incompleto")
	case dns.TypeDNSKEY:
		if !resp.Authoritative {
			return false, fmt.Errorf("DNSKEY sin AA")
		}
		hasKEY, hasRRSIG := false, false
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype == dns.TypeDNSKEY {
				hasKEY = true
			}
			if rr.Header().Rrtype == dns.TypeRRSIG {
				hasRRSIG = true
			}
		}
		if hasKEY && hasRRSIG {
			return true, nil
		}
		return false, fmt.Errorf("DNSKEY incompleto")
	default:
		return false, fmt.Errorf("Qtype %d no manejado", qtype)
	}
}
