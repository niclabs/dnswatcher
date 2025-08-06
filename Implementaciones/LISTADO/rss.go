package LISTADO

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/miekg/dns"
)

type RootMetric struct {
	Server       string
	Success      bool
	ResponseTime time.Duration
	Error        string
}

func RunRSSMetrics() []RootMetric {
	fmt.Println("\n=== Punto 11 - Métricas agregadas a nivel RSS ===")

	rootServers := []string{
		"a.root-servers.net", "b.root-servers.net", "c.root-servers.net",
		"d.root-servers.net", "e.root-servers.net", "f.root-servers.net",
		"g.root-servers.net", "h.root-servers.net", "i.root-servers.net",
		"j.root-servers.net", "k.root-servers.net", "l.root-servers.net",
		"m.root-servers.net",
	}

	var results []RootMetric

	for _, root := range rootServers {
		ips, err := net.LookupIP(root)
		if err != nil || len(ips) == 0 {
			results = append(results, RootMetric{Server: root, Success: false, Error: "no se resolvió IP"})
			continue
		}

		// Solo usa la primera IP (preferimos IPv4 si hay)
		ip := selectIPv4(ips)
		if ip == "" {
			ip = ips[0].String() // Si no hay IPv4, usa IPv6
		}

		start := time.Now()
		m := new(dns.Msg)
		m.SetQuestion(".", dns.TypeSOA)
		m.SetEdns0(1220, true)

		client := &dns.Client{Timeout: 3 * time.Second}
		resp, _, err := client.Exchange(m, net.JoinHostPort(ip, "53"))
		elapsed := time.Since(start)

		r := RootMetric{
			Server:       root + " (" + ip + ")",
			ResponseTime: elapsed,
		}

		if err != nil || resp == nil || len(resp.Answer) == 0 {
			r.Success = false
			if err != nil {
				r.Error = err.Error()
			} else {
				r.Error = "sin respuesta"
			}
		} else {
			r.Success = true
		}

		results = append(results, r)
	}

	return results
}

func selectIPv4(ips []net.IP) string {
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

func MedianDuration(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	return durations[len(durations)/2]
}
