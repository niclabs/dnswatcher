package LISTADO

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Datos resumidos
type DisponibilidadStats struct {
	IPv4UDP int
	IPv4TCP int
	IPv6UDP int
	IPv6TCP int

	IPv4Total int
	IPv6Total int

	IPv4Set map[string]bool
	IPv6Set map[string]bool

	LatenciasUDP []time.Duration
	LatenciasTCP []time.Duration
}

// Ejecuta resolución A/AAAA + UDP/TCP
func RunDisponibilidad(domains []string) DisponibilidadStats {
	fmt.Println("=== Punto 1 & 2 & 3 - RSI Availability & Response Latency ===")

	stats := DisponibilidadStats{
		IPv4Set: make(map[string]bool),
		IPv6Set: make(map[string]bool),
	}

	udpSupport := make(map[string]bool)
	tcpSupport := make(map[string]bool)

	for _, domain := range domains {
		fmt.Printf("\nDominio: %s\n", domain)

		ipv4s := resolveDNS(domain, dns.TypeA)
		ipv6s := resolveDNS(domain, dns.TypeAAAA)

		if len(ipv4s) == 0 {
			fmt.Println("  IPv4: No disponible")
		} else {
			fmt.Printf("  IPv4: %s\n", strings.Join(ipv4s, ", "))
			for _, ip := range ipv4s {
				okUDP, latencyUDP := testTransport(ip, false)
				okTCP, latencyTCP := testTransport(ip, true)

				stats.IPv4Set[ip] = true
				stats.IPv4Total++

				if okUDP {
					udpSupport[ip+"-v4"] = true
					stats.LatenciasUDP = append(stats.LatenciasUDP, latencyUDP)
				}
				if okTCP {
					tcpSupport[ip+"-v4"] = true
					stats.LatenciasTCP = append(stats.LatenciasTCP, latencyTCP)
				}

				fmt.Printf("    IP: %s | UDP: %v (%.2fms) | TCP: %v (%.2fms)\n",
					ip, okUDP, latencyUDP.Seconds()*1000, okTCP, latencyTCP.Seconds()*1000)
			}
		}

		if len(ipv6s) == 0 {
			fmt.Println("  IPv6: No disponible")
		} else {
			fmt.Printf("  IPv6: %s\n", strings.Join(ipv6s, ", "))
			for _, ip := range ipv6s {
				okUDP, latencyUDP := testTransport(ip, false)
				okTCP, latencyTCP := testTransport(ip, true)

				stats.IPv6Set[ip] = true
				stats.IPv6Total++

				if okUDP {
					udpSupport[ip+"-v6"] = true
					stats.LatenciasUDP = append(stats.LatenciasUDP, latencyUDP)
				}
				if okTCP {
					tcpSupport[ip+"-v6"] = true
					stats.LatenciasTCP = append(stats.LatenciasTCP, latencyTCP)
				}

				fmt.Printf("    IP: %s | UDP: %v (%.2fms) | TCP: %v (%.2fms)\n",
					ip, okUDP, latencyUDP.Seconds()*1000, okTCP, latencyTCP.Seconds()*1000)
			}
		}
	}

	// Resumen UDP/TCP
	for ip := range udpSupport {
		if strings.HasSuffix(ip, "-v4") {
			stats.IPv4UDP++
		} else {
			stats.IPv6UDP++
		}
	}
	for ip := range tcpSupport {
		if strings.HasSuffix(ip, "-v4") {
			stats.IPv4TCP++
		} else {
			stats.IPv6TCP++
		}
	}

	// Resumen general
	fmt.Println("\n--- Resumen RSI Availability & Transporte ---")
	fmt.Printf("Cantidad total de direcciones (SIN REPETICIONES):\n")
	fmt.Printf("IPv4: %d\n", len(stats.IPv4Set))
	fmt.Printf("IPv6: %d\n", len(stats.IPv6Set))

	fmt.Printf("\nCantidad total de direcciones (CON REPETICIONES):\n")
	fmt.Printf("IPv4: %d\n", stats.IPv4Total)
	fmt.Printf("IPv6: %d\n", stats.IPv6Total)

	fmt.Printf("\nDisponibilidad por tipo de transporte:\n")
	fmt.Printf("IPv4 UDP: %d\n", stats.IPv4UDP)
	fmt.Printf("IPv4 TCP: %d\n", stats.IPv4TCP)
	fmt.Printf("IPv6 UDP: %d\n", stats.IPv6UDP)
	fmt.Printf("IPv6 TCP: %d\n", stats.IPv6TCP)

	return stats
}

// Resuelve registros A o AAAA
func resolveDNS(domain string, qtype uint16) []string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil
	}

	var results []string
	for _, a := range r.Answer {
		switch rr := a.(type) {
		case *dns.A:
			results = append(results, rr.A.String())
		case *dns.AAAA:
			results = append(results, rr.AAAA.String())
		}
	}
	return results
}

// Prueba SOA por transporte
func testTransport(ip string, useTCP bool) (bool, time.Duration) {
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeSOA)
	m.SetEdns0(1220, true) // Esto habilita NSID

	client := &dns.Client{Timeout: 4 * time.Second}
	if useTCP {
		client.Net = "tcp"
	} else {
		client.Net = "udp"
	}
	start := time.Now()
	resp, _, err := client.Exchange(m, net.JoinHostPort(ip, "53"))
	latency := time.Since(start)

	if err != nil || resp == nil {
		return false, latency
	}

	for _, extra := range resp.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			for _, option := range opt.Option {
				if nsid, ok := option.(*dns.EDNS0_NSID); ok {
					fmt.Printf("      NSID: %x\n", nsid.Nsid)
				}
			}
		}
	}

	return true, latency
}
