package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

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

func measureLatency(ip string, useTCP bool) (bool, time.Duration) {
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeSOA)
	client := &dns.Client{
		Timeout: 4 * time.Second,
	}
	if useTCP {
		client.Net = "tcp"
	} else {
		client.Net = "udp"
	}
	start := time.Now()
	_, _, err := client.Exchange(m, ip+":53")
	latency := time.Since(start)
	return err == nil, latency
}

func main() {
	file, err := os.Open("input-example.txt")
	if err != nil {
		fmt.Println("Error leyendo archivo:", err)
		return
	}
	defer file.Close()

	outFile, err := os.Create("OUT.txt")
	if err != nil {
		fmt.Println("Error creando archivo de salida:", err)
		return
	}
	defer outFile.Close()

	ipv4Set := make(map[string]bool)
	ipv6Set := make(map[string]bool)

	tcpSupport := make(map[string]bool)
	udpSupport := make(map[string]bool)

	ipv4TotalCount := 0
	ipv6TotalCount := 0

	ipv4UDPCount, ipv4TCPCount := 0, 0
	ipv6UDPCount, ipv6TCPCount := 0, 0

	var latenciasUDP, latenciasTCP []time.Duration

	scanner := bufio.NewScanner(file)
	domainCount := 0

	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}
		domainCount++

		ipv4 := resolveDNS(domain, dns.TypeA)
		ipv6 := resolveDNS(domain, dns.TypeAAAA)

		if len(ipv4) == 0 && len(ipv6) == 0 {
			fmt.Printf("No se pudo resolver o interpretar '%s'\n", domain)
			continue
		}

		fmt.Fprintf(outFile, "\nDominio: %s\n", domain)

		ipv4UDP, ipv4TCP := 0, 0
		for _, ip := range ipv4 {
			okUDP, latencyUDP := measureLatency(ip, false)
			okTCP, latencyTCP := measureLatency(ip, true)

			ipv4Set[ip] = true
			ipv4TotalCount++

			if okUDP {
				udpSupport[ip] = true
				ipv4UDP++
				ipv4UDPCount++
				latenciasUDP = append(latenciasUDP, latencyUDP)
			}
			if okTCP {
				tcpSupport[ip] = true
				ipv4TCP++
				ipv4TCPCount++
				latenciasTCP = append(latenciasTCP, latencyTCP)
			}
		}

		ipv6UDP, ipv6TCP := 0, 0
		for _, ip := range ipv6 {
			okUDP, latencyUDP := measureLatency(ip, false)
			okTCP, latencyTCP := measureLatency(ip, true)

			ipv6Set[ip] = true
			ipv6TotalCount++

			if okUDP {
				udpSupport[ip] = true
				ipv6UDP++
				ipv6UDPCount++
				latenciasUDP = append(latenciasUDP, latencyUDP)
			}
			if okTCP {
				tcpSupport[ip] = true
				ipv6TCP++
				ipv6TCPCount++
				latenciasTCP = append(latenciasTCP, latencyTCP)
			}
		}

		fmt.Fprintf(outFile, "  IPv4 -> Total: %d | UDP: %d | TCP: %d\n", len(ipv4), ipv4UDP, ipv4TCP)
		fmt.Fprintf(outFile, "  IPv6 -> Total: %d | UDP: %d | TCP: %d\n", len(ipv6), ipv6UDP, ipv6TCP)
	}

	fmt.Fprintf(outFile, "\nCantidad total de dominios evaluados: %d\n", domainCount)
	fmt.Fprintf(outFile, "Cantidad total de direcciones (SIN REPETICIONES):\n")
	fmt.Fprintf(outFile, "IPv4: %d\n", len(ipv4Set))
	fmt.Fprintf(outFile, "IPv6: %d\n", len(ipv6Set))
	fmt.Fprintf(outFile, "Cantidad total de direcciones (CON REPETICIONES):\n")
	fmt.Fprintf(outFile, "IPv4: %d\n", ipv4TotalCount)
	fmt.Fprintf(outFile, "IPv6: %d\n", ipv6TotalCount)
	fmt.Fprintf(outFile, "\nDisponibilidad por tipo de transporte:\n")
	fmt.Fprintf(outFile, "Soportan UDP: %d\n", len(udpSupport))
	fmt.Fprintf(outFile, "Soportan TCP: %d\n", len(tcpSupport))
	fmt.Fprintf(outFile, "\nResumen agregado por tipo de transporte y protocolo:\n")
	fmt.Fprintf(outFile, "IPv4 UDP disponibles: %d\n", ipv4UDPCount)
	fmt.Fprintf(outFile, "IPv4 TCP disponibles: %d\n", ipv4TCPCount)
	fmt.Fprintf(outFile, "IPv6 UDP disponibles: %d\n", ipv6UDPCount)
	fmt.Fprintf(outFile, "IPv6 TCP disponibles: %d\n", ipv6TCPCount)

	if len(latenciasUDP) > 0 {
		sort.Slice(latenciasUDP, func(i, j int) bool { return latenciasUDP[i] < latenciasUDP[j] })
		medianaUDP := latenciasUDP[len(latenciasUDP)/2]
		estadoUDP := "Cumple (<= 250ms)"
		if medianaUDP > 250*time.Millisecond {
			estadoUDP = "Supera (> 250ms)"
		}
		fmt.Fprintf(outFile, "\nLatencia mediana UDP: %v [%s]\n", medianaUDP, estadoUDP)
	}
	if len(latenciasTCP) > 0 {
		sort.Slice(latenciasTCP, func(i, j int) bool { return latenciasTCP[i] < latenciasTCP[j] })
		medianaTCP := latenciasTCP[len(latenciasTCP)/2]
		estadoTCP := "Cumple (<= 500ms)"
		if medianaTCP > 500*time.Millisecond {
			estadoTCP = "Supera (> 500ms)"
		}
		fmt.Fprintf(outFile, "Latencia mediana TCP: %v [%s]\n", medianaTCP, estadoTCP)
	}

	fmt.Println("Proceso finalizado. Resultados finales escritos en OUT.txt")
}
