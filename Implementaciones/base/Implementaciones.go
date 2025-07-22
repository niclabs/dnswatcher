package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

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

func getRootServerIPs() (ipv4List []string, ipv6List []string) {
	for _, name := range rootServers {
		ips, err := net.LookupIP(name)
		if err != nil {
			fmt.Printf("Error resolviendo %s: %v\n", name, err)
			continue
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				ipv4List = append(ipv4List, ip.String())
			} else {
				ipv6List = append(ipv6List, ip.String())
			}
		}
	}
	return
}

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

// validateDSConsulta realiza una validación básica de consistencia DS <-> DNSKEY
func validateDS(domain string) (bool, error) {
	domainFQDN := dns.Fqdn(domain)
	tld := strings.ToLower(getParent(domain)) // ej: "cl" para "doite.cl"

	// Elegir servidor del TLD según corresponda
	var parentServer string
	switch tld {
	case "cl.":
		parentServer = "200.7.7.1"
	default:
		parentServer = resolveTLDParent(tld)
	}

	// Obtener los registros DS desde el padre
	msgDS := new(dns.Msg)
	msgDS.SetEdns0(1220, true)
	msgDS.SetQuestion(domainFQDN, dns.TypeDS)

	client := new(dns.Client)
	dsResp, _, err := client.Exchange(msgDS, net.JoinHostPort(parentServer, "53"))
	if err != nil || dsResp == nil || len(dsResp.Answer) == 0 {
		return false, fmt.Errorf("fallo al obtener DS desde %s: %v", parentServer, err)
	}

	dsRRs := []*dns.DS{}
	for _, rr := range dsResp.Answer {
		if ds, ok := rr.(*dns.DS); ok {
			dsRRs = append(dsRRs, ds)
		}
	}
	if len(dsRRs) == 0 {
		return false, fmt.Errorf("no se encontraron DS en la respuesta")
	}

	// Obtener los registros DNSKEY desde el hijo
	msgKEY := new(dns.Msg)
	msgKEY.SetEdns0(1220, true)
	msgKEY.SetQuestion(domainFQDN, dns.TypeDNSKEY)

	keyResp, _, err := client.Exchange(msgKEY, "8.8.8.8:53")
	if err != nil || keyResp == nil || len(keyResp.Answer) == 0 {
		return false, fmt.Errorf("fallo al obtener DNSKEY: %v", err)
	}

	dnskeyRRs := []*dns.DNSKEY{}
	for _, rr := range keyResp.Answer {
		if key, ok := rr.(*dns.DNSKEY); ok {
			dnskeyRRs = append(dnskeyRRs, key)
		}
	}
	if len(dnskeyRRs) == 0 {
		return false, fmt.Errorf("no se encontraron DNSKEY")
	}

	// Validar si algún DS coincide con alguna DNSKEY
	for _, ds := range dsRRs {
		for _, key := range dnskeyRRs {
			calculatedDS := key.ToDS(ds.DigestType)
			if calculatedDS != nil &&
				calculatedDS.Digest == ds.Digest &&
				calculatedDS.KeyTag == ds.KeyTag &&
				calculatedDS.Algorithm == ds.Algorithm {
				return true, nil
			}
		}
	}

	return false, fmt.Errorf("no hay correspondencia DS-DNSKEY")
}

func getParent(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 1 {
		return "."
	}
	return strings.Join(parts[1:], ".")
}

func testTransport(ip string, useTCP bool) (bool, time.Duration) {
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
	_, _, err := client.Exchange(m, net.JoinHostPort(ip, "53"))
	latency := time.Since(start)
	return err == nil, latency
}

// Punto 4 - RSI Correctness (5.3 RSSAC047)
func validateCorrectness(ip, qname string, qtype uint16, useTCP bool) (bool, error) {
	m := new(dns.Msg)
	m.SetEdns0(1220, true)
	m.SetQuestion(dns.Fqdn(qname), qtype)

	client := &dns.Client{Timeout: 4 * time.Second}
	if useTCP {
		client.Net = "tcp"
	}

	resp, _, err := client.Exchange(m, net.JoinHostPort(ip, "53"))
	if err != nil {
		return false, fmt.Errorf("fallo consulta: %v", err)
	}
	if resp == nil {
		return false, fmt.Errorf("respuesta nula")
	}

	if resp.Truncated && !useTCP {
		client.Net = "tcp"
		resp, _, err = client.Exchange(m, net.JoinHostPort(ip, "53"))
		if err != nil {
			return false, fmt.Errorf("reintento TCP fallo: %v", err)
		}
		if resp == nil {
			return false, fmt.Errorf("respuesta nula tras reintento TCP")
		}
	}

	// 1) Verificar Rcode
	if resp.Rcode == dns.RcodeNameError {
		// NXDOMAIN -> Reglas para negative responses
		if !resp.Authoritative {
			return false, fmt.Errorf("NXDOMAIN sin AA")
		}
		if len(resp.Answer) != 0 {
			return false, fmt.Errorf("NXDOMAIN con Answer inesperado")
		}
		hasSOA, hasNSEC := false, false
		for _, rr := range resp.Ns {
			switch rr.Header().Rrtype {
			case dns.TypeSOA:
				hasSOA = true
			case dns.TypeNSEC, dns.TypeNSEC3:
				hasNSEC = true
			}
		}
		if !hasSOA || !hasNSEC {
			return false, fmt.Errorf("NXDOMAIN sin SOA o NSEC/NSEC3")
		}
		for _, rr := range resp.Extra {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue // OK
			}
			// Glue de NS es permitido
			if rr.Header().Rrtype != dns.TypeA && rr.Header().Rrtype != dns.TypeAAAA {
				return false, fmt.Errorf("SOA Additional tiene RRset inesperado: %d", rr.Header().Rrtype)
			}
		}
		return true, nil
	}

	// 2) Verificar por tipo de query positiva
	switch qtype {
	case dns.TypeSOA:
		if !resp.Authoritative {
			return false, fmt.Errorf("SOA sin AA")
		}
		if len(resp.Answer) == 0 {
			return false, fmt.Errorf("SOA sin Answer")
		}
		// Debe existir SOA firmado en Answer
		hasSOA, hasRRSIG := false, false
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype == dns.TypeSOA {
				hasSOA = true
			} else if rr.Header().Rrtype == dns.TypeRRSIG {
				hasRRSIG = true
			}
		}
		if !hasSOA || !hasRRSIG {
			return false, fmt.Errorf("SOA sin RRset o RRSIG")
		}
		// Authority debe contener NS RRset firmado
		hasNS := false
		for _, rr := range resp.Ns {
			if rr.Header().Rrtype == dns.TypeNS {
				hasNS = true
				break
			}
		}
		if !hasNS {
			return false, fmt.Errorf("SOA sin NS en Authority")
		}
		for _, rr := range resp.Extra {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue // OK
			}
			if rr.Header().Rrtype != dns.TypeA && rr.Header().Rrtype != dns.TypeAAAA {
				return false, fmt.Errorf("Additional tiene RRset inesperado: %d", rr.Header().Rrtype)
			}
		}

	case dns.TypeNS:
		if qname == "." {
			if !resp.Authoritative {
				return false, fmt.Errorf("root NS sin AA")
			}
			if len(resp.Answer) == 0 {
				return false, fmt.Errorf("root NS sin Answer")
			}
			hasNS, hasRRSIG := false, false
			for _, rr := range resp.Answer {
				if rr.Header().Rrtype == dns.TypeNS {
					hasNS = true
				} else if rr.Header().Rrtype == dns.TypeRRSIG {
					hasRRSIG = true
				}
			}
			if !hasNS || !hasRRSIG {
				return false, fmt.Errorf("root NS sin NS o RRSIG")
			}
			if len(resp.Ns) != 0 {
				return false, fmt.Errorf("root NS con Authority inesperado")
			}
			for _, rr := range resp.Extra {
				if rr.Header().Rrtype == dns.TypeOPT {
					continue
				}
				if rr.Header().Rrtype != dns.TypeA && rr.Header().Rrtype != dns.TypeAAAA {
					return false, fmt.Errorf("root NS Additional tiene RRset inesperado: %d", rr.Header().Rrtype)
				}
			}
			fmt.Printf("[DEBUG] SOA AA=%v Answer=%d Ns=%d Extra=%d\n",
				resp.Authoritative, len(resp.Answer), len(resp.Ns), len(resp.Extra))

		} else {
			// TLD NS referral
			if resp.Authoritative {
				return false, fmt.Errorf("TLD NS con AA inesperado")
			}
			if len(resp.Answer) != 0 {
				return false, fmt.Errorf("TLD NS con Answer inesperado")
			}
			hasNS := false
			for _, rr := range resp.Ns {
				if rr.Header().Rrtype == dns.TypeNS {
					hasNS = true
				}
			}
			if !hasNS {
				return false, fmt.Errorf("TLD NS sin NS en Authority")
			}
			fmt.Printf("[DEBUG] SOA AA=%v Answer=%d Ns=%d Extra=%d\n",
				resp.Authoritative, len(resp.Answer), len(resp.Ns), len(resp.Extra))

		}

	case dns.TypeDNSKEY:
		if !resp.Authoritative {
			return false, fmt.Errorf("DNSKEY sin AA")
		}
		hasDNSKEY, hasRRSIG := false, false
		for _, rr := range resp.Answer {
			if rr.Header().Rrtype == dns.TypeDNSKEY {
				hasDNSKEY = true
			} else if rr.Header().Rrtype == dns.TypeRRSIG {
				hasRRSIG = true
			}
		}
		if !hasDNSKEY || !hasRRSIG {
			return false, fmt.Errorf("DNSKEY sin RRset o RRSIG")
		}
		if len(resp.Ns) != 0 || len(resp.Extra) != 0 {
			return false, fmt.Errorf("DNSKEY con Authority/Additional inesperados")
		}

	default:
		return false, fmt.Errorf("tipo de query no manejado: %d", qtype)
	}

	return true, nil
}

func resolveTLDParent(tld string) string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(tld), dns.TypeNS)

	client := new(dns.Client)
	resp, _, err := client.Exchange(m, net.JoinHostPort(rootServers[0], "53"))
	if err != nil || resp == nil || len(resp.Answer) == 0 {
		fmt.Printf("No se pudo resolver parent NS para %s\n", tld)
		return rootServers[0]
	}

	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			// Obtiene la IP del NS
			ips, _ := net.LookupIP(ns.Ns)
			for _, ip := range ips {
				if ip.To4() != nil {
					return ip.String()
				}
			}
		}
	}
	return rootServers[0]
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

		fmt.Fprintf(outFile, "%s\n", domain)

		if len(ipv4) > 0 {
			fmt.Fprintf(outFile, "  IPv4: %s\n", strings.Join(ipv4, ", "))
			for _, ip := range ipv4 {
				okUDP, latencyUDP := testTransport(ip, false)
				okTCP, latencyTCP := testTransport(ip, true)

				ipv4Set[ip] = true
				ipv4TotalCount++

				udpStr := "no"
				tcpStr := "no"
				if okUDP {
					udpStr = "sí"
					udpSupport[ip] = true
					ipv4UDPCount++
					latenciasUDP = append(latenciasUDP, latencyUDP)
				}
				if okTCP {
					tcpStr = "sí"
					tcpSupport[ip] = true
					ipv4TCPCount++
					latenciasTCP = append(latenciasTCP, latencyTCP)
				}
				fmt.Fprintf(outFile, "    IP: %s | UDP: %s | TCP: %s\n", ip, udpStr, tcpStr)
			}
		} else {
			fmt.Fprintf(outFile, "  IPv4: No disponible\n")
		}

		if len(ipv6) > 0 {
			fmt.Fprintf(outFile, "  IPv6: %s\n", strings.Join(ipv6, ", "))
			for _, ip := range ipv6 {
				okUDP, latencyUDP := testTransport(ip, false)
				okTCP, latencyTCP := testTransport(ip, true)

				ipv6Set[ip] = true
				ipv6TotalCount++

				udpStr := "no"
				tcpStr := "no"
				if okUDP {
					udpStr = "sí"
					udpSupport[ip] = true
					ipv6UDPCount++
					latenciasUDP = append(latenciasUDP, latencyUDP)
				}
				if okTCP {
					tcpStr = "sí"
					tcpSupport[ip] = true
					ipv6TCPCount++
					latenciasTCP = append(latenciasTCP, latencyTCP)
				}
				fmt.Fprintf(outFile, "    IP: %s | UDP: %s | TCP: %s\n", ip, udpStr, tcpStr)
			}
		} else {
			fmt.Fprintf(outFile, "  IPv6: No disponible\n")
		}
	}

	// RESULTADOS RESUMIDOS
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

	// PUNTO 4 - RSI Correctness
	fmt.Fprintln(outFile, "\n--- Punto 4: RSI Correctness (5.3 RSSAC047) ---")

	ipv4List, ipv6List := getRootServerIPs()
	type correctnessResult struct {
		Total   int
		Success int
		Fail    int
	}

	rsiCorrectnessStats := make(map[string]correctnessResult)

	queries := []struct {
		qname string
		qtype uint16
	}{
		{".", dns.TypeSOA},
		{".", dns.TypeNS},
		{".", dns.TypeDNSKEY},
		{"com.", dns.TypeNS},
		{"nonexistent.rssac047-test.", dns.TypeA},
	}

	for _, ip := range ipv4List {
		key := fmt.Sprintf("IPv4 %s", ip)
		var res correctnessResult
		for _, q := range queries {
			ok, err := validateCorrectness(ip, q.qname, q.qtype, false)
			fmt.Printf("[DEBUG] Server=%s Query=%s Type=%d ok=%v err=%v\n", ip, q.qname, q.qtype, ok, err)
			res.Total++
			if err == nil && ok {
				res.Success++
			} else {
				res.Fail++
			}
		}
		rsiCorrectnessStats[key] = res
	}

	for _, ip := range ipv6List {
		key := fmt.Sprintf("IPv6 %s", ip)
		var res correctnessResult
		for _, q := range queries {
			ok, err := validateCorrectness(ip, q.qname, q.qtype, false)
			fmt.Printf("[DEBUG] Server=%s Query=%s Type=%d ok=%v err=%v\n", ip, q.qname, q.qtype, ok, err)
			res.Total++
			if err == nil && ok {
				res.Success++
			} else {
				res.Fail++
			}
		}
		rsiCorrectnessStats[key] = res

	}

	// Reporte Punto 4
	for k, v := range rsiCorrectnessStats {
		porcentaje := 0.0
		if v.Total > 0 {
			porcentaje = float64(v.Success) / float64(v.Total) * 100
		}
		estado := "PASS"
		if porcentaje < 100.0 {
			estado = "FAIL"
		}
		fmt.Fprintf(outFile, "%s - Correct: %d | Total: %d | %% Correct: %.2f%% [%s]\n",
			k, v.Success, v.Total, porcentaje, estado)
	}

	// ----------------------------------------------
	// PUNTO 5 - Tasa de éxito/fallo DNSSEC (Reaprovecha los datos)
	fmt.Fprintln(outFile, "\n--- Punto 5: Tasa de éxito/fallo DNSSEC (5.3 RSSAC047) ---")

	for k, v := range rsiCorrectnessStats {
		porcentaje := 0.0
		if v.Total > 0 {
			porcentaje = float64(v.Success) / float64(v.Total) * 100
		}
		fmt.Fprintf(outFile, "%s - Total: %d | Éxito: %d | Fallo: %d | %% Éxito: %.2f%%\n",
			k, v.Total, v.Success, v.Fail, porcentaje)
	}

	// ----------------------------------------------
	// PUNTO 6 - Validación DS-DNSKEY (igual que antes)
	fmt.Fprintln(outFile, "\n--- Punto 6: Validación DS-DNSKEY (5.3 RSSAC047) ---")
	file.Seek(0, 0)
	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}
		ok, err := validateDS(domain)
		if ok {
			fmt.Fprintf(outFile, "%s: VALIDACIÓN EXITOSA\n", domain)
		} else {
			fmt.Fprintf(outFile, "%s: FALLÓ validación -> %v\n", domain, err)
		}
	}

	fmt.Println("Proceso finalizado. Resultados escritos en OUT.txt")
}
