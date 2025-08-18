package LISTADO

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

type AdversoResult struct {
	IP           string
	Success      bool
	ResponseTime time.Duration
	Error        string
}

type AdversoLoadResult struct {
	IP         string
	Successes  int
	Failures   int
	AvgLatency time.Duration
}

func RunAdverso(domains []string) map[string][]AdversoResult {
	fmt.Println("\n=== Punto 10 - Pruebas bajo condiciones adversas ===")
	results := make(map[string][]AdversoResult)

	for _, domain := range domains {
		fmt.Printf("\nDominio: %s\n", domain)
		ips := resolveDomainNSIPs(domain)

		//for _, ip := range ips {
		//	res := simulateLatencyQuery(ip)
		//	results[domain] = append(results[domain], res)
		//	fmt.Printf("  IP %s -> Success: %v | Tiempo: %.2fms | Error: %s\n",
		//		res.IP, res.Success, res.ResponseTime.Seconds()*1000, res.Error)
		//}
		for _, ip := range ips {
			if ip.To4() == nil {
				continue // Ignorar IPv6
			}
			res := simulateLatencyQuery(ip)
			results[domain] = append(results[domain], res)
			fmt.Printf("  IP %s -> Success: %v | Tiempo: %.2fms | Error: %s\n",
				res.IP, res.Success, res.ResponseTime.Seconds()*1000, res.Error)
		}

	}

	return results
}

func simulateLatencyQuery(ip net.IP) AdversoResult {
	time.Sleep(200 * time.Millisecond) // Simulación de alta latencia de red

	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeSOA)
	m.SetEdns0(1220, true)

	client := &dns.Client{
		Timeout: 5 * time.Second,
	}

	start := time.Now()
	resp, _, err := client.Exchange(m, net.JoinHostPort(ip.String(), "53"))
	elapsed := time.Since(start)

	result := AdversoResult{
		IP:           ip.String(),
		ResponseTime: elapsed,
	}

	if err != nil || resp == nil {
		result.Success = false
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Error = "respuesta nula"
		}
	} else if resp.Rcode == dns.RcodeRefused {
		result.Success = false
		result.Error = "respuesta REFUSED: no autoritativo o política"
	} else if resp.Rcode != dns.RcodeSuccess {
		result.Success = false
		result.Error = fmt.Sprintf("respuesta inesperada (rcode=%s)", dns.RcodeToString[resp.Rcode])
	} else {
		result.Success = true
	}

	return result
}

// Punto 10 extendido: carga real con QPS y duración
func RunAdversoConCarga(domains []string, qps int, dur time.Duration) map[string][]AdversoLoadResult {
	fmt.Println("\n=== Punto 10 (Extendido) - Simulación de carga DNS ===")
	results := make(map[string][]AdversoLoadResult)

	for _, domain := range domains {
		fmt.Printf("\nDominio: %s (QPS=%d | Duración=%s)\n", domain, qps, dur)
		ips := resolveDomainNSIPs(domain)

		for _, ip := range ips {
			if ip.To4() == nil {
				continue
			}
			loadResult := simulateLoadQuery(ip, qps, dur)
			results[domain] = append(results[domain], loadResult)
			fmt.Printf("  IP: %s | OK: %d | Fails: %d | Promedio: %.2fms\n",
				loadResult.IP, loadResult.Successes, loadResult.Failures, loadResult.AvgLatency.Seconds()*1000)
		}
	}

	return results
}

func simulateLoadQuery(ip net.IP, qps int, duration time.Duration) AdversoLoadResult {
	var (
		successes int
		failures  int
		latencies []time.Duration
		done      = time.After(duration)
		ticker    = time.NewTicker(time.Second / time.Duration(qps))
		resChan   = make(chan time.Duration, 1000)
		errorChan = make(chan error, 1000)
	)

	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeSOA)
	m.SetEdns0(1220, true)

	client := &dns.Client{Timeout: 2 * time.Second}
	addr := net.JoinHostPort(ip.String(), "53")

	go func() {
		for {
			select {
			case <-done:
				ticker.Stop()
				return
			case <-ticker.C:
				go func() {
					start := time.Now()
					resp, _, err := client.Exchange(m.Copy(), addr)
					elapsed := time.Since(start)

					if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
						errorChan <- fmt.Errorf("fallo o RCODE: %v", err)
					} else {
						resChan <- elapsed
					}
				}()
			}
		}
	}()

	// Espera el tiempo total
	time.Sleep(duration + 1*time.Second)

	// Procesar resultados
	for {
		select {
		case lat := <-resChan:
			successes++
			latencies = append(latencies, lat)
		case <-errorChan:
			failures++
		default:
			goto OUT
		}
	}
OUT:

	var avg time.Duration
	if len(latencies) > 0 {
		var total time.Duration
		for _, l := range latencies {
			total += l
		}
		avg = total / time.Duration(len(latencies))
	}

	return AdversoLoadResult{
		IP:         ip.String(),
		Successes:  successes,
		Failures:   failures,
		AvgLatency: avg,
	}
}
