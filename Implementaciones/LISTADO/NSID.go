package LISTADO

import (
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/niclabs/Observatorio/dbController"
)

type NSIDResult struct {
	Server  string
	NSID    string
	Error   string
	Latency time.Duration
}

// RunNSIDCheck runs the NSID inclusion checks for the given domains.
// Signature extended to accept runId, domainIDs map and db connection to optionally save results.
func RunNSIDCheck(domains []string, runId int, domainIDs map[string]int, db *sql.DB) map[string][]NSIDResult {
	fmt.Println("\n=== Punto 12 - Inclusión de NSID ===")
	results := make(map[string][]NSIDResult)

	for _, domain := range domains {
		nsIPs := resolveDomainNSIPs(domain)
		var domainResults []NSIDResult

		for _, ip := range nsIPs {
			if ip.To4() == nil {
				continue
			}

			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
			m.SetEdns0(1220, true)
			if opt := m.IsEdns0(); opt != nil {
				opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
			}

			client := &dns.Client{Timeout: 2 * time.Second}

			start := time.Now()
			resp, _, err := client.Exchange(m, net.JoinHostPort(ip.String(), "53"))
			latency := time.Since(start)

			res := NSIDResult{Server: ip.String(), Latency: latency}

			if err != nil {
				res.Error = err.Error()
			} else {
				for _, extra := range resp.Extra {
					if opt, ok := extra.(*dns.OPT); ok {
						for _, o := range opt.Option {
							if nsid, ok := o.(*dns.EDNS0_NSID); ok {
								res.NSID = string(nsid.Nsid)
							}
						}
					}
				}
				if res.NSID == "" {
					res.Error = "No se recibió NSID"
				}
			}

			domainResults = append(domainResults, res)
			//fmt.Printf("  %s -> NSID: %s | Latencia: %.2fms | Error: %s\n", res.Server, res.NSID, latency.Seconds()*1000, res.Error)

			// Persistir en BD si se entregó conexión
			if db != nil {
				domainID := lookupDomainID(domain, domainIDs)
				// lanzar goroutine no bloqueante para insertar y la función manejará NULL si domainId==0
				go func(r NSIDResult, dID int) {
					if err := dbController.SaveNSID(runId, dID, r.Server, r.NSID, r.Error, r.Latency, db); err != nil {
						fmt.Println("SaveNSID error:", err, " domainID:", dID, " server:", r.Server)
					}
				}(res, domainID)
				if domainID != 0 {
					fmt.Printf("Successful: SI se encontró domain_id para %s, guardado\n", domain)
				} else {
					fmt.Printf("Failed: NO se encontró domain_id para %s, guardado con domain_id=0\n", domain)
				}
			}
		}
		results[domain] = domainResults
	}

	return results
}
