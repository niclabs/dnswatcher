package LISTADO

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

type NSIDResult struct {
	Server  string
	NSID    string
	Error   string
	Latency time.Duration
}

func RunNSIDCheck(domains []string) map[string][]NSIDResult {
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
			fmt.Printf("  %s -> NSID: %s | Latencia: %.2fms | Error: %s\n", res.Server, res.NSID, latency.Seconds()*1000, res.Error)
		}
		results[domain] = domainResults
	}

	return results
}
