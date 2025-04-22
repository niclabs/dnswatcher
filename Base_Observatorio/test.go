package main

import (
	"bufio"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"strings"
)

func resolveDNS(domain string, qtype uint16) []string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	c := new(dns.Client)

	r, _, err := c.Exchange(m, "8.8.8.8:53") // usa Google DNS
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

func main() {
	file, err := os.Open("input-example.txt")
	if err != nil {
		fmt.Println("Error leyendo archivo:", err)
		return
	}
	defer file.Close()

	ipv4Set := map[string]bool{}
	ipv6Set := map[string]bool{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" {
			continue
		}

		ipv4 := resolveDNS(domain, dns.TypeA)
		ipv6 := resolveDNS(domain, dns.TypeAAAA)

		if len(ipv4) == 0 && len(ipv6) == 0 {
			fmt.Printf("No se pudo resolver o interpretar '%s'\n", domain)
			continue
		}

		for _, ip := range ipv4 {
			ipv4Set[ip] = true
		}
		for _, ip := range ipv6 {
			ipv6Set[ip] = true
		}
	}

	fmt.Println("==== Direcciones IPv4 ====")
	for ip := range ipv4Set {
		fmt.Println(ip)
	}

	fmt.Println("==== Direcciones IPv6 ====")
	for ip := range ipv6Set {
		fmt.Println(ip)
	}
}


