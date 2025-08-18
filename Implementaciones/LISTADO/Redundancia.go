package LISTADO

import (
	"fmt"
	"strings"
)

func CheckRedundancia(domains []string) map[string]int {
	fmt.Println("\n=== Punto 8 - Redundancia y distribución de NS ===")
	result := make(map[string]int)

	for _, domain := range domains {
		nsIPs := resolveDomainNSIPs(domain)
		subnetSet := map[string]bool{}

		for _, ip := range nsIPs {
			var subnet string
			if ip.To4() != nil {
				// IPv4 /24
				octets := strings.Split(ip.String(), ".")
				if len(octets) >= 3 {
					subnet = fmt.Sprintf("%s.%s.%s.0/24", octets[0], octets[1], octets[2])
				}
			} else {
				// IPv6 /48
				segments := strings.Split(ip.String(), ":")
				if len(segments) >= 3 {
					subnet = fmt.Sprintf("%s:%s:%s::/48", segments[0], segments[1], segments[2])
				}
			}
			if subnet != "" {
				subnetSet[subnet] = true
			}
		}
		result[domain] = len(subnetSet)
	}
	return result
}
