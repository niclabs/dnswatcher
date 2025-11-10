package LISTADO

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/niclabs/Observatorio/dbController"
)

func CheckRedundancia(domains []string, runId int, domainIDs map[string]int, db *sql.DB) map[string]int {
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
				// IPv6 /48 (representación simple por primeros 3 bloques)
				segments := strings.Split(ip.String(), ":")
				if len(segments) >= 3 {
					subnet = fmt.Sprintf("%s:%s:%s::/48", segments[0], segments[1], segments[2])
				}
			}
			if subnet != "" {
				subnetSet[subnet] = true
			}
		}
		subnetCount := len(subnetSet)
		result[domain] = subnetCount

		domainId := lookupDomainID(domain, domainIDs)

		if db != nil {
			dbController.SaveRedundancy(runId, domainId, subnetCount, db)
			if domainId != 0 {
				fmt.Printf("Successful: SI se encontró domain_id para %s, guardado\n", domain)
			} else {
				fmt.Printf("Failed: NO se encontró domain_id para %s, guardado con domain_id=0\n", domain)
			}
		}
	}

	fmt.Println("=== Métrica 8 recolectada correctamente ===")

	return result
}
