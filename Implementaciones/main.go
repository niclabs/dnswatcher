package main

import (
	"MAIN/LISTADO"
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

func calculateMedian(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values[len(values)/2]
}

func checkLatencyStatus(lat time.Duration, isTCP bool) string {
	if isTCP {
		if lat <= 500*time.Millisecond {
			return "OK (<=500ms)"
		}
		return "ALTO (>500ms)"
	} else {
		if lat <= 250*time.Millisecond {
			return "OK (<=250ms)"
		}
		return "ALTO (>250ms)"
	}
}

func main() {
	// Leer dominios desde input-example.txt
	file, err := os.Open("input-example.txt")
	if err != nil {
		fmt.Println("Error leyendo archivo:", err)
		return
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := scanner.Text()
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	// Ejecuta RSI Availability
	stats := LISTADO.RunDisponibilidad(domains)

	// Escribir archivo de salida alineado
	outFile, _ := os.Create("main_result.txt")
	defer outFile.Close()

	fmt.Fprintln(outFile, "=== Punto 1 & 2 - RSI Availability ===")
	fmt.Fprintf(outFile, "IPv4 UDP: %d\n", stats.IPv4UDP)
	fmt.Fprintf(outFile, "IPv4 TCP: %d\n", stats.IPv4TCP)
	fmt.Fprintf(outFile, "IPv6 UDP: %d\n", stats.IPv6UDP)
	fmt.Fprintf(outFile, "IPv6 TCP: %d\n", stats.IPv6TCP)
	fmt.Fprintln(outFile, "\nCantidad total de direcciones (SIN REPETICIONES):")
	fmt.Fprintf(outFile, "IPv4: %d\n", len(stats.IPv4Set))
	fmt.Fprintf(outFile, "IPv6: %d\n", len(stats.IPv6Set))
	fmt.Fprintln(outFile, "\nCantidad total de direcciones (CON REPETICIONES):")
	fmt.Fprintf(outFile, "IPv4: %d\n", stats.IPv4Total)
	fmt.Fprintf(outFile, "IPv6: %d\n", stats.IPv6Total)
	udpMedian := calculateMedian(stats.LatenciasUDP)
	tcpMedian := calculateMedian(stats.LatenciasTCP)

	fmt.Fprintln(outFile, "\nLatencia de respuesta (mediana):")
	fmt.Fprintf(outFile, "UDP: %.2fms [%s]\n", udpMedian.Seconds()*1000, checkLatencyStatus(udpMedian, false))
	fmt.Fprintf(outFile, "TCP: %.2fms [%s]\n", tcpMedian.Seconds()*1000, checkLatencyStatus(tcpMedian, true))

	correctness := LISTADO.RunCorrectness(domains)
	fmt.Fprintln(outFile, "\n=== Punto 4 - RSI Correctness ===")
	for ip, stat := range correctness {
		porcentaje := float64(stat.Success) / float64(stat.Total) * 100
		estado := "PASS"
		if porcentaje < 100.0 {
			estado = "FAIL"
		}
		fmt.Fprintf(outFile, "%s: %d/%d (%.2f%%) [%s]\n",
			ip, stat.Success, stat.Total, porcentaje, estado)
	}

	dnssecStats := LISTADO.RunDNSSECStats(domains)
	fmt.Fprintln(outFile, "\n=== Punto 5 - Tasa de éxito/fallo DNSSEC ===")
	fmt.Fprintln(outFile, "=== Punto 6 - Validación firma y DS ===")
	fmt.Fprintln(outFile, "=== Punto 7 - Detalles de fallos ===")

	for domain, detail := range dnssecStats {
		// Diferencia: sin DS ni DNSKEY no es fallo
		if len(detail.FailedDetails) == 1 && strings.HasPrefix(detail.FailedDetails[0], "No hay DS ni DNSKEY") {
			fmt.Fprintf(outFile, "Dominio: %s\n", domain)
			fmt.Fprintf(outFile, "  Zona sin DNSSEC (NO ERROR)\n")
			continue
		}

		percent := 0.0
		if detail.Total > 0 {
			percent = float64(detail.Success) / float64(detail.Total) * 100
		}

		fmt.Fprintf(outFile, "Dominio: %s\n", domain)
		fmt.Fprintf(outFile, "  Éxito: %d | Fallos: %d | %% Éxito: %.2f%%\n",
			detail.Success, detail.Fail, percent)

		// Punto 7: detalle de fallos reales
		if len(detail.FailedDetails) > 0 {
			fmt.Fprintln(outFile, "  Detalles de fallos:")
			for _, f := range detail.FailedDetails {
				fmt.Fprintf(outFile, "    %s\n", f)
			}
		}

	}

	redMap := LISTADO.CheckRedundancia(domains)
	fmt.Fprintln(outFile, "\n=== Punto 8 - Redundancia y distribución de NS ===")
	for dom, count := range redMap {
		fmt.Fprintf(outFile, "%s: %d subred(es)\n", dom, count)
	}

	fmt.Fprintln(outFile, "\n=== Punto 9 - Clasificación de errores DNSSEC ===")
	typeCount := map[string]int{}
	for _, detail := range dnssecStats {
		for _, d := range detail.FailedDetails {
			if strings.HasPrefix(d, "ERROR[") {
				parts := strings.Split(d, "[")
				if len(parts) > 1 {
					typ := strings.TrimSuffix(parts[1], "]")
					typeCount[typ]++
				}
			}
		}
	}
	for errType, count := range typeCount {
		fmt.Fprintf(outFile, "%s: %d ocurrencia(s)\n", errType, count)
	}

	fmt.Println("Proceso finalizado. Resultados escritos en main_result.txt")
}
