package LISTADO

import (
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/niclabs/Observatorio/dbController"
)

type hostProbe struct {
	Tried     bool
	Reachable bool
	Scheme    string
	URL       string // URL inicial probada
	FinalURL  string // URL final tras redirecciones
	Status    int    // código HTTP
	Latency   time.Duration
	TLSCN     string // Common Name del cert (si HTTPS)
	Err       string
	BodyHash  string // hash SHA256 del cuerpo de respuesta
}

type WebPresenceResult struct {
	Domain       string
	Apex         hostProbe // dominio.cl
	WWW          hostProbe // www.dominio.cl
	AnyReachable bool
}

// RunWebPresence realiza HEAD (con fallback a GET mínimo) sobre https://{host} y http://{host}
func RunWebPresence(domains []string, runID int, domainIDs map[string]int, db *sql.DB) map[string]WebPresenceResult {
	fmt.Println("=== Punto 15 - Web presence associated with domains ===")
	results := make(map[string]WebPresenceResult)
	for _, d := range domains {
		apex := probeHost(d)
		www := probeHost("www." + d)
		results[d] = WebPresenceResult{
			Domain:       d,
			Apex:         apex,
			WWW:          www,
			AnyReachable: (apex.Reachable || www.Reachable),
		}

		domainId := lookupDomainID(d, domainIDs)
		// Persistir en BD si se entregó conexión
		if db != nil {
			if err := dbController.SaveWebPresence(domainId, runID, "APX", apex.Scheme, apex.URL, apex.FinalURL, apex.Status, apex.Reachable, apex.TLSCN, apex.BodyHash, apex.Err, apex.Latency, db); err != nil {
				fmt.Println("SaveWebPresence APX error:", err)
			}
			if err := dbController.SaveWebPresence(domainId, runID, "WWW", www.Scheme, www.URL, www.FinalURL, www.Status, www.Reachable, www.TLSCN, www.BodyHash, www.Err, www.Latency, db); err != nil {
				fmt.Println("SaveWebPresence WWW error:", err)
			}
			if domainId != 0 {
				fmt.Printf("Successful: SI se encontró domain_id para %s, guardado\n", d)
			} else {
				fmt.Printf("Failed: NO se encontró domain_id para %s, guardado con domain_id=0\n", d)
			}
		}
	}
	fmt.Println("=== Métrica 15 recolectada correctamente ===")
	return results
}

func probeHost(host string) hostProbe {
	// 1) intenta HTTPS, luego HTTP
	if r := tryOne(host, "https"); r.Tried && (r.Reachable || r.Err != "") {
		return r
	}
	return tryOne(host, "http")
}

func tryOne(host, scheme string) hostProbe {
	h := hostProbe{Tried: true, Scheme: scheme}
	h.URL = fmt.Sprintf("%s://%s", scheme, host)

	// Redirection tracker
	var finalURL string
	client := &http.Client{
		Timeout: 4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			finalURL = req.URL.String()
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: false},
			DisableKeepAlives: true,
		},
	}

	// Primero HEAD
	methodUsed := "HEAD"
	req, _ := http.NewRequest("HEAD", h.URL, nil)
	req.Header.Set("User-Agent", "DNSWatcher-WebPresence/1.0")
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	// Si HEAD no es soportado (405/501), usamos GET mínimo
	if err == nil && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented) {
		_ = resp.Body.Close()
		methodUsed = "GET"
		req2, _ := http.NewRequest("GET", h.URL, nil)
		req2.Header.Set("Range", "bytes=0-0")
		start = time.Now()
		resp, err = client.Do(req2)
		elapsed = time.Since(start)
	}

	if err != nil {
		h.Err = err.Error()
		h.Latency = elapsed
		h.FinalURL = h.URL
		return h
	}
	defer resp.Body.Close()

	h.Status = resp.StatusCode
	h.Latency = elapsed
	h.FinalURL = h.URL
	if finalURL != "" {
		h.FinalURL = finalURL
	}

	// Considera “Reachable” si 2xx o 3xx
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		h.Reachable = true
	}

	// Si HTTPS, anota CN del certificado
	if scheme == "https" && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		h.TLSCN = resp.TLS.PeerCertificates[0].Subject.CommonName
	}

	// Hash
	if methodUsed == "HEAD" {
		reqHash, _ := http.NewRequest("GET", h.URL, nil)
		reqHash.Header.Set("User-Agent", "DNSWatcher-WebPresence/1.0")
		reqHash.Header.Set("Range", "bytes=0-16383") // 16 KiB
		respHash, err2 := client.Do(reqHash)
		if err2 == nil {
			defer respHash.Body.Close()
			if bh, _ := io.ReadAll(io.LimitReader(respHash.Body, 1<<20)); len(bh) > 0 {
				sum := sha256.Sum256(bh)
				h.BodyHash = hex.EncodeToString(sum[:])
			}
			if respHash.Request != nil && respHash.Request.URL != nil {
				h.FinalURL = respHash.Request.URL.String()
			}
		} else {
		}
	} else {
		if bh, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)); len(bh) > 0 {
			sum := sha256.Sum256(bh)
			h.BodyHash = hex.EncodeToString(sum[:])
		}
	}

	return h
}
