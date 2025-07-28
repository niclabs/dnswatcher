package dataAnalyzer

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/niclabs/Observatorio/dbController"
)

// mutexTT is a mutex used to synchronize access to the total time variable across goroutines.
var mutexTT *sync.Mutex

// jsonsFolder is the directory where JSON files will be saved.
var jsonsFolder string = "jsons"

// AnalyzeData processes domain data for a given run, performing DNSSEC checks and generating statistics.
//
// It connects to a PostgreSQL database using the provided credentials, retrieves all domains for the specified run,
// and analyzes each domain concurrently. After processing, it generates and saves global statistics in JSON format.
//
// Parameters:
//   - runId: Identifier of the run to analyze.
//   - dbname: Name of the PostgreSQL database.
//   - user: Database user.
//   - password: Database password.
//   - host: Database host address.
//   - port: Database port.
//
// The function prints timing information and database connection stats to standard output.
// Any errors encountered during processing are logged or printed.
func AnalyzeData(runId int, dbname string, user string, password string, host string, port int) {
	mutexTT = &sync.Mutex{}
	t := time.Now()
	c := 30
	url := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=disable",
		user,
		password,
		host,
		port,
		dbname)
	db, err := sql.Open("postgres", url)
	if err != nil {
		fmt.Println(err)
		return
	}
	ts := dbController.GetRunTimestamp(runId, db)
	//TODO fix ts format-> ":" not accepted in windows
	ts = strings.ReplaceAll(ts, ":", "-")
	concurrency := int(c)
	domainIds := make(chan int, concurrency)

	wg := sync.WaitGroup{}
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ { // Start c goroutines
		go func(t int) {
			j := 0
			totalTime := 0
			for domainId := range domainIds {
				t2 := time.Now()
				CheckDomainInfo(domainId, db)
				duration := time.Since(t2)
				mutexTT.Lock()
				totalTime += int(duration)
				mutexTT.Unlock()
				j++
			}
			wg.Done()
		}(i)
	}

	//Now we have to fill the queue with domainIds!
	rows, err := dbController.GetDomains(runId, db)
	defer rows.Close()
	//for each domainId in the run:
	for rows.Next() {
		var domainId int
		if err := rows.Scan(&domainId); err != nil {
			log.Fatal(err)
		}
		domainIds <- domainId
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	close(domainIds) //Close the queue
	wg.Wait()        // waiting for all goroutines to finish
	getGlobalStatistics(runId, ts, db)

	TotalTime := (int)(time.Since(t).Nanoseconds())
	fmt.Println("Total Time (nsec):", TotalTime)
	fmt.Println("Total Time (min:sec):", TotalTime/60000000000, ":", TotalTime%60000000000/1000000000)

	fmt.Println("openconnections", db.Stats())

}

// verifyDNSSEC performs a series of DNSSEC validation checks for the specified domain.
//
// It first checks if a DNSKEY record exists for the given domain ID in the database.
// If no DNSKEY is found, the function returns immediately. Otherwise, it is intended
// to verify the DS record against the DNSKEY SEP, validate ZSK and KSK relationships,
// and check for nonexistence proofs using NSEC or NSEC3 records, including wildcard handling.
//
// Parameters:
//   - domainId: The identifier of the domain to validate.
//   - db: The database connection used to retrieve DNSSEC information.
//
// This function does not return a value; it is designed to be used internally for DNSSEC validation steps.
func verifyDNSSEC(domainId int, db *sql.DB) {
	//check if dnskey is found
	dnskeyFound, _ := dbController.GetDNSKEYInfo(domainId, db)
	if !dnskeyFound {
		return
	}
	//verify DS against dnskey SEP
	//verify DNSKey 256 zsk against 257 ksk
	//verify nonexistence
	//if not wildcard:
	//if nsec
	//check wildcard
	//check cover doman
	//if nsec3
	//check next closer
	//check closest encloser
	//check wildcard
	//if wildcard check rrsig ok
}

// CheckDomainInfo performs DNSSEC validation checks for a given domain and updates its DNSSEC status in the database.
//
// It calls verifyDNSSEC to run a series of DNSSEC checks, then uses CheckDNSSEC to determine the presence and validity
// of DS, DNSKEY, NSEC, and NSEC3 records. If all required DNSSEC conditions are met, it marks the domain as DNSSEC-valid
// in the database.
//
// Parameters:
//   - domainId: The identifier of the domain to check.
//   - db: The database connection used for retrieving and updating DNSSEC information.
//
// This function does not return a value; it updates the DNSSEC status for the domain in the database.
func CheckDomainInfo(domainId int, db *sql.DB) {
	//verify DNSSEC
	verifyDNSSEC(domainId, db)
	//CheckDispersion(domain_id,db)
	dnssecOk := false
	dsFound, dsOk, dnskeyFound, dnskeyOk, nsecFound, nsecOk, nsec3Found, nsec3Ok, _ := CheckDNSSEC(domainId, db)

	if dsFound && dsOk && dnskeyFound && dnskeyOk && ((nsecFound && nsecOk) || (nsec3Found && nsec3Ok)) {
		dnssecOk = true
	}
	dbController.UpdateDomainDNSSEC(domainId, dnssecOk, db)

}

// getGlobalStatistics generates and saves global statistics for a given run.
//
// This function initializes the JSON output directory and sequentially calls helper functions
// to compute and store various statistics, including dispersion, DNSSEC status, nameserver characteristics,
// and recommendations, all in JSON format.
//
// Parameters:
//   - runId: Identifier of the run to analyze.
//   - ts: Timestamp string used for naming output files.
//   - db: Database connection used to retrieve statistical data.
//
// This function does not return a value; it writes results to JSON files.
func getGlobalStatistics(runId int, ts string, db *sql.DB) {
	initjsonFolder()
	saveDispersion(runId, ts, db)
	saveDNSSEC(runId, ts, db)
	saveCountNameserverCharacteristics(runId, ts, db)
	saveJsonRecomendations(runId, ts)
}

// saveJsonRecomendations generates recommendations in JSON format for a given run.
//
// This function constructs file paths for the input and output JSON files based on the run ID and timestamp.
// It then executes an external command to process the input file and generate the recommendations file.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the input file.
//
// This function does not return a value; it logs any errors encountered during command execution.
func saveJsonRecomendations(runId int, ts string) {
	filename := "./json/" + strconv.Itoa(runId) + "CountNSCountryASNPerDomain" + ts + ".json"
	newfilename := "./json/" + strconv.Itoa(runId) + "CountRecomendations.json"

	//generate json data
	command := exec.Command("./json", filename, newfilename)
	err := command.Run()
	if err != nil {
		log.Println(err)
	}
}

// initjsonFolder ensures that the JSON output directory exists.
// If the directory specified by the global variable `jsonsFolder` does not exist,
// this function creates it with the default permissions.
//
// This function is typically called before writing any JSON output files to guarantee
// that the target directory is available.
func initjsonFolder() {
	if _, err := os.Stat(jsonsFolder); os.IsNotExist(err) {
		os.Mkdir(jsonsFolder, os.ModePerm)
	}
}

// saveDispersion generates and saves various dispersion and nameserver characteristics statistics for a given run.
//
// This function sequentially calls helper functions to compute and store statistics such as the number of nameservers,
// ASNs, countries per domain, combined nameserver/country/ASN data, IPv4/IPv6 nameserver counts, domains with specific
// nameserver IP counts, exclusive nameserver IPs, and availability results. All results are saved in JSON format.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming output files.
//   - db: Database connection used to retrieve statistical data.
//
// This function does not return a value; it writes results to JSON files.
func saveDispersion(runId int, ts string, db *sql.DB) {
	saveCountNSPerDomain(runId, ts, db)
	saveCountASNPerDomain(runId, ts, db)
	saveCountCountryPerDomain(runId, ts, db)
	saveCountNSCountryASNPerDomain(runId, ts, db)
	saveCountNSIPv4IPv6(runId, ts, db)
	saveCountDomainsWithCountNSIPs(runId, ts, db)
	saveCountDomainsWithCountNSIPExclusive(runId, ts, db)
	saveAvailabilityResults(runId, ts, db)
	saveAvailabilityAndLatency(runId, ts) // metric 1 and 3
}

// saveAvailabilityResults retrieves availability results from the database and saves them in JSON format.
//
// This function queries the database for availability statistics related to the specified run ID,
// processes the result set, and writes the data to a JSON file named using the run ID and timestamp.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the output file.
//   - db: Database connection used to retrieve availability data.
//
// This function does not return a value; it panics on critical errors and logs scanning issues.
func saveAvailabilityResults(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountAvailabilityResults(runId, db)
	if err != nil {
		panic(err) //error
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_CountAvailabilityResults_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	data := []map[string]interface{}{}
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			log.Fatal(err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}
}

// new funcion!
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

func saveAvailabilityAndLatency(runId int, ts string) {
	// open file with domains
	file, err := os.Open("input-example.txt")
	if err != nil {
		fmt.Println("Error leyendo archivo:", err)
		return
	}
	defer file.Close()

	ipv4Set := make(map[string]bool)
	ipv6Set := make(map[string]bool)

	tcpSupport := make(map[string]bool)
	udpSupport := make(map[string]bool)

	ipv4TotalCount, ipv6TotalCount := 0, 0
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

		for _, ip := range ipv4 {
			okUDP, latencyUDP := measureLatency(ip, false)
			okTCP, latencyTCP := measureLatency(ip, true)

			ipv4Set[ip] = true
			ipv4TotalCount++
			if okUDP {
				udpSupport[ip] = true
				ipv4UDPCount++
				latenciasUDP = append(latenciasUDP, latencyUDP)
			}
			if okTCP {
				tcpSupport[ip] = true
				ipv4TCPCount++
				latenciasTCP = append(latenciasTCP, latencyTCP)
			}
		}

		for _, ip := range ipv6 {
			okUDP, latencyUDP := measureLatency(ip, false)
			okTCP, latencyTCP := measureLatency(ip, true)

			ipv6Set[ip] = true
			ipv6TotalCount++
			if okUDP {
				udpSupport[ip] = true
				ipv6UDPCount++
				latenciasUDP = append(latenciasUDP, latencyUDP)
			}
			if okTCP {
				tcpSupport[ip] = true
				ipv6TCPCount++
				latenciasTCP = append(latenciasTCP, latencyTCP)
			}
		}
	}

	// save CountAvailabilityIP.json
	filename := fmt.Sprintf("%s/%d_CountAvailabilityIP_%s.json", jsonsFolder, runId, ts)
	file, err = os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	data := []map[string]interface{}{
		{
			"numdomains": domainCount,
			"unique_ipcount": map[string]int{
				"IPv4": len(ipv4Set),
				"IPv6": len(ipv6Set),
			},
			"ipcount": map[string]int{
				"IPv4": ipv4TotalCount,
				"IPv6": ipv6TotalCount,
			},
			"availability_transport": map[string]int{
				"UDP": len(udpSupport),
				"TCP": len(tcpSupport),
			},
			"Summary by type of transport and protocol": map[string]int{
				"IPv4_UDP_available": ipv4UDPCount,
				"IPv4_TCP_available": ipv4TCPCount,
				"IPv6_UDP_available": ipv6UDPCount,
				"IPv6_TCP_available": ipv6TCPCount,
			},
		},
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}

	// Save CountLatency.json
	filename = fmt.Sprintf("%s/%d_CountLatency_%s.json", jsonsFolder, runId, ts)
	file, err = os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	latency := make(map[string]string)

	if len(latenciasUDP) > 0 {
		sort.Slice(latenciasUDP, func(i, j int) bool { return latenciasUDP[i] < latenciasUDP[j] })
		medianaUDP := latenciasUDP[len(latenciasUDP)/2]
		estado := "satisfy (<= 250ms)"
		if medianaUDP > 250*time.Millisecond {
			estado = "exceed (> 250ms)"
		}
		latency["UDP_mediumlatency"] = fmt.Sprintf("%v [%s]", medianaUDP, estado)
	}
	if len(latenciasTCP) > 0 {
		sort.Slice(latenciasTCP, func(i, j int) bool { return latenciasTCP[i] < latenciasTCP[j] })
		medianaTCP := latenciasTCP[len(latenciasTCP)/2]
		estado := "satisfy (<= 500ms)"
		if medianaTCP > 500*time.Millisecond {
			estado = "exceed (> 500ms)"
		}
		latency["TCP_mediumlatency"] = fmt.Sprintf("%v [%s]", medianaTCP, estado)
	}

	encoder = json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(latency); err != nil {
		panic(err)
	}
}

// saveCountDomainsWithCountNSIPExclusive retrieves and saves statistics about domains with exclusive nameserver IPs.
//
// This function queries the database for domains that have exclusive nameserver IP addresses for a given run ID,
// processes the result set, and writes the data to a JSON file named using the run ID and timestamp.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the output file.
//   - db: Database connection used to retrieve statistical data.
//
// This function does not return a value; it panics on critical errors and logs scanning issues.
func saveCountDomainsWithCountNSIPExclusive(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountDomainsWithCountNSIPExclusive(runId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_CountDomainsWithCountNSIPExclusive_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	data := []map[string]interface{}{}
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			log.Fatal(err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}
}

// saveCountCountryPerDomain retrieves and saves statistics about the number of countries per domain.
//
// This function queries the database for country distribution data for each domain in the specified run,
// processes the result set, and writes the data to a JSON file named using the run ID and timestamp.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the output file.
//   - db: Database connection used to retrieve statistical data.
//
// This function does not return a value; it panics on critical errors and logs scanning issues.
func saveCountCountryPerDomain(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountCountryPerDomain(runId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_CountCountryPerDomain_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	data := []map[string]interface{}{}
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			log.Fatal(err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}
}

// saveCountASNPerDomain retrieves and saves statistics about the number of Autonomous System Numbers (ASNs) per domain.
//
// This function queries the database for ASN distribution data for each domain in the specified run,
// processes the result set, and writes the data to a JSON file named using the run ID and timestamp.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the output file.
//   - db: Database connection used to retrieve statistical data.
//
// This function does not return a value; it panics on critical errors and logs scanning issues.
func saveCountASNPerDomain(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountASNPerDomain(runId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_CountASNPerDomain_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	data := []map[string]interface{}{}
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			log.Fatal(err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}
}

// saveCountNSPerDomain retrieves and saves statistics about the number of nameservers per domain.
//
// This function queries the database for the count of nameservers associated with each domain in the specified run,
// processes the result set, and writes the data to a JSON file named using the run ID and timestamp.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the output file.
//   - db: Database connection used to retrieve statistical data.
//
// This function does not return a value; it panics on critical errors.
func saveCountNSPerDomain(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountNSPerDomain(runId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_CountNSPerDomain_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	data := []map[string]interface{}{}
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			panic(err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		panic(err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}
}

// saveCountNSCountryASNPerDomain retrieves and saves statistics about the number of nameservers, countries, and ASNs per domain.
//
// This function queries the database for combined statistics on nameservers, countries, and Autonomous System Numbers (ASNs)
// associated with each domain in the specified run. It processes the result set and writes the data to a JSON file named
// using the run ID and timestamp.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the output file.
//   - db: Database connection used to retrieve statistical data.
//
// This function does not return a value; it panics on critical errors and logs scanning issues.
func saveCountNSCountryASNPerDomain(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountNSCountryASNPerDomain(runId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_CountNSCountryASNPerDomain_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	data := []map[string]interface{}{}
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			log.Fatal(err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}
}

// saveCountNSIPv4IPv6 retrieves and saves statistics about the number of distinct nameservers with IPv4 and IPv6 addresses.
//
// This function queries the database for the count of unique nameservers using IPv4 and IPv6 for the specified run ID,
// processes the results, and writes the data to a JSON file named using the run ID and timestamp.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the output file.
//   - db: Database connection used to retrieve statistical data.
//
// This function does not return a value; it panics on critical errors and logs scanning issues.
func saveCountNSIPv4IPv6(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountDistinctNSWithIPv4(runId, db)
	if err != nil {
		panic(err)
	}
	var countIPv4 int
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&countIPv4); err != nil {
			log.Fatal(err)
		}
	}

	rows, err = dbController.CountDistinctNSWithIPv6(runId, db)
	if err != nil {
		panic(err)
	}
	var countIPv6 int
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&countIPv6); err != nil {
			log.Fatal(err)
		}
	}

	filename := fmt.Sprintf("%s/%d_CountNSIPv4IPv6_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	data := map[string]int{
		"countIPv4": countIPv4,
		"countIPv6": countIPv6,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}
}

// saveCountDomainsWithCountNSIPs retrieves and saves statistics about the number of domains
// with a specific count of nameserver IPs for a given run.
//
// This function queries the database for domains and their associated nameserver IP counts,
// processes the result set, and writes the data to a JSON file named using the run ID and timestamp.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the output file.
//   - db: Database connection used to retrieve statistical data.
//
// This function does not return a value; it panics on critical errors and logs scanning issues.
func saveCountDomainsWithCountNSIPs(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountDomainsWithCountNSIp(runId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_CountDomainsWithCountNSIPs_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	data := []map[string]interface{}{}
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			log.Fatal(err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}
}

// saveCountDNSSEC generates and saves a summary of DNSSEC validation results for a given run.
//
// This function retrieves the number of domains without DNSSEC, with failed DNSSEC validation,
// and with successful DNSSEC validation from the database. It then writes these statistics to a
// JSON file named using the run ID and timestamp.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the output file.
//   - db: Database connection used to retrieve DNSSEC statistics.
//
// The function panics on critical errors related to file creation or JSON encoding.
func saveCountDNSSEC(runId int, ts string, db *sql.DB) {
	dnssecFail, dnssecOk, noDnssec := dbController.CountDomainsWithDNSSEC(runId, db)
	filename := fmt.Sprintf("%s/%d_CountDomainsWithDNSSEC_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	data := []map[string]interface{}{
		{"category": "no_dnssec", "domains": noDnssec},
		{"category": "dnssec_fail", "domains": dnssecFail},
		{"category": "dnssec_ok", "domains": dnssecOk},
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}
}

// saveCountDNSSECerrors generates and saves a summary of DNSSEC validation error types for a given run.
//
// This function retrieves the number of domains with each type of DNSSEC validation failure
// (denial of existence, DNSKEY validation, and DS validation) from the database. It then writes
// these statistics to a JSON file named using the run ID and timestamp.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the output file.
//   - db: Database connection used to retrieve DNSSEC error statistics.
//
// The function panics on critical errors related to file creation or JSON encoding.
func saveCountDNSSECerrors(runId int, ts string, db *sql.DB) {
	denialProof, dnskeyValidation, dsValidation := dbController.CountDomainsWithDNSSECErrors(runId, db)
	filename := fmt.Sprintf("%s/%d_CountDomainsWithDNSSECerrors_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	data := []map[string]interface{}{
		{"failure": "Negación de Existencia", "domains": denialProof},
		{"failure": "Validación de llaves", "domains": dnskeyValidation},
		{"failure": "Validación de DS", "domains": dsValidation},
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}
}

// saveCountNameserverCharacteristics generates and saves statistics about nameserver characteristics for a given run.
//
// This function retrieves counts of nameservers with and without specific characteristics (recursivity, EDNS, TCP support,
// zone transfer, and LOC query response) from the database for the specified run ID. It then writes these statistics
// to a JSON file named using the run ID and timestamp.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the output file.
//   - db: Database connection used to retrieve nameserver characteristic data.
//
// The function panics on critical errors related to file creation or JSON encoding.
func saveCountNameserverCharacteristics(runId int, ts string, db *sql.DB) {
	recursivity, noRecursivity, edns, noEdns, tcp, noTcp, zoneTransfer, noZoneTransfer, locQuery, noLocQuery := dbController.CountNameserverCharacteristics(runId, db)
	filename := fmt.Sprintf("%s/%d_CountNameserverCharacteristics_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	data := []map[string]interface{}{
		{"category": "Permite Recursividad", "fail": noRecursivity, "fulfill": recursivity},
		{"category": "EDNS activado", "fail": noEdns, "fulfill": edns},
		{"category": "comunicacion TCP", "fail": noTcp, "fulfill": tcp},
		{"category": "Transferencia de zona TCP", "fail": noZoneTransfer, "fulfill": zoneTransfer},
		{"category": "Respuesta a consultas LOC", "fail": noLocQuery, "fulfill": locQuery},
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		panic(err)
	}
}

// saveDNSSEC generates and saves DNSSEC validation statistics and error summaries for a given run.
//
// This function sequentially calls helper functions to compute and store the overall DNSSEC validation
// results and the breakdown of DNSSEC error types. The results are written to JSON files named using
// the run ID and timestamp.
//
// Parameters:
//   - runId: Identifier of the run to process.
//   - ts: Timestamp string used for naming the output files.
//   - db: Database connection used to retrieve DNSSEC statistics.
//
// This function does not return a value; it panics on critical errors related to file creation or JSON encoding.
func saveDNSSEC(runId int, ts string, db *sql.DB) {
	saveCountDNSSEC(runId, ts, db)
	saveCountDNSSECerrors(runId, ts, db)
}

// CheckDNSSEC performs a comprehensive DNSSEC validation for a given domain.
//
// This function checks for the presence and validity of DS, DNSKEY, NSEC, and NSEC3 records
// associated with the specified domain ID in the database. It updates the domain's NSEC and NSEC3
// information in the database as part of the process. The function returns a set of boolean values
// indicating the presence and validity of each DNSSEC component, as well as whether a wildcard was detected.
//
// Parameters:
//   - domainId: The identifier of the domain to validate.
//   - db: The database connection used to retrieve and update DNSSEC information.
//
// Returns:
//   - dsFound:      true if a DS record was found.
//   - dsOk:         true if the DS record is valid.
//   - dnskeyFound:  true if a DNSKEY record was found.
//   - dnskeyOk:     true if the DNSKEY record is valid.
//   - nsecFound:    true if an NSEC record was found.
//   - nsecOk:       true if the NSEC record is valid.
//   - nsec3Found:   true if an NSEC3 record was found.
//   - nsec3Ok:      true if the NSEC3 record is valid.
//   - wildcard:     true if a wildcard was detected in NSEC or NSEC3 records.
func CheckDNSSEC(domainId int, db *sql.DB) (bool, bool, bool, bool, bool, bool, bool, bool, bool) {

	nsecFound, nsecOk, wildcard1 := CheckNSECs(domainId, db)
	if nsecFound {
		dbController.UpdateDomainNSECInfo(domainId, nsecOk, nsecFound, wildcard1, db)
	}
	nsec3Found, nsec3Ok, wildcard2 := CheckNSEC3s(domainId, db)

	if nsec3Found {
		dbController.UpdateDomainNSEC3Info(domainId, nsec3Ok, nsec3Found, wildcard2, db)
	}
	dsFound, dsOk := CheckDS(domainId, db)
	dnskeyFound, dnskeyOk := CheckDNSKEY(domainId, db)
	return dsFound, dsOk, dnskeyFound, dnskeyOk, nsecFound, nsecOk, nsec3Found, nsec3Ok, wildcard1 || wildcard2
}

// CheckDNSKEY retrieves and validates the DNSKEY record for a given domain.
//
// This function queries the database for the DNSKEY record associated with the specified domain ID.
// It returns two boolean values:
//   - dnskeyFound: true if a DNSKEY record was found for the domain.
//   - dnskeyOk:    true if the DNSKEY record is considered valid.
//
// Parameters:
//   - domainId: The identifier of the domain to check.
//   - db:       The database connection used to retrieve DNSKEY information.
//
// Returns:
//   - dnskeyFound: Indicates if a DNSKEY record was found.
//   - dnskeyOk:    Indicates if the DNSKEY record is valid.
func CheckDNSKEY(domainId int, db *sql.DB) (dnskeyFound bool, dnskeyOk bool) {
	dnskeyFound, dnskeyOk = dbController.GetDNSKEYInfo(domainId, db)
	return
}

// CheckDS retrieves and validates the DS (Delegation Signer) record for a given domain.
//
// This function queries the database for the DS record associated with the specified domain ID.
// It returns two boolean values:
//   - dsFound: true if a DS record was found for the domain.
//   - dsOk:    true if the DS record is considered valid.
//
// Parameters:
//   - domainId: The identifier of the domain to check.
//   - db:       The database connection used to retrieve DS information.
//
// Returns:
//   - dsFound: Indicates if a DS record was found.
//   - dsOk:    Indicates if the DS record is valid.
func CheckDS(domainId int, db *sql.DB) (dsFound bool, dsOk bool) {
	dsFound, dsOk = dbController.GetDSInfo(domainId, db)
	return
}

// CheckNSECs retrieves and validates NSEC records for a given domain.
//
// This function checks the NSEC records associated with the specified domain ID in the database.
// It determines if NSEC records are present, if they are valid according to DNSSEC non-existence
// proof logic, and whether a wildcard is detected. The function processes all NSEC records for
// the domain, evaluating RRSIG validity, coverage, and wildcard status. It also considers the
// non-existence status from the database to decide if the NSEC proof is valid.
//
// Parameters:
//   - domainId: The identifier of the domain to check.
//   - db: The database connection used to retrieve NSEC information.
//
// Returns:
//   - nsecFound:  true if at least one NSEC record was found.
//   - nsecOk:     true if the NSEC records provide a valid non-existence proof.
//   - wildcard:   true if a wildcard was detected in the NSEC records.
func CheckNSECs(domainId int, db *sql.DB) (nsecFound bool, nsecOk bool, wildcard bool) {
	_, nonExistenceStatus, err := dbController.GetNonExistenceStatus(domainId, db)
	if err != nil {
		return false, false, false
	}
	rows, err := dbController.GetNSECsInfo(domainId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	nsecFound = false
	nsecOk = false
	wildcard = false
	nnsec := 0
	var nrrsigOk, ncover, ncoverwc, niswc bool
	nrrsigOk = true
	ncover = false
	ncoverwc = false
	niswc = false
	for rows.Next() {
		nnsec++
		nsecFound = true
		var rrsigOk, cover, coverwc, iswc bool
		if err := rows.Scan(&rrsigOk, &cover, &coverwc, &iswc); err != nil {
			log.Fatal(err)
		}
		nrrsigOk = nrrsigOk && rrsigOk
		ncover = ncover || cover
		ncoverwc = ncoverwc || coverwc
		niswc = niswc || iswc
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	if nnsec == 0 {
		return
	}
	nsecFound = true
	wildcard = niswc
	if !nrrsigOk {
		return
	}
	if niswc && nnsec == 1 && nonExistenceStatus == 0 {
		nsecOk = true
		return
	}
	if ncover && ncoverwc && !niswc && nnsec == 2 && nonExistenceStatus == 3 {
		nsecOk = true
		return
	}
	return
}

// CheckNSEC3s retrieves and validates NSEC3 records for a given domain.
//
// This function checks the NSEC3 records associated with the specified domain ID in the database.
// It determines if NSEC3 records are present, if they provide a valid non-existence proof according
// to DNSSEC logic, and whether a wildcard is detected. The function processes all NSEC3 records for
// the domain, evaluating RRSIG validity, match, coverage, and wildcard status. It also considers the
// non-existence status from the database to decide if the NSEC3 proof is valid.
//
// Parameters:
//   - domainId: The identifier of the domain to check.
//   - db: The database connection used to retrieve NSEC3 information.
//
// Returns:
//   - nsec3Found:  true if at least one NSEC3 record was found.
//   - nsec3Ok:     true if the NSEC3 records provide a valid non-existence proof.
//   - wildcard:    true if a wildcard was detected in the NSEC3 records.
func CheckNSEC3s(domainId int, db *sql.DB) (nsec3Found bool, nsec3Ok bool, wildcard bool) {
	_, nonExistenceStatus, err := dbController.GetNonExistenceStatus(domainId, db)
	if err != nil {
		return false, false, false
	}
	rows, err := dbController.GetNSEC3s(domainId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	nnsec := 0

	nrrsigok := true
	nmatch := false
	ncover := false
	ncoverwc := false
	nwc := false
	for rows.Next() {
		nsec3Found = true
		nnsec++
		var rrsigOk bool
		var match bool
		var cover bool
		var coverwc bool
		var wc bool

		if err := rows.Scan(&rrsigOk, &match, &cover, &coverwc, &wc); err != nil {
			log.Fatal(err)
		}

		nrrsigok = nrrsigok && rrsigOk
		nmatch = nmatch || match
		ncover = ncover || cover
		ncoverwc = ncoverwc || coverwc
		nwc = nwc || wc
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	nsec3Ok = false
	wildcard = nwc
	if nnsec == 0 {
		nsec3Found = false
		return
	}
	if nnsec == 1 && nwc && nrrsigok && nonExistenceStatus == 0 {
		nsec3Ok = true
		return
	}
	if nmatch && ncover && ncoverwc && !nwc && nrrsigok && nonExistenceStatus == 3 {
		nsec3Ok = true
		return
	}
	return
}
