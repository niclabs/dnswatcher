package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/howeyc/gopass"
	"github.com/niclabs/Observatorio/dbController"
)

var mutexTT *sync.Mutex   // Used for synchronization if needed.
var jsonsFolder = "jsons" // Folder containing JSON input files.

// main parses command-line arguments to obtain database credentials and a run ID,
// and then calls GetNSs to process domain information and extract NS data.
//
// Supported flags:
//
//   - p: Prompt for password securely via terminal input.
//   - u: Database username.
//   - pw: Database password (if -p is not used).
//   - db: Name of the PostgreSQL database.
//   - runid: Run ID to associate with the processed data.
//
// If -p is set, the user is prompted for the password securely using gopass.
// Otherwise, the password is read from the -pw flag.
//
// Once all flags are parsed and credentials collected, the function invokes GetNSs
// to start the name server extraction process for the specified run ID.
func main() {
	p := flag.Bool("p", false, "Prompt for password?")
	u := flag.String("u", "", "Database User")
	db := flag.String("db", "", "Database Name")
	pw := flag.String("pw", "", "Database Password")
	runid := flag.Int("runid", 1, "Database run id")
	flag.Parse()

	pass := ""

	if *p {
		fmt.Printf("Password: ")
		// Silent. For printing *'s use gopass.GetPasswdMasked()
		pwd, err := gopass.GetPasswdMasked()
		if err != nil {
			// Handle gopass.ErrInterrupted or getch() read error
		}
		pass = string(pwd)

	} else {
		pass = *pw
	}

	GetNSs(*runid, *db, *u, pass)
}

// GetNSs retrieves and processes NS records for all domains associated with the given run ID.
// It opens a connection to the PostgreSQL database using the provided credentials and sets up
// a pool of concurrent goroutines to process each domain in parallel.
//
// Each worker pulls domain IDs from a channel and invokes CheckDomainInfo to extract and handle
// NS-related data. Execution time per domain is tracked individually and aggregated across workers.
//
// Parameters:
//   - runId: ID of the database run to process.
//   - dbname: Name of the PostgreSQL database.
//   - user: Username for database authentication.
//   - password: Password for database authentication.
func GetNSs(runId int, dbname string, user string, password string) {
	mutexTT = &sync.Mutex{}
	t := time.Now()
	c := 30
	db, err := sql.Open("postgres", "user="+user+" password="+password+" dbname="+dbname+" sslmode=disable")
	if err != nil {
		fmt.Println(err)
		return
	}
	ts := dbController.GetRunTimestamp(runId, db)
	concurrency := c
	domainIds := make(chan int, concurrency)
	wg := sync.WaitGroup{}
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
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
	rows, err := dbController.GetDomains(runId, db)
	defer rows.Close()
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
	close(domainIds)
	wg.Wait()
	getGlobalStatistics(runId, ts, db)
	TotalTime := (int)(time.Since(t).Nanoseconds())
	fmt.Println("Total Time:", TotalTime)
	fmt.Println("openconnections", db.Stats())
}

// CheckDomainInfo validates the DNSSEC status of a domain based on its ID.
//
// It retrieves DNSSEC-related record status (DS, DNSKEY, NSEC, NSEC3) from CheckDNSSEC.
// A domain is considered DNSSEC-valid if:
//   - DS and DNSKEY records are found and valid, and
//   - Either NSEC or NSEC3 records are found and valid.
//
// The result is saved in the database using UpdateDomainDNSSEC.
//
// Parameters:
//   - domainId: The database ID of the domain to evaluate.
//   - db: The PostgreSQL database connection.
func CheckDomainInfo(domainId int, db *sql.DB) {
	//CheckDispersion(domain_id,db)
	dnssecOk := false
	dsFound, dsOk, dnskeyFound, dnskeyOk, nsecFound, nsecOk, nsec3Found, nsec3Ok, _ := CheckDNSSEC(domainId, db)

	if dsFound && dsOk && dnskeyFound && dnskeyOk && ((nsecFound && nsecOk) || (nsec3Found && nsec3Ok)) {
		dnssecOk = true
	}
	dbController.UpdateDomainDNSSEC(domainId, dnssecOk, db)

}

// getGlobalStatistics collects and saves overall DNS-related statistics for a given run.
//
// It initializes the JSON output folder and then saves dispersion metrics,
// DNSSEC validation results, and nameserver characteristic counts.
//
// Parameters:
//   - runId: The identifier of the current run in the database.
//   - ts: The timestamp string associated with the run.
//   - db: The active database connection.
func getGlobalStatistics(runId int, ts string, db *sql.DB) {
	initjsonsFolder()
	saveDispersion(runId, ts, db)
	saveDNSSEC(runId, ts, db)
	saveCountNameserverCharacteristics(runId, ts, db)
}

// initjsonsFolder ensures that the JSON output folder exists.
//
// If the folder defined by the `jsonsFolder` variable does not exist,
// it creates it with default permissions. This folder is typically used
// to store JSON files generated during global statistics collection.
func initjsonsFolder() {
	if _, err := os.Stat(jsonsFolder); os.IsNotExist(err) {
		os.Mkdir(jsonsFolder, os.ModePerm)
	}
}

// saveDispersion generates and stores dispersion-related nameserver statistics.
//
// This function executes a set of operations that analyze how domain nameservers are distributed
// across different dimensions such as ASN, countries, and IP versions. Each helper function
// persists a different aspect of this analysis as a JSON file, using the given run ID and timestamp.
//
// Parameters:
//   - runId: the ID of the current run in the database.
//   - ts: the timestamp string associated with the current run.
//   - db: the active database connection used for retrieving and storing data.
func saveDispersion(runId int, ts string, db *sql.DB) {
	saveCountNSPerDomain(runId, ts, db)
	saveCountASNPerDomain(runId, ts, db)
	saveCountCountryPerDomain(runId, ts, db)
	saveCountNSCountryASNPerDomain(runId, ts, db)
	saveCountNSIPv4IPv6(runId, ts, db)
	saveCountDomainsWithCountNSIPs(runId, ts, db)
	saveCountDomainsWithCountNSIPExclusive(runId, ts, db)
}

// saveCountDomainsWithCountNSIPExclusive exports the count of domains based on exclusive NS IPs to a JSON file.
//
// This function retrieves statistical data from the database about domains that use
// a specific number of exclusive nameserver IPs. It formats the results as a JSON array of objects,
// where each object maps column names to values, and saves it in the 'jsons' folder.
//
// Parameters:
//   - runId: ID of the run associated with the statistics.
//   - ts: timestamp string used to uniquely name the output file.
//   - db: active database connection used to retrieve the data.
func saveCountDomainsWithCountNSIPExclusive(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountDomainsWithCountNSIPExclusive(runId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_CountDomainsWithCountNSIPExclusive_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
	}
	defer file.Close()

	var data []map[string]interface{}
	columns, err := rows.Columns()
	if err != nil {
		log.Fatalf("Error getting columns: %v", err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			log.Fatalf("Error scanning row: %v", err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("Error iterating rows: %v", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatalf("Error encoding JSON: %v", err)
	}
}

// saveCountCountryPerDomain exports the number of countries associated with each domain to a JSON file.
//
// This function queries the database for statistics about how many different countries
// are associated with the nameservers of each domain in the given run. The results are
// encoded in JSON format and saved to a file named using the run ID and timestamp.
//
// Parameters:
// - runId: ID of the run from which to fetch the data.
// - ts: timestamp string used to name the output file.
// - db: database connection to use for querying.
func saveCountCountryPerDomain(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountCountryPerDomain(runId, db)
	if err != nil {
		log.Fatalf("Error counting country per domain: %v", err)
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_CountCountryPerDomain_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
	}
	defer file.Close()

	var data []map[string]interface{}
	columns, err := rows.Columns()
	if err != nil {
		log.Fatalf("Error getting columns: %v", err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			log.Fatalf("Error scanning row: %v", err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("Error iterating rows: %v", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatalf("Error encoding JSON: %v", err)
	}
}

// saveCountNSPerDomain exports the number of nameservers per domain to a JSON file.
//
// This function queries the database to count how many nameservers (NS records) are
// associated with each domain in the specified run. The results are serialized to
// a JSON file, stored under the jsonsFolder directory.
//
// Parameters:
// - runId: ID of the current run for which the statistics are gathered.
// - ts: timestamp string used to generate a unique filename.
// - db: database handle used to execute the query.
func saveCountNSPerDomain(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountNSPerDomain(runId, db)
	if err != nil {
		log.Fatalf("Error counting NS per domain: %v", err)
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_CountNSPerDomain_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
	}
	defer file.Close()

	var data []map[string]interface{}
	columns, err := rows.Columns()
	if err != nil {
		log.Fatalf("Error getting columns: %v", err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			log.Fatalf("Error scanning row: %v", err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("Error iterating rows: %v", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatalf("Error encoding JSON: %v", err)
	}
}

// saveCountNSCountryASNPerDomain exports NS distribution data per domain to a JSON file.
//
// This function retrieves information from the database about how nameservers (NS)
// are distributed across countries and autonomous systems (ASNs) for each domain in the run.
// The results are written as a JSON file into the jsonsFolder directory.
//
// Parameters:
// - runId: ID of the current run used to filter the data.
// - ts: timestamp string used to name the output file uniquely.
// - db: database handle used to perform the query.
func saveCountNSCountryASNPerDomain(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountNSCountryASNPerDomain(runId, db)
	if err != nil {
		log.Fatalf("Error counting NS Country ASN per domain: %v", err)
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_CountNSCountryASNPerDomain_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
	}
	defer file.Close()

	var data []map[string]interface{}
	columns, err := rows.Columns()
	if err != nil {
		log.Fatalf("Error getting columns: %v", err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			log.Fatalf("Error scanning row: %v", err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("Error iterating rows: %v", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatalf("Error encoding JSON: %v", err)
	}
}

// saveCountNSIPv4IPv6 writes the count of unique nameservers with IPv4 and IPv6 addresses to a JSON file.
//
// This function queries the database for the number of distinct nameservers that have IPv4 and IPv6 addresses
// for a given run. It then creates a JSON file in the jsonFolder directory containing these two values.
//
// Parameters:
// - runId: ID of the current data collection run.
// - ts: timestamp string used to generate the output filename.
// - db: open database connection used for querying.
func saveCountNSIPv4IPv6(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountDistinctNSWithIPv4(runId, db)
	if err != nil {
		log.Fatalf("Error counting distinct NS with IPv4: %v", err)
	}
	var countIPv4 int
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&countIPv4); err != nil {
			log.Fatalf("Error scanning countIPv4: %v", err)
		}
	}

	rows, err = dbController.CountDistinctNSWithIPv6(runId, db)
	if err != nil {
		log.Fatalf("Error counting distinct NS with IPv6: %v", err)
	}
	var countIPv6 int
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&countIPv6); err != nil {
			log.Fatalf("Error scanning countIPv6: %v", err)
		}
	}

	filename := fmt.Sprintf("%s/%d_CountNSIPv4IPv6_%s.json", jsonFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
	}
	defer file.Close()

	data := map[string]int{
		"countIPv4": countIPv4,
		"countIPv6": countIPv6,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatalf("Error encoding JSON: %v", err)
	}
}

// saveCountDomainsWithCountNSIPs exports the number of IP addresses per domain's nameservers to a JSON file.
//
// This function retrieves from the database the count of IP addresses (either IPv4 or IPv6) associated
// with the nameservers of each domain involved in a specific run. The result is encoded into a JSON
// file named using the run ID and timestamp, and stored in the `jsonFolder` directory.
//
// Parameters:
//   - runId: ID of the data collection run (used for filtering and naming the output).
//   - ts: timestamp string used to generate the filename (typically the start time of the run).
//   - db: database connection used to perform the query.
//
// The output JSON is an array of objects, where each object represents one domain and its associated
// count of NS IPs. Each object contains key-value pairs corresponding to the columns returned by the query.
func saveCountDomainsWithCountNSIPs(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountDomainsWithCountNSIp(runId, db)
	if err != nil {
		log.Fatalf("Error counting domains with NS IPs: %v", err)
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_CountDomainsWithCountNSIPs_%s.json", jsonFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
	}
	defer file.Close()

	var data []map[string]interface{}
	columns, err := rows.Columns()
	if err != nil {
		log.Fatalf("Error getting columns: %v", err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			log.Fatalf("Error scanning row: %v", err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("Error iterating rows: %v", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatalf("Error encoding JSON: %v", err)
	}
}

// saveCountDNSSEC exports the DNSSEC status summary for all domains in a given run to a JSON file.
//
// This function queries the number of domains with three categories of DNSSEC status:
//   - "no_dnssec": domains without any DNSSEC records,
//   - "dnssec_fail": domains with invalid or misconfigured DNSSEC,
//   - "dnssec_ok": domains with valid DNSSEC configuration.
//
// The data is saved in a JSON file located in `jsonsFolder`, with the filename containing the run ID and timestamp.
//
// Parameters:
//   - runId: ID of the current measurement run.
//   - ts: timestamp string used to generate the filename.
//   - db: database connection used to retrieve DNSSEC statistics.
//
// The output JSON is an array of objects, each containing a "category" and the number of "domains" in that category.
//
// Example output format:
/*
[
  {"category": "no_dnssec", "domains": 800},
  {"category": "dnssec_fail", "domains": 110},
  {"category": "dnssec_ok", "domains": 90}
]
*/
func saveCountDNSSEC(runId int, ts string, db *sql.DB) {
	dnssecFail, dnssecOk, noDnssec := dbController.CountDomainsWithDNSSEC(runId, db)
	filename := fmt.Sprintf("%s/%d_CountDomainsWithDNSSEC_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
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
		log.Fatalf("Error encoding JSON: %v", err)
	}
}

// saveCountDNSSECerrors exports the count of DNSSEC validation failure types for a given run to a JSON file.
//
// This function retrieves the number of domains that failed DNSSEC validation due to specific reasons:
//   - "Negación de Existencia" (Denial of Existence): issues related to NSEC/NSEC3 proof failures.
//   - "Validación de llaves" (Key Validation): issues validating DNSKEY records.
//   - "Validación de DS" (DS Validation): issues validating the Delegation Signer (DS) record.
//
// The data is saved as a JSON array in a file located in `jsonsFolder` with a filename
// including the run ID and timestamp.
//
// Parameters:
//   - runId: ID of the current measurement run.
//   - ts: timestamp string used to generate the filename.
//   - db: database connection used to retrieve DNSSEC error statistics.
//
// The resulting JSON file contains an array of objects with "failure" descriptions and
// the number of "domains" affected in each category.
func saveCountDNSSECerrors(runId int, ts string, db *sql.DB) {
	denialProof, dnskeyValidation, dsValidation := dbController.CountDomainsWithDNSSECErrors(runId, db)
	filename := fmt.Sprintf("%s/%d_CountDomainsWithDNSSECerrors_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
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
		log.Fatalf("Error encoding JSON: %v", err)
	}
}

// saveCountNameserverCharacteristics retrieves various DNS nameserver characteristic counts for a given run
// and saves the data into a JSON file.
//
// This function queries the database for counts of nameservers based on whether they fulfill or fail certain characteristics:
//   - Recursive query support
//   - EDNS (Extension mechanisms for DNS) support
//   - TCP communication support
//   - Zone transfer allowance over TCP
//   - Response to LOC (location) queries
//
// The data is then saved as an array of objects, each containing:
//   - "category": the characteristic being evaluated,
//   - "fail": the count of domains/nameservers that do NOT support the characteristic,
//   - "fulfill": the count of domains/nameservers that DO support the characteristic.
//
// Parameters:
//   - runId: the ID of the current measurement run.
//   - ts: a timestamp string used to create unique output filenames.
//   - db: a pointer to the SQL database connection.
//
// The JSON file is saved in the directory specified by `jsonsFolder` with a filename including the run ID and timestamp.
//
// Example output format:
/*
-category, count of domains "yes", count of domains "no"
allows recursion, 300, 700
-EDNS enabled, 100, 900
-no TCP communication allowed, 500, 500
-zone transfer allowed, 100, 900
*/
func saveCountNameserverCharacteristics(runId int, ts string, db *sql.DB) {
	recursivity, noRecursivity, edns, noEdns, tcp, noTcp, zoneTransfer, noZoneTransfer, locQuery, noLocQuery := dbController.CountNameserverCharacteristics(runId, db)
	filename := fmt.Sprintf("%s/%d_CountNameserverCharacteristics_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
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
		log.Fatalf("Error encoding JSON: %v", err)
	}
}

// saveDNSSEC runs the saving process for DNSSEC-related domain statistics.
//
// This function calls two separate functions to generate JSON reports:
//   - saveCountDNSSEC: saves counts of domains by DNSSEC status (no DNSSEC, fail, ok).
//   - saveCountDNSSECerrors: saves counts of domains by specific DNSSEC error types.
//
// Parameters:
//   - runId: the ID of the current measurement run.
//   - ts: timestamp string used to create unique output filenames.
//   - db: pointer to the SQL database connection.
func saveDNSSEC(runId int, ts string, db *sql.DB) {
	saveCountDNSSEC(runId, ts, db)
	saveCountDNSSECerrors(runId, ts, db)
}

// CheckDNSSEC performs DNSSEC validation checks for a specific domain.
//
// It verifies the presence and correctness of DNSSEC-related records:
//   - NSEC and NSEC3 records, including wildcard handling.
//   - DS (Delegation Signer) records.
//   - DNSKEY (DNS Public Key) records.
//
// The function also updates domain information in the database about NSEC and NSEC3 status if those records are found.
//
// Parameters:
//   - domainId: the identifier of the domain to check.
//   - db: the database connection used for updating domain info.
//
// Returns nine booleans indicating the presence and validity of the DNSSEC records and wildcard detection:
//   - dsFound: whether a DS record was found.
//   - dsOk: whether the DS record is valid.
//   - dnskeyFound: whether a DNSKEY record was found.
//   - dnskeyOk: whether the DNSKEY record is valid.
//   - nsecFound: whether an NSEC record was found.
//   - nsecOk: whether the NSEC record is valid.
//   - nsec3Found: whether an NSEC3 record was found.
//   - nsec3Ok: whether the NSEC3 record is valid.
//   - wildcard: true if either NSEC or NSEC3 wildcard presence was detected.
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

// CheckDNSKEY checks the presence and validity of DNSKEY records for a specific domain.
//
// This function queries the database for DNSKEY information of the given domain.
//
// Parameters:
//   - domainId: the identifier of the domain to check.
//   - db: the database connection used to retrieve DNSKEY information.
//
// Returns:
//   - dnskeyFound: true if DNSKEY records exist for the domain.
//   - dnskeyOk: true if the DNSKEY records are valid according to the database.
func CheckDNSKEY(domainId int, db *sql.DB) (dnskeyFound bool, dnskeyOk bool) {
	dnskeyFound, dnskeyOk = dbController.GetDNSKEYInfo(domainId, db)
	return
}

// CheckDS checks the presence and validity of DS (Delegation Signer) records for a specific domain.
//
// This function queries the database for DS record information of the given domain.
//
// Parameters:
//   - domainId: the identifier of the domain to check.
//   - db: the database connection used to retrieve DS record information.
//
// Returns:
//   - dsFound: true if DS records exist for the domain.
//   - dsOk: true if the DS records are valid according to the database.
func CheckDS(domainId int, db *sql.DB) (dsFound bool, dsOk bool) {
	dsFound, dsOk = dbController.GetDSInfo(domainId, db)
	return
}

// CheckNSECs verifies the presence and validity of NSEC (Next Secure) records for a given domain.
//
// This function performs several checks:
//   - Retrieves the non-existence status of the domain from the database.
//   - Retrieves NSEC records info, including flags about RRSIG validity, coverage, and wildcard presence.
//   - Aggregates the flags to determine overall NSEC presence and validity according to DNSSEC rules.
//
// Parameters:
//   - domainId: the ID of the domain to check.
//   - db: the database connection used for querying NSEC data.
//
// Returns:
//   - nsecFound: true if one or more NSEC records are found.
//   - nsecOk: true if the NSEC records satisfy validity conditions based on the aggregated flags and non-existence status.
//   - wildcard: true if any of the NSEC records indicate a wildcard proof.
//
// Behavior notes:
//   - If no NSEC records are found, all return values are false.
//   - The function considers multiple NSEC records and their RRSIG validation, coverage, and wildcard status to determine if the domain's NSEC configuration is valid.
//   - If any database query errors occur, the function logs fatally or panics.
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

// CheckNSEC3s verifies the presence and validity of NSEC3 records for a given domain.
//
// This function performs the following steps:
//   - Retrieves the domain's non-existence status from the database.
//   - Retrieves NSEC3 records and their attributes, such as RRSIG validation, matching, coverage, wildcard flags.
//   - Aggregates these attributes to determine if NSEC3 records are present and valid according to DNSSEC criteria.
//
// Parameters:
//   - domainId: the ID of the domain to check.
//   - db: the database connection used to query NSEC3 data.
//
// Returns:
//   - nsec3Found: true if one or more NSEC3 records are found.
//   - nsec3Ok: true if the NSEC3 records satisfy the validity conditions based on aggregated flags and non-existence status.
//   - wildcard: true if any NSEC3 record indicates a wildcard proof.
//
// Behavior notes:
//   - If no NSEC3 records exist, all return values are false.
//   - The function logs fatal errors if database queries or scans fail.
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

// saveNSs retrieves all nameserver (NS) records for a given run from the database,
// and saves them as a JSON array in a file.
//
// The function performs the following steps:
//   - Queries the database for NS records linked to the specified run ID.
//   - Reads each row dynamically, mapping column names to values.
//   - Writes the entire result as an indented JSON array into a file named
//     "<jsonsFolder>/<runId>_domainNSs.json".
//
// Parameters:
//   - runId: the identifier of the measurement run whose NS records are retrieved.
//   - db: the database connection used to execute queries.
//
// The output file is created under the directory specified by `jsonsFolder`,
// and contains a JSON array of objects representing NS records with their column names as keys.
//
// The function terminates the program with a fatal log message if any error occurs
// during database query, file creation, row scanning, or JSON encoding.
func saveNSs(runId int, db *sql.DB) {
	rows, err := dbController.GetNSs(runId, db)
	if err != nil {
		log.Fatalf("Error retrieving NSs: %v", err)
	}
	defer rows.Close()

	filename := fmt.Sprintf("%s/%d_domainNSs.json", jsonsFolder, runId)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
	}
	defer file.Close()

	var data []map[string]interface{}
	columns, err := rows.Columns()
	if err != nil {
		log.Fatalf("Error getting columns: %v", err)
	}

	for rows.Next() {
		row := make(map[string]interface{})
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			log.Fatalf("Error scanning row: %v", err)
		}
		for i, col := range columns {
			row[col] = values[i]
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("Error iterating rows: %v", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatalf("Error encoding JSON: %v", err)
	}
}
