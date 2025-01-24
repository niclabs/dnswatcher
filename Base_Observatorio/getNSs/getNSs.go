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

var mutexTT *sync.Mutex
var jsonsFolder = "jsons"

func main() {
	p := flag.Bool("p", false, "Prompt for password?")
	u := flag.String("u", "", "Database User")
	db := flag.String("db", "", "Database Name")
	pw := flag.String("pw", "", "Database Password")
	runid := flag.Int("runid", 1, "Database run id")
	flag.Parse()

	pass := ""
	//
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
	for i := 0; i < concurrency; i++ { //Lanzo n rutinas para que lean de la cola
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

	//Ahora hay que llenar la cola!
	rows, err := dbController.GetDomains(runId, db)
	defer rows.Close()
	for rows.Next() { //para cada dominio hacer lo siguiente:
		var domainId int
		if err := rows.Scan(&domainId); err != nil {
			log.Fatal(err)
		}
		domainIds <- domainId
	}
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	close(domainIds) //Cierro la cola
	//espero a que todos terminen
	wg.Wait()
	getGlobalStatistics(runId, ts, db)

	TotalTime := (int)(time.Since(t).Nanoseconds())
	fmt.Println("Total Time:", TotalTime)
	fmt.Println("openconnections", db.Stats())
}
func CheckDomainInfo(domainId int, db *sql.DB) {
	//CheckDispersion(domain_id,db)
	dnssecOk := false
	dsFound, dsOk, dnskeyFound, dnskeyOk, nsecFound, nsecOk, nsec3Found, nsec3Ok, _ := CheckDNSSEC(domainId, db)

	if dsFound && dsOk && dnskeyFound && dnskeyOk && ((nsecFound && nsecOk) || (nsec3Found && nsec3Ok)) {
		dnssecOk = true
	}
	dbController.UpdateDomainDNSSEC(domainId, dnssecOk, db)

}

/*global statistics*/
func getGlobalStatistics(runId int, ts string, db *sql.DB) {
	initjsonsFolder()
	saveDispersion(runId, ts, db)
	saveDNSSEC(runId, ts, db)
	saveCountNameserverCharacteristics(runId, ts, db)
}
func initjsonsFolder() {
	if _, err := os.Stat(jsonsFolder); os.IsNotExist(err) {
		os.Mkdir(jsonsFolder, os.ModePerm)
	}
}

/*Nameserver characteristics*/
/*Dispersion*/
func saveDispersion(runId int, ts string, db *sql.DB) {
	saveCountNSPerDomain(runId, ts, db)
	saveCountASNPerDomain(runId, ts, db)
	saveCountCountryPerDomain(runId, ts, db)
	saveCountNSCountryASNPerDomain(runId, ts, db)
	saveCountNSIPv4IPv6(runId, ts, db)
	saveCountDomainsWithCountNSIPs(runId, ts, db)
	saveCountDomainsWithCountNSIPExclusive(runId, ts, db)
}

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

func saveCountDNSSEC(runId int, ts string, db *sql.DB) {
	dnssecFail, dnssecOk, noDnssec := dbController.CountDomainsWithDNSSEC(runId, db)
	filename := fmt.Sprintf("%s/%d_CountDomainsWithDNSSEC_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
	}
	defer file.Close()
	/*categoría, cantidad de dominios
	no_dnssec, 800
	dnssec_fail, 110
	dnssec_ok, 90
	*/
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

func saveCountNameserverCharacteristics(runId int, ts string, db *sql.DB) {
	recursivity, noRecursivity, edns, noEdns, tcp, noTcp, zoneTransfer, noZoneTransfer, locQuery, noLocQuery := dbController.CountNameserverCharacteristics(runId, db)
	filename := fmt.Sprintf("%s/%d_CountNameserverCharacteristics_%s.json", jsonsFolder, runId, ts)
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating JSON file: %v", err)
	}
	defer file.Close()
	/*categoria, cantidad de dominios "si", cantidad dominios "no"
	permite recursividad, 300, 700
	no posee EDNS, 900, 100
	no permite comunicación tcp, 500, 500
	permite transferir la zona, 100, 900
	*/
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

/*DNSSEC zone*/
func saveDNSSEC(runId int, ts string, db *sql.DB) {
	saveCountDNSSEC(runId, ts, db)
	saveCountDNSSECerrors(runId, ts, db)
}
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
func CheckDNSKEY(domainId int, db *sql.DB) (dnskeyFound bool, dnskeyOk bool) {
	dnskeyFound, dnskeyOk = dbController.GetDNSKEYInfo(domainId, db)
	return
}
func CheckDS(domainId int, db *sql.DB) (dsFound bool, dsOk bool) {
	dsFound, dsOk = dbController.GetDSInfo(domainId, db)
	return
}
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
