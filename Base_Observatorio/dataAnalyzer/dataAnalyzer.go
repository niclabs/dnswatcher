package dataAnalyzer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/niclabs/Observatorio/dbController"
)

var mutexTT *sync.Mutex
var jsonsFolder string = "jsons"

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
	fmt.Println("Total Time (nsec):", TotalTime)
	fmt.Println("Total Time (min:sec):", TotalTime/60000000000, ":", TotalTime%60000000000/1000000000)

	fmt.Println("openconnections", db.Stats())

}
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

/*global statistics*/
func getGlobalStatistics(runId int, ts string, db *sql.DB) {
	initjsonFolder()
	saveDispersion(runId, ts, db)                     // aqui estan 7 de los json
	saveDNSSEC(runId, ts, db)                         //9 y 10
	saveCountNameserverCharacteristics(runId, ts, db) // 8
	saveJsonRecomendations(runId, ts)
}

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
func initjsonFolder() {
	if _, err := os.Stat(jsonsFolder); os.IsNotExist(err) {
		os.Mkdir(jsonsFolder, os.ModePerm)
	}
}

/*Nameserver characteristics*/
/*Dispersion*/
// es cm guardarlo a json creo
// agregué el de disponibilidad
func saveDispersion(runId int, ts string, db *sql.DB) {
	saveCountNSPerDomain(runId, ts, db)
	saveCountASNPerDomain(runId, ts, db)
	saveCountCountryPerDomain(runId, ts, db)
	saveCountNSCountryASNPerDomain(runId, ts, db)
	saveCountNSIPv4IPv6(runId, ts, db)
	saveCountDomainsWithCountNSIPs(runId, ts, db)
	saveCountDomainsWithCountNSIPExclusive(runId, ts, db)
	saveAvailabilityResults(runId, ts, db)
}

// Obtiene los resultados de disponibilidad y los guarda en formato json
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
