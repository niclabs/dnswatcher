package dataAnalyzer

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/niclabs/Observatorio/dbController"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var mutexTT *sync.Mutex
var csvsFolder string = "csvs"


func AnalyzeData(runId int, dbname string, user string, password string, host string, port int){
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
	ts=strings.ReplaceAll(ts,":","-")
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
func verifyDNSSEC(domainId int, db *sql.DB){
	//check if dnskey is found
	dnskeyFound, _ := dbController.GetDNSKEYInfo(domainId, db)
	if(!dnskeyFound){
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
	initcsvsFolder()
	saveDispersion(runId, ts, db)
	saveDNSSEC(runId, ts, db)
	saveCountNameserverCharacteristics(runId, ts, db)
	saveJsonRecomendations(runId,ts)
}

func saveJsonRecomendations(runId int, ts string){
	filename:="./csvs/"+strconv.Itoa(runId)+"CountNSCountryASNPerDomain"+ts+".csv"
	newfilename := "./csvs/"+strconv.Itoa(runId)+"CountRecomendations.json"

	//generate json data
	command:= exec.Command("./json" , filename,newfilename)
	err:=command.Run()
	if err != nil {
		log.Println(err)
	}
}
func initcsvsFolder() {
	if _, err := os.Stat(csvsFolder); os.IsNotExist(err) {
		os.Mkdir(csvsFolder, os.ModePerm)
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
	filename := "csvs/" + strconv.Itoa(runId) + "CountDomainsWithCountNSIPExclusive" + ts + ".csv"
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}
	writer.Write([]string{columns[0], columns[1]})
	for rows.Next() {
		var family int
		var num int
		if err := rows.Scan(&num, &family); err != nil {
			log.Fatal(err)
		}
		line := []string{strconv.Itoa(num), strconv.Itoa(family)}
		err := writer.Write(line)
		if err != nil {
			panic(err)
		}
	}
	defer writer.Flush()
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
}
func saveCountCountryPerDomain(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountCountryPerDomain(runId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	filename := "csvs/" + strconv.Itoa(runId) + "CountCountryPerDomain" + ts + ".csv"
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}
	writer.Write([]string{columns[0], columns[1]})
	for rows.Next() {
		var numCountries int
		var num int
		if err := rows.Scan(&numCountries, &num); err != nil {
			log.Fatal(err)
		}
		line := []string{strconv.Itoa(numCountries), strconv.Itoa(num)}
		err := writer.Write(line)
		if err != nil {
			panic(err)
		}
	}
	defer writer.Flush()
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

}
func saveCountASNPerDomain(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountASNPerDomain(runId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	filename := "csvs/" + strconv.Itoa(runId) + "CountASNPerDomain" + ts + ".csv"
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}
	writer.Write(columns)
	for rows.Next() {
		var numASN int
		var num int
		if err := rows.Scan(&numASN, &num); err != nil {
			log.Fatal(err)
		}
		line := []string{strconv.Itoa(numASN), strconv.Itoa(num)}
		err := writer.Write(line)
		if err != nil {
			panic(err)
		}
	}
	defer writer.Flush()
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}

}
func saveCountNSPerDomain(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountNSPerDomain(runId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	filename := "./csvs/" + strconv.Itoa(runId) + "CountNSPerDomain" + ts + ".csv"
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}
	writer.Write(columns)
	for rows.Next() {
		var numNS int
		var num int
		if err := rows.Scan(&numNS, &num); err != nil {
			log.Fatal(err)
		}
		line := []string{strconv.Itoa(numNS), strconv.Itoa(num)}
		err := writer.Write(line)
		if err != nil {
			panic(err)
		}
	}
	defer writer.Flush()
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
}
func saveCountNSCountryASNPerDomain(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountNSCountryASNPerDomain(runId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	filename := "csvs/" + strconv.Itoa(runId) + "CountNSCountryASNPerDomain" + ts + ".csv"
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}
	writer.Write([]string{columns[0], columns[1], columns[2], columns[3]})
	for rows.Next() {
		var numCountries int
		var numNS int
		var numASN int
		var num int
		if err := rows.Scan(&num, &numNS, &numASN, &numCountries); err != nil {
			log.Fatal(err)
		}
		line := []string{strconv.Itoa(num), strconv.Itoa(numNS), strconv.Itoa(numASN), strconv.Itoa(numCountries)}
		err := writer.Write(line)
		if err != nil {
			panic(err)
		}
	}
	defer writer.Flush()
	if err := rows.Err(); err != nil {
		log.Fatal(err)
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

	filename := "csvs/" + strconv.Itoa(runId) + "CountNSIPv4IPv6" + ts + ".csv"
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	err = writer.Write([]string{"countIPv4", "countIPv6"})
	if err != nil {
		panic(err)
	}
	line := []string{strconv.Itoa(countIPv4), strconv.Itoa(countIPv6)}
	err = writer.Write(line)
	if err != nil {
		panic(err)
	}
	defer writer.Flush()
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
}
func saveCountDomainsWithCountNSIPs(runId int, ts string, db *sql.DB) {
	rows, err := dbController.CountDomainsWithCountNSIp(runId, db)
	if err != nil {
		panic(err)
	}
	defer rows.Close()
	filename := "csvs/" + strconv.Itoa(runId) + "CountDomainsWithCountNSIps" + ts + ".csv"
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	columns, err := rows.Columns()
	if err != nil {
		panic(err)
	}
	writer.Write([]string{columns[0], columns[1], columns[2], columns[3]})
	for rows.Next() {
		var numIP int
		var numIPv6 int
		var numIPv4 int
		var num int
		if err := rows.Scan(&num, &numIP, &numIPv4, &numIPv6); err != nil {
			log.Fatal(err)
		}
		line := []string{strconv.Itoa(num), strconv.Itoa(numIP), strconv.Itoa(numIPv4), strconv.Itoa(numIPv6)}
		err := writer.Write(line)
		if err != nil {
			panic(err)
		}
	}
	defer writer.Flush()
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
}
func saveCountDNSSEC(runId int, ts string, db *sql.DB) {
	dnssecFail, dnssecOk, noDnssec := dbController.CountDomainsWithDNSSEC(runId, db)
	filename := "csvs/" + strconv.Itoa(runId) + "CountDomainsWithDNSSEC" + ts + ".csv"
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	if err != nil {
		panic(err)
	}
	/*categoría, cantidad de dominios
	no_dnssec, 800
	dnssec_fail, 110
	dnssec_ok, 90
	*/
	writer.Write([]string{"category", "domains"})
	line := []string{"no_dnssec", strconv.Itoa(noDnssec)}
	err = writer.Write(line)
	if err != nil {
		panic(err)
	}
	line = []string{"dnssec_fail", strconv.Itoa(dnssecFail)}
	err = writer.Write(line)
	if err != nil {
		panic(err)
	}
	line = []string{"dnssec_ok", strconv.Itoa(dnssecOk)}
	err = writer.Write(line)
	if err != nil {
		panic(err)
	}
	defer writer.Flush()
}
func saveCountDNSSECerrors(runId int, ts string, db *sql.DB) {
	denialProof, dnskeyValidation, dsValidation := dbController.CountDomainsWithDNSSECErrors(runId, db)
	filename := "csvs/" + strconv.Itoa(runId) + "CountDomainsWithDNSSECErrors" + ts + ".csv"
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	writer.Write([]string{"failiure", "domains"})
	writer.Write([]string{"Negación de Existencia", strconv.Itoa(denialProof)})
	writer.Write([]string{"Validación de llaves", strconv.Itoa(dnskeyValidation)})
	writer.Write([]string{"Validación de DS", strconv.Itoa(dsValidation)})
	defer writer.Flush()
}
func saveCountNameserverCharacteristics(runId int, ts string, db *sql.DB) {
	recursivity, noRecursivity, edns, noEdns, tcp, noTcp, zoneTransfer, noZoneTransfer, locQuery, noLocQuery := dbController.CountNameserverCharacteristics(runId, db)
	filename := "csvs/" + strconv.Itoa(runId) + "CountNameserverCharacteristics" + ts + ".csv"
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	/*categoria, cantidad de dominios "si", cantidad dominios "no"
	permite recursividad, 300, 700
	no posee EDNS, 900, 100
	no permite comunicación tcp, 500, 500
	permite transferir la zona, 100, 900
	*/
	writer := csv.NewWriter(file)
	writer.Write([]string{"category", "fail", "fulfill"})
	writer.Write([]string{"Permite Recursividad", strconv.Itoa(recursivity), strconv.Itoa(noRecursivity)})
	writer.Write([]string{"EDNS activado", strconv.Itoa(noEdns), strconv.Itoa(edns)})
	writer.Write([]string{"comunicacion TCP", strconv.Itoa(noTcp), strconv.Itoa(tcp)})
	writer.Write([]string{"Transferencia de zona TCP", strconv.Itoa(zoneTransfer), strconv.Itoa(noZoneTransfer)})
	writer.Write([]string{"Respuesta a consultas LOC", strconv.Itoa(locQuery), strconv.Itoa(noLocQuery)})
	defer writer.Flush()
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
