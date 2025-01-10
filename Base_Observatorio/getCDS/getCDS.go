package main

import (
	"bufio"
	"database/sql"
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/howeyc/gopass"
	_ "github.com/lib/pq"
	"github.com/miekg/dns"
	"github.com/niclabs/Observatorio/dbController"
	"github.com/niclabs/Observatorio/utils"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

//usage: -i=input_file -c=100 -u=user -pw=pass -db=database

var TotalTime int
var debug = false
var err error

var resultsFolder = "CDS_results"
var fo *os.File

var Drop = false

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

/*code that executes each routine*/
func getCDSInfo(domainName string, runId int, config *dns.ClientConfig, db *sql.DB) {
	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(domainName, dns.TypeCDS)
	records, _, error := c.Exchange(msg, config.Servers[0]+":53")
	if error != nil {
		fmt.Println(error)
	} else {
		for _, record := range records.Answer {
			if _, ok := record.(*dns.CDS); ok {
				dt := record.(*dns.CDS).DigestType
				dg := record.(*dns.CDS).Digest
				kt := record.(*dns.CDS).KeyTag
				al := record.(*dns.CDS).Algorithm
				r := []string{domainName, strconv.Itoa(int(kt)), strconv.Itoa(int(al)), strconv.Itoa(int(dt)), dg}
				err = csvWriter.Write(r)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println(r)
				//(dns.CDS)(record).DigestType
				//(dns.CDS)(record).KeyTag
				//(dns.CDS)(record).Algorithm
				//writeToResultsFile(record.String())
			}
		}
	}
}

/*dispatcher of routines*/
func DispatchCollectors(db *sql.DB, inputFile string, runId int, debugVar bool, concurrency int) {
	debug = debugVar
	t := time.Now()

	fmt.Println("input file: ", inputFile)
	writeToResultsFile("input file: " + inputFile)

	lines, err := readLines(inputFile)
	if err != nil {
		fmt.Println(err.Error())
	}
	config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	runtime.GOMAXPROCS(runtime.NumCPU())

	fmt.Println("num CPU:", runtime.NumCPU())
	writeToResultsFile("num CPU: " + strconv.Itoa(runtime.NumCPU()))

	getDataQueue := make(chan string, concurrency)
	wg := sync.WaitGroup{}
	wg.Add(concurrency)
	/*Init n routines to read the queue*/
	for i := 0; i < concurrency; i++ {
		go func(runId int) {
			j := 0
			for line := range getDataQueue {
				getCDSInfo(line, runId, config, db)
				j++
			}
			wg.Done()
		}(runId)
	}
	/*fill the queue with data to obtain*/
	for _, line := range lines {
		line := dns.Fqdn(line)
		getDataQueue <- line
	}
	/*Close the queue*/
	close(getDataQueue)
	/*wait for routines to finish*/
	wg.Wait()

	/*Collection finished!!*/
	TotalTime = (int)(time.Since(t).Nanoseconds())
	dbController.SaveCorrectRun(runId, TotalTime, true, db)
	fmt.Println("Successful Run. run_id:", runId)
	writeToResultsFile("Successful Run. run_id: " + strconv.Itoa(runId))
	db.Close()
}
func initResultsFile() {
	var err error
	f := "2006-01-02T15:04:05"
	ts := time.Now().Format(f)

	if _, err := os.Stat(resultsFolder); os.IsNotExist(err) {
		os.Mkdir(resultsFolder, os.ModePerm)
	}

	fo, err = os.Create(resultsFolder + "/CDS-" + ts + ".txt")
	if err != nil {
		fmt.Println(err.Error())
	}
	// close fo on exit and check for its returned error
}
func writeToResultsFile(s string) {
	if _, err := fo.WriteString(s + "\n"); err != nil {
		fmt.Println("error escribiendo en output", err.Error())
	}
}

var csvWriter *csv.Writer

func closeResultsFile() {
	fo.Close()
}

var csvFile os.File

func initCSV() {

	f := "2006-01-02T15:04:05"
	ts := time.Now().Format(f)

	filename := "results-" + ts + ".csv"
	folder := "CDS_csvs"

	csvFile, err := utils.CreateFile(folder, filename)
	if err != nil {
		fmt.Println(err.Error())
	}
	csvWriter = csv.NewWriter(csvFile)
}
func closeCSV() {
	csvWriter.Flush()
	csvFile.Close()
}

func collectCDS(inputfile string, concurrency int, ccmax int, maxRetry int, dropdatabase bool, database string, user string, password string, debug bool) {

}

func main() {

	inputFile, concurrency, ccmax, maxRetry, dropDatabase, database, user, password, debug := readArguments()
	initResultsFile()
	initCSV()

	Drop = *dropDatabase
	var retry = 0 //initial retry
	db, err := sql.Open("postgres", "user="+*user+" password="+password+" dbname="+*database+" sslmode=disable")
	if err != nil {
		fmt.Println(err)
		return
	}
	CreateTables(db)
	db.Close()

	for *concurrency <= ccmax { //used only for performance evaluation
		for retry < *maxRetry { //used only for performance evaluation

			db, err := sql.Open("postgres", "user="+*user+" password="+password+" dbname="+*database+" sslmode=disable")
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println("EXECUTING WITH ", concurrency, " GOROUTINES; retry: ", retry)
			writeToResultsFile("EXECUTING WITH " + strconv.Itoa(*concurrency) + " GOROUTINES; retry: " + strconv.Itoa(retry))

			runId := NewRun(db)
			/*Collect data*/
			DispatchCollectors(db, *inputFile, runId, *debug, *concurrency)

			fmt.Println("TotalTime(nsec):", TotalTime, " (sec) ", TotalTime/1000000000, " (min:sec) ", TotalTime/60000000000, ":", TotalTime%60000000000/1000000000)
			writeToResultsFile("TotalTime(nsec):" + strconv.Itoa(TotalTime) + " (sec) " + strconv.Itoa(TotalTime/1000000000) + " (min:sec) " + strconv.Itoa(TotalTime/60000000000) + ":" + strconv.Itoa(TotalTime%60000000000/1000000000))
			//var line string;
			//line = string(strconv.Itoa(run_id) + ", "+ strconv.Itoa(Concurrency) + ", " + strconv.Itoa(retry)+ ", " + strconv.Itoa(ec) + ", " + strconv.Itoa(tc) + ", " +strconv.Itoa(trc) + ", " + strconv.Itoa(tt))
			//fmt.Println(line)
			db.Close()
			retry++
		}
		*concurrency++
		retry = 0
	}

	closeResultsFile()
	closeCSV()

}

//usage: -i=input-file -c=100 -u=user -pw=pass -db=database
func readArguments() (inputfile *string, concurrency *int, ccmax int, maxRetry *int, dropdatabase *bool, db *string, u *string, pass string, debug *bool) {
	inputfile = flag.String("i", "", "Input file with domains to analize")
	concurrency = flag.Int("c", 50, "Concurrency: how many routines")
	cmax := flag.Int("cmax", -1, "max Concurrency: how many routines")
	maxRetry = flag.Int("retry", 1, "retry:how many times")
	dropdatabase = flag.Bool("drop", false, "true if want to drop database")
	p := flag.Bool("p", false, "Prompt for password?")
	u = flag.String("u", "", "Database User")
	db = flag.String("db", "", "Database Name")
	pw := flag.String("pw", "", "Database Password")
	debug = flag.Bool("d", false, "Debug flag")
	flag.Parse()
	pass = ""
	if *p {
		fmt.Printf("Password: ")
		// Silent. For printing *'s use gopass.GetPasswdMasked()
		pwd, err := gopass.GetPasswdMasked()
		if err != nil {
			fmt.Println(err.Error())
		}
		pass = string(pwd)

	} else {
		pass = *pw
	}
	ccmax = *cmax
	if ccmax == -1 {
		ccmax = *concurrency
	}
	return
}

/*TODOsave to database results*/
func CreateTables(db *sql.DB) {

	DropTable("runs_cds", db)
	_, err := db.Exec("CREATE TABLE  IF NOT EXISTS runs ( id SERIAL PRIMARY KEY, tstmp timestamp, correct_run bool, duration int)")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}

	DropTable("cds", db)
	// id | run_id | domain_name | int field_1 | int field_2 |  int field_3 | varchar() field_4 |  field_5 |
	_, err = db.Exec("CREATE TABLE  IF NOT EXISTS domain (id SERIAL PRIMARY KEY, run_id integer REFERENCES runs(id), domain_name varchar(253), field_1 int, field_2 int, field_3 int, field_4 varchar(253), field_5 varchar(253))")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
}
func SaveCDS(line string, field1 int, field2 int, field3 int, field4 string, field5 string, runId int, db *sql.DB) int {
	var cdsId int
	err := db.QueryRow("INSERT INTO cds(domain_name, field_1, field_2, field_3, field_4, field_5, run_id) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id", line, runId).Scan(&cdsId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), "domain name", line)
		if strings.Contains(err.Error(), "too many open files") {
			return SaveCDS(line, field1, field2, field3, field4, field5, runId, db)
		}
		panic(err)
	}
	return cdsId
}
func DropTable(table string, db *sql.DB) {
	if Drop {
		_, err := db.Exec("DROP TABLE IF EXISTS " + table + " CASCADE")
		if err != nil {
			fmt.Println("OpenConnections", db.Stats())
			panic(err)
		}
	}
}
func NewRun(db *sql.DB) int {
	var runId int
	err := db.QueryRow("INSERT INTO runs(tstmp) VALUES($1) RETURNING id", time.Now()).Scan(&runId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
	return runId
}
func SaveCorrectRun(runId int, duration int, correct bool, db *sql.DB) {
	_, err := db.Exec("UPDATE runs SET duration = $1, correct_run = $2 WHERE id = $3", duration/1000000000, correct, runId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " run_id", runId)
		panic(err)
	}
}
