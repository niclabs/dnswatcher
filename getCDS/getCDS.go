package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/howeyc/gopass"
	_ "github.com/lib/pq"
	"github.com/miekg/dns"
	"github.com/niclabs/Observatorio/dbController"
)

//usage: -i=input_file -c=100 -u=user -pw=pass -db=database

var TotalTime int
var debug = false
var err error

var resultsFolder = "CDS_results"
var fo *os.File

var Drop = false

// readLines reads a file line by line and returns a slice containing all the lines.
//
// Parameters:
//
//   - path: The path to the input file to be read.
//
// Returns:
//
//   - A slice of strings, each representing a line from the file.
//   - An error if the file cannot be opened or read.
//
// Notes:
//
//   - Uses a buffered scanner for efficient line-by-line reading.
//   - The file is closed automatically using defer.
//   - Returns the first error encountered during scanning (if any).
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

// getCDSInfo queries CDS (Child DS) DNS records for a given domain and writes the results to a JSON file.
//
// Parameters:
//
//   - domainName: The domain name to query for CDS records.
//   - runId: An identifier used to name the output file uniquely.
//   - config: A pointer to a dns.ClientConfig struct containing DNS server configuration.
//   - db: A pointer to an SQL database connection (currently unused in this function).
//
// Behavior:
//
//   - Sends a DNS query of type CDS to the first DNS server in the provided config.
//   - Parses the CDS records from the DNS response, extracting key tag, algorithm, digest type, and digest.
//   - Collects all CDS records into a slice of maps.
//   - If records are found, serializes them into a prettified JSON file named as "<resultsFolder>/<runId>_CDS_<domainName>.json".
//   - Handles and logs errors during DNS querying and file operations.
//
// Notes:
//   - The database parameter 'db' is currently unused but may be reserved for future use or logging.
func getCDSInfo(domainName string, runId int, config *dns.ClientConfig, db *sql.DB) {
	c := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetQuestion(domainName, dns.TypeCDS)
	records, _, error := c.Exchange(msg, config.Servers[0]+":53")
	if error != nil {
		fmt.Println(error)
	} else {
		var data []map[string]interface{}
		for _, record := range records.Answer {
			if cds, ok := record.(*dns.CDS); ok {
				dt := cds.DigestType
				dg := cds.Digest
				kt := cds.KeyTag
				al := cds.Algorithm
				entry := map[string]interface{}{
					"domain":      domainName,
					"key_tag":     kt,
					"algorithm":   al,
					"digest_type": dt,
					"digest":      dg,
				}
				data = append(data, entry)
			}
		}
		if len(data) > 0 {
			filename := fmt.Sprintf("%s/%d_CDS_%s.json", resultsFolder, runId, domainName)
			file, err := os.Create(filename)
			if err != nil {
				fmt.Printf("Error creating JSON file: %v", err)
				return
			}
			defer file.Close()
			encoder := json.NewEncoder(file)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(data); err != nil {
				fmt.Printf("Error writing JSON: %v", err)
			}
		}
	}
}

// DispatchCollectors manages concurrent execution of CDS data collection routines for a list of domain names.
//
// Parameters:
//
//   - db: An active connection to the SQL database, used to log the run status.
//   - inputFile: Path to a file containing domain names, one per line.
//   - runId: A unique identifier for this execution, used in logs and result filenames.
//   - debugVar: Boolean to enable or disable debug mode (currently sets a global debug variable).
//   - concurrency: The number of concurrent routines to launch for processing domains.
//
// Behavior:
//   - Reads domain names from the input file.
//   - Initializes a fixed number of goroutines to consume domain names from a channel and call getCDSInfo.
//   - Each routine processes entries until the queue is empty.
//   - Writes runtime information and status messages to the results log.
//   - After completion, logs the run as successful in the database.
//
// Notes:
//   - Uses a buffered channel (`getDataQueue`) to control work distribution.
//   - Uses a WaitGroup to ensure all routines complete before proceeding.
//   - Applies full domain name formatting (FQDN) before processing with DNS lookups.
//   - Sets the number of OS threads to the number of available CPUs.
//   - Closes the database connection at the end of the run.
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

// initResultsFile initializes the results log file with a timestamped filename.
//
// Behavior:
//   - Creates the `resultsFolder` directory if it does not exist.
//   - Generates a filename using the current timestamp in the format "YYYY-MM-DDTHH:MM:SS".
//   - Creates a new `.txt` file inside the `resultsFolder` for writing log information.
//   - The file is assigned to the global variable `fo`.
//
// Notes:
//   - The function does not close the file, as it is intended to remain open for later writes.
//   - Errors during folder creation or file creation are printed to standard output.
//   - The global `fo` file should be closed appropriately elsewhere in the program to avoid resource leaks.
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

// writeToResultsFile appends a log entry to the "results_log.json" file.
//
// Parameters:
//   - s: the message string to log.
//
// Behavior:
//   - Opens (or creates if it does not exist) a JSON file named "results_log.json" in append mode.
//   - Constructs a log entry containing the provided message and a timestamp in RFC3339 format.
//   - Encodes the entry as a JSON object and writes it to the file.
//   - If any error occurs during file opening or writing, it prints the error message to standard output.
//
// Notes:
//   - Each log entry is a single JSON object written on a new line.
//   - The file is closed automatically via a deferred call to `file.Close()`.
//   - This function is useful for debugging or recording operational status messages.
func writeToResultsFile(s string) {
	filename := "results_log.json"
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("error opening results file", err.Error())
		return
	}
	defer file.Close()
	entry := map[string]string{"message": s, "timestamp": time.Now().Format(time.RFC3339)}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(entry); err != nil {
		fmt.Println("error writing to results file", err.Error())
	}
}

// closeResultsFile closes the global results file.
//
// Behavior:
//   - Closes the global file object `fo`, which is expected to have been initialized by `initResultsFile`.
//
// Notes:
//   - This function should be called when no further writes to the results file are needed.
//   - It does not handle or report any error from the `Close()` call.
//   - Ensure `fo` is not nil before calling this function to avoid a runtime panic.
func closeResultsFile() {
	fo.Close()
}

// collectCDS orchestrates the collection of CDS records from a list of domain names.
//
// Parameters:
//   - inputfile: path to the input file containing domain names (one per line).
//   - concurrency: number of concurrent workers to use during collection.
//   - ccmax: maximum number of concurrent connections (purpose should be clarified in implementation).
//   - maxRetry: number of retry attempts per failed operation.
//   - dropdatabase: if true, the database will be dropped before starting the collection.
//   - database: name of the PostgreSQL database to connect to.
//   - user: database username.
//   - password: database password.
//   - debug: enables debug output if set to true.
//
// Notes:
//   - This function is currently not implemented.
//   - It is expected to read domains from the input file, collect CDS DNS records in parallel,
//     store them into a database, and optionally handle cleanup or retries.
//   - The results may be logged or saved to external files, depending on the implementation.
//
// Usage example (CLI):
//
//	collectCDS("domains.txt", 100, 50, 3, false, "dnswatcher", "admin", "secret", true)
func collectCDS(inputfile string, concurrency int, ccmax int, maxRetry int, dropdatabase bool, database string, user string, password string, debug bool) {

}

// main is the entry point of the program.
// It reads command-line arguments, initializes the database,
// and orchestrates the collection of CDS records for a set of domain names.
//
// Workflow:
//  1. Parses arguments such as input file, concurrency level, retries, and DB credentials.
//  2. Initializes the PostgreSQL database and creates required tables.
//  3. For each concurrency level up to ccmax:
//     a. Attempts to collect CDS records up to maxRetry times.
//     b. Each attempt creates a new DB connection and run ID.
//     c. Launches DispatchCollectors to collect CDS data in parallel.
//  4. Logs progress to a results file.
//
// Notes:
//   - This function modifies the global variable Drop based on the provided flag.
//   - Each CDS collection attempt is associated with a unique run ID for traceability.
//   - Concurrency increases incrementally up to the defined maximum.
func main() {
	inputFile, concurrency, ccmax, maxRetry, dropDatabase, database, user, password, debug := readArguments()

	Drop = *dropDatabase
	db, err := sql.Open("postgres", "user="+*user+" password="+*password+" dbname="+*database+" sslmode=disable")
	if err != nil {
		fmt.Println(err)
		return
	}
	CreateTables(db)
	db.Close()

	for *concurrency <= ccmax {
		for retry := 0; retry < *maxRetry; retry++ {
			db, err := sql.Open("postgres", "user="+*user+" password="+*password+" dbname="+*database+" sslmode=disable")
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println("EXECUTING WITH ", *concurrency, " GOROUTINES; retry: ", retry)
			writeToResultsFile(fmt.Sprintf("EXECUTING WITH %d GOROUTINES; retry: %d", *concurrency, retry))

			runId := NewRun(db)
			DispatchCollectors(db, *inputFile, runId, *debug, *concurrency)
			db.Close()
		}
		*concurrency++
	}
}

// readArguments parses and returns the command-line arguments required for the CDS collection process.
//
// Supported Flags:
//   - i      (string)  Input file containing a list of domains to analyze (required).
//   - c      (int)     Initial concurrency level (number of goroutines to start). Default: 50.
//   - cmax   (int)     Maximum concurrency allowed. If not provided, it defaults to the initial concurrency.
//   - retry  (int)     Number of retry attempts for failed executions. Default: 1.
//   - drop   (bool)    Indicates whether to drop the existing database. Default: false.
//   - p      (bool)    Prompt for database password (masked input).
//   - pw     (string)  Database password (optional if -p is used).
//   - u      (string)  Database username.
//   - db     (string)  Database name.
//   - d      (bool)    Enable debug mode.
//
// Returns:
//
//	inputfile     -> pointer to input file string
//	concurrency   -> pointer to initial concurrency int
//	ccmax         -> int value for max concurrency
//	maxRetry      -> pointer to retry count int
//	dropdatabase  -> pointer to drop database flag
//	db            -> pointer to database name string
//	u             -> pointer to database username string
//	pass          -> string with the database password
//	debug         -> pointer to debug flag
//
// usage: -i=input-file -c=100 -u=user -pw=pass -db=database
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

// CreateTables ensures the required tables exist in the PostgreSQL database for storing CDS scan results.
// If the tables already exist, they will not be recreated. Optionally drops specific tables beforehand.
//
// Tables created:
//
//   - runs: stores metadata about each execution, including duration and success status.
//
//     Columns:
//
//   - id (SERIAL PRIMARY KEY)
//
//   - tstmp (timestamp): execution time
//
//   - correct_run (bool): whether the run was successful
//
//   - duration (int): execution time in nanoseconds
//
//   - domain: stores CDS records for scanned domains.
//
//     Columns:
//
//   - id (SERIAL PRIMARY KEY)
//
//   - run_id (int): foreign key referencing `runs(id)`
//
//   - domain_name (varchar(253)): fully qualified domain name
//
//   - field_1 (int): DNS CDS key tag
//
//   - field_2 (int): CDS algorithm
//
//   - field_3 (int): CDS digest type
//
//   - field_4 (varchar(253)): CDS digest
//
//   - field_5 (varchar(253)): reserved for additional info
//
// Parameters:
// - db (*sql.DB): an open connection to the PostgreSQL database
//
// Panics:
// - If table creation fails, the function will panic after printing database connection stats.
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

// SaveCDS inserts a CDS (Child DS) record into the `cds` table and returns the generated record ID.
//
// Parameters:
// - line (string): the domain name for which the CDS record was extracted.
// - field1 (int): CDS key tag.
// - field2 (int): CDS algorithm.
// - field3 (int): CDS digest type.
// - field4 (string): CDS digest.
// - field5 (string): optional or reserved field for additional info.
// - runId (int): identifier referencing the run (foreign key to `runs` table).
// - db (*sql.DB): open connection to the PostgreSQL database.
//
// Returns:
// - (int): the autogenerated ID of the newly inserted CDS record.
//
// Behavior:
// - If an error related to "too many open files" occurs, the function retries recursively.
// - On any other error, it prints connection stats and panics.
//
// Note:
//
//   - The current `INSERT` statement only passes `line` and `runId` to the query, which does not match
//     the placeholder structure of 7 values. The SQL query should be corrected to include all 7 parameters:
//
//     Corrected SQL:
//     ```sql
//     INSERT INTO cds(domain_name, field_1, field_2, field_3, field_4, field_5, run_id)
//     VALUES($1, $2, $3, $4, $5, $6, $7) RETURNING id
//     ```
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

// DropTable drops the specified table from the database if the global `Drop` flag is set to true.
//
// Parameters:
//   - table (string): name of the table to drop.
//   - db (*sql.DB): active connection to the PostgreSQL database.
//
// Behavior:
//   - Executes a `DROP TABLE IF EXISTS <table> CASCADE` SQL command.
//   - Only runs if the global variable `Drop` is true.
//   - Prints current open connection stats if an error occurs, and panics.
//
// Notes:
//   - The `CASCADE` option ensures that dependent objects (e.g., foreign key constraints) are also removed.
//   - Useful for test runs or controlled cleanups where you want to reset the database state.
func DropTable(table string, db *sql.DB) {
	if Drop {
		_, err := db.Exec("DROP TABLE IF EXISTS " + table + " CASCADE")
		if err != nil {
			fmt.Println("OpenConnections", db.Stats())
			panic(err)
		}
	}
}

// NewRun inserts a new run record into the `runs` table with the current timestamp,
// and returns the generated run ID.
//
// Parameters:
//   - db (*sql.DB): active connection to the PostgreSQL database.
//
// Returns:
//   - int: the ID of the newly created run record.
//
// Behavior:
//   - Executes an INSERT SQL statement to add a new row with the current timestamp.
//   - Uses RETURNING id to fetch the newly created run's primary key.
//   - Prints database connection stats and panics if an error occurs.
func NewRun(db *sql.DB) int {
	var runId int
	err := db.QueryRow("INSERT INTO runs(tstmp) VALUES($1) RETURNING id", time.Now()).Scan(&runId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
	return runId
}

// SaveCorrectRun updates the run record in the database with the total duration and correctness status.
//
// Parameters:
//   - runId (int): the ID of the run to update.
//   - duration (int): the total duration of the run in nanoseconds.
//   - correct (bool): indicates if the run was successful (true) or not (false).
//   - db (*sql.DB): active connection to the PostgreSQL database.
//
// Behavior:
//   - Converts duration from nanoseconds to seconds by dividing by 1,000,000,000.
//   - Executes an UPDATE SQL statement to set the duration and correctness flag for the specified run.
//   - Prints database connection stats and panics if an error occurs.
func SaveCorrectRun(runId int, duration int, correct bool, db *sql.DB) {
	_, err := db.Exec("UPDATE runs SET duration = $1, correct_run = $2 WHERE id = $3", duration/1000000000, correct, runId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " run_id", runId)
		panic(err)
	}
}
