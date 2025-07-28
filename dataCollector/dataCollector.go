package dataCollector

import (
	"database/sql"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"github.com/miekg/dns"
	"github.com/niclabs/Observatorio/dbController"
	"github.com/niclabs/Observatorio/dnsUtils"
	"github.com/niclabs/Observatorio/geoIPUtils"
	"github.com/niclabs/Observatorio/utils"
	"github.com/oschwald/geoip2-golang"
)

// domain_list_size stores the number of domains to be processed.
var domain_list_size = 0

// concurrency defines the number of goroutines used for data collection.
var concurrency = 100

// dontProbeList contains IP networks that should not be probed.
var dontProbeList []*net.IPNet

// totalTime accumulates the total time taken for data collection.
var totalTime = 0

// debug enables debug logging if set to true.
var debug = false

// verbose enables verbose logging if set to true.
var verbose = false

// geoipCountryDb is the GeoIP2 database reader for country lookups.
var geoipCountryDb *geoip2.Reader

// geoipAsnDb is the GeoIP2 database reader for ASN lookups.
var geoipAsnDb *geoip2.Reader

// configServers holds the list of DNS servers to use for queries.
var configServers []string

// weirdStringSubdomainName is a random subdomain name used for NSEC/NSEC3 non-existence checks.
var weirdStringSubdomainName = "zskldhoisdh123dnakjdshaksdjasmdnaksjdh" //potentially nonexistent subdomain To use with NSEC

// dnsClient is the DNS client used for all DNS queries.
var dnsClient *dns.Client

// RootServer represents a DNS root server with its name and IP addresses.
type RootServer struct {
	Name string // Nombre del servidor
	IPv4 string // Dirección IPv4
	IPv6 string // Dirección IPv6
}

// rootServers is the list of DNS root servers with their IPv4 and IPv6 addresses.
var rootServers = []RootServer{
	{"a.root-servers.net", "198.41.0.4", "2001:503:ba3e::2:30"},
	{"b.root-servers.net", "199.9.14.201", "2001:500:200::b"},
	{"c.root-servers.net", "192.33.4.12", "2001:500:2::c"},
	{"d.root-servers.net", "199.7.91.13", "2001:500:2d::d"},
	{"e.root-servers.net", "192.203.230.10", "2001:500:a8::e"},
	{"f.root-servers.net", "192.5.5.241", "2001:500:2f::f"},
	{"g.root-servers.net", "192.112.36.4", "2001:500:12::d0d"},
	{"h.root-servers.net", "198.97.190.53", "2001:500:1::53"},
	{"i.root-servers.net", "192.36.148.17", "2001:7fe::53"},
	{"j.root-servers.net", "192.58.128.30", "2001:503:c27::2:30"},
	{"k.root-servers.net", "193.0.14.129", "2001:7fd::1"},
	{"l.root-servers.net", "199.7.83.42", "2001:500:1::42"},
	{"m.root-servers.net", "202.12.27.33", "2001:dc3::35"},
}

// InitCollect initializes the data collection environment.
//
// This function sets up the environment for data collection by performing the following tasks:
//   - Loads the list of IP networks that should not be probed from the specified file.
//   - Initializes the GeoIP country and ASN databases.
//   - Connects to the PostgreSQL database and creates tables if they do not exist.
//   - Sets the maximum number of CPUs to be used for concurrent processing.
//   - Configures the DNS servers to be used for queries.
//   - Initializes the DNS client.
//
// Parameters:
//   - dontProbeFileName: Path to the file containing IP networks that should not be probed.
//   - drop: If true, drops the existing database (always set to false in this function for safety).
//   - user: Database username.
//   - password: Database password.
//   - host: Database host address.
//   - port: Database port.
//   - dbname: Name of the database.
//   - geoipdb: Pointer to the GeoIP database struct containing country and ASN readers.
//   - dnsServers: List of DNS servers to use for queries.
//
// Returns:
//   - error: Returns an error if any step fails, otherwise returns nil.
func InitCollect(dontProbeFileName string, drop bool, user string, password string, host string, port int, dbname string, geoipdb *geoIPUtils.GeoipDB, dnsServers []string) error {
	drop = false //be careful, if this is true, it will drop the complete database
	//check Dont probelist file
	dontProbeList = InitializeDontProbeList(dontProbeFileName)

	//Init geoip
	geoipCountryDb = geoipdb.CountryDb
	geoipAsnDb = geoipdb.AsnDb

	url := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=disable",
		user,
		password,
		host,
		port,
		dbname)
	//initialize database (create tables if not created already and drop database if indicated)
	database, err := sql.Open("postgres", url)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	dbController.CreateTables(database, drop)
	database.Close()

	//set maximum number of cpus
	runtime.GOMAXPROCS(runtime.NumCPU())
	fmt.Println("num CPU:", runtime.NumCPU())

	//obtain config default dns servers
	//config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	configServers = dnsServers //config.Servers

	//dns client to use in future queries.
	dnsClient = new(dns.Client)

	return nil //no error.

}

// InitializeDontProbeList loads a list of IP networks (in CIDR notation) from a file
// and returns a slice of *net.IPNet representing networks that should not be probed.
//
// Parameters:
//   - dpf: Path to the file containing the list of IP networks in CIDR format.
//
// The function reads each line from the file, ignoring lines that are empty or contain a '#' character.
// For each valid CIDR, it parses and appends the network to the returned slice.
// If a line cannot be parsed as a CIDR, it prints a warning message.
//
// Returns:
//   - dontProbeList: Slice of *net.IPNet with the networks to avoid probing.
func InitializeDontProbeList(dpf string) (dontProbeList []*net.IPNet) {
	dontProbeListFile := dpf
	if len(dontProbeListFile) == 0 {
		fmt.Println("no dont Pobe list file found")
		return
	}
	domainNames, err := utils.ReadLines(dontProbeListFile)
	if err != nil {
		fmt.Println(err.Error())

	}
	for _, domainName := range domainNames {

		if strings.Contains(domainName, "#") || len(domainName) == 0 {
			continue
		}
		_, ipNet, err := net.ParseCIDR(domainName)
		if err != nil {
			fmt.Println("no CIDR in DontProbeList:", domainName)
		}
		dontProbeList = append(dontProbeList, ipNet)
	}
	return dontProbeList
}

// StartCollect initializes and starts the data collection process for a list of domains.
//
// This function performs the following steps:
//   - Connects to the PostgreSQL database using the provided credentials.
//   - Sets the concurrency level for goroutines.
//   - Creates a new run entry in the database.
//   - Sets debug and verbose logging options.
//   - Launches the data collection routines for the input domain list.
//   - Prints the total time taken for the collection process.
//   - Closes the database connection.
//
// Parameters:
//   - input: Path to the file containing the list of domains to process.
//   - c: Number of concurrent goroutines to use.
//   - dbname: Name of the PostgreSQL database.
//   - user: Database username.
//   - password: Database password.
//   - host: Database host address.
//   - port: Database port.
//   - debugBool: Enables debug logging if true.
//   - verboseBool: Enables verbose logging if true.
//
// Returns:
//   - runId: The identifier of the created run in the database.
func StartCollect(input string, c int, dbname string, user string, password string, host string, port int, debugBool bool, verboseBool bool) (runId int) {
	url := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=disable",
		user,
		password,
		host,
		port,
		dbname)
	database, err := sql.Open("postgres", url)
	if err != nil {
		fmt.Println(err)
		return
	}
	/*Initialize*/
	concurrency = c
	runId = dbController.NewRun(database)
	debug = debugBool
	verbose = verboseBool

	/*Collect data*/
	createCollectorRoutines(database, input, runId)

	fmt.Println("TotalTime(nsec):", totalTime, " (sec) ", totalTime/1000000000, " (min:sec) ", totalTime/60000000000, ":", totalTime%60000000000/1000000000)

	database.Close()
	return runId
}

// createCollectorRoutines launches concurrent routines to process a list of domains and collect DNS data.
//
// This function performs the following steps:
//   - Reads the list of domains from the specified input file.
//   - Initializes a queue and launches a number of goroutines (as defined by the global `concurrency` variable) to process the domains concurrently.
//   - Each goroutine processes domains from the queue by calling `collectSingleDomainInfo`.
//   - Progress is printed in 5% increments.
//   - After all domains are processed, it collects root server availability data.
//   - Saves the total execution time and marks the run as successful in the database.
//
// Parameters:
//   - db: Database connection.
//   - inputFile: Path to the file containing the list of domains to process.
//   - runId: Identifier for the current run in the database.
func createCollectorRoutines(db *sql.DB, inputFile string, runId int) {
	startTime := time.Now()
	fmt.Println("EXECUTING WITH ", concurrency, " GOROUTINES;")

	domainsList, err := utils.ReadLines(inputFile)
	if err != nil {
		fmt.Println("Error reading domains list" + err.Error())
		return
	}

	domain_list_size = len(domainsList)

	// Create the routines
	domainsQueue := make(chan string, concurrency)
	wg := sync.WaitGroup{}
	wg.Add(concurrency)
	//Init n routines to read the queue
	for i := 0; i < concurrency; i++ {
		go func(runId int) {
			j := 0
			for domainName := range domainsQueue {
				//t2:=time.Now()
				collectSingleDomainInfo(domainName, runId, db)
				//duration := time.Since(t2)
				j++
			}
			wg.Done()
		}(runId)
	}

	last_fifth := 0
	//fill the queue with data to obtain
	for i, domainName := range domainsList {
		domainName := dns.Fqdn(domainName)
		domainsQueue <- domainName
		percentage := 100 * i / domain_list_size
		if percentage > last_fifth {
			fmt.Println(last_fifth, "%")
			last_fifth += 5

		}
		manageVerbosity(strings.Join([]string{"Collecting data ", domainName}, ""))
		//fmt.Println(i)
	}
	fmt.Println("100%")

	//Close the queue
	close(domainsQueue)

	// Wait for routines to finish
	wg.Wait()

	// Collect root server availability data
	availabilityWg := sync.WaitGroup{}
	availabilityWg.Add(1)
	go func() {
		defer availabilityWg.Done()
		collectAvailabilityData(runId, db)
	}()

	// Wait for availability data collection to complete
	availabilityWg.Wait()

	// Save the result of the execution
	totalTime := (int)(time.Since(startTime).Nanoseconds())
	dbController.SaveCorrectRun(runId, totalTime, true, db)
	fmt.Println("Successful Run. run_id:", runId)
	db.Close()
}

// manageError logs the provided error message if debug mode is enabled.
//
// This function is used to print error messages to the standard output
// only when the global debug flag is set to true. It helps control
// the verbosity of error reporting during execution.
//
// Parameters:
//   - err: The error message to be logged.
func manageError(err string) {
	if debug {
		fmt.Println(err)
	}
}

// manageVerbosity prints the provided string to the standard output
// if verbose mode is enabled.
//
// This function is used to control the verbosity of the application's output.
// When the global verbose flag is set to true, it prints the given message.
//
// Parameters:
//   - str: The message to be printed if verbose mode is active.
func manageVerbosity(str string) {
	if verbose {
		fmt.Println(str)
	}
}

// getDomainsNameservers retrieves the NS (Name Server) records for a given domain.
//
// Parameters:
//   - domainName: The fully qualified domain name (FQDN) for which to obtain NS records.
//
// Returns:
//   - nameservers: A slice of dns.RR containing the NS records for the domain, or nil if none are found or an error occurs.
//
// This function queries the configured DNS servers for NS records of the specified domain using the global DNS client.
// If an error occurs during the query or no NS records are found, it returns nil.
func getDomainsNameservers(domainName string) (nameservers []dns.RR) {

	nss, _, err := dnsUtils.GetRecordSet(domainName, dns.TypeNS, configServers, dnsClient)
	if err != nil {
		manageError(strings.Join([]string{"get NS: ", domainName, err.Error()}, ""))
		//fmt.Println("Error asking for NS", domainName, err.Error())
		return nil
	} else {
		if len(nss.Answer) == 0 || nss.Answer == nil {
			return nil
		}
		return nss.Answer
	}
}

// obtainNsIpv4Info retrieves ASN and country information for a given IPv4 address of a nameserver,
// checks if the IP is in the Do-Not-Probe list, and saves the nameserver IP information to the database.
//
// Parameters:
//   - ip: IPv4 address of the nameserver.
//   - domainName: The domain name being processed.
//   - nameserverId: Identifier of the nameserver in the database.
//   - runId: Identifier of the current run in the database.
//   - db: Database connection.
//
// Returns:
//   - nameserverIpString: The string representation of the nameserver IP address, or an empty string if the IP is in the Do-Not-Probe list.
func obtainNsIpv4Info(ip net.IP, domainName string, nameserverId int, runId int, db *sql.DB) (nameserverIpString string) {
	nameserverIpString = net.IP.String(ip)
	dontProbe := true
	asn := geoIPUtils.GetIPASN(nameserverIpString, geoipAsnDb)
	country := geoIPUtils.GetIPCountry(nameserverIpString, geoipCountryDb)
	if isIPInDontProbeList(ip) {
		//fmt.Println("domain ", domainName, "in DontProbeList", ip)
		//TODO Future: save DONTPROBELIST in nameserver? and Domain?
		dbController.SaveNSIP(nameserverId, nameserverIpString, country, asn, dontProbe, runId, db)
		return ""
	}
	dontProbe = false
	dbController.SaveNSIP(nameserverId, nameserverIpString, country, asn, dontProbe, runId, db)
	return nameserverIpString
}

// obtainNsIpv6Info retrieves ASN and country information for a given IPv6 address of a nameserver
// and saves the nameserver IP information to the database.
//
// Parameters:
//   - ip: IPv6 address of the nameserver.
//   - nameserverId: Identifier of the nameserver in the database.
//   - runId: Identifier of the current run in the database.
//   - db: Database connection.
//
// Returns:
//   - nameserverIpString: The string representation of the nameserver IPv6 address.
func obtainNsIpv6Info(ip net.IP, nameserverId int, runId int, db *sql.DB) (nameserverIpString string) {
	nameserverIpString = net.IP.String(ip)
	country := geoIPUtils.GetIPCountry(nameserverIpString, geoipCountryDb)
	asn := geoIPUtils.GetIPASN(nameserverIpString, geoipAsnDb)
	dbController.SaveNSIP(nameserverId, nameserverIpString, country, asn, false, runId, db)
	return nameserverIpString
}

// checkRecursivityAndEDNS checks if a given nameserver provides recursion and supports EDNS for a specific domain.
//
// Parameters:
//   - domainName: The fully qualified domain name (FQDN) to query.
//   - ns: The nameserver to query (as a string, typically an IP or hostname).
//
// Returns:
//   - recursionAvailable: true if the nameserver allows recursion for the domain, false otherwise.
//   - EDNS: true if the nameserver supports EDNS (Extension Mechanisms for DNS), false otherwise.
//
// This function queries the specified nameserver for the given domain to determine if recursion is available
// and if EDNS is supported. It uses the global DNS client and logs errors if debug mode is enabled.
func checkRecursivityAndEDNS(domainName string, ns string) (recursionAvailable bool, EDNS bool) {
	RecAndEDNS := new(dns.Msg)
	RecAndEDNS, rtt, err := dnsUtils.GetRecursivityAndEDNS(domainName, ns, "53", dnsClient)
	if err != nil {
		manageError(strings.Join([]string{"Rec and EDNS: ", domainName, ns, err.Error(), rtt.String()}, ""))
	} else {
		if RecAndEDNS.RecursionAvailable {
			recursionAvailable = true
		}
		if RecAndEDNS.IsEdns0() != nil {
			EDNS = true
		}
	}
	return recursionAvailable, EDNS
}

// checkTCP checks if a given nameserver supports TCP for SOA queries on the specified domain.
//
// Parameters:
//   - domainName: The fully qualified domain name (FQDN) to query.
//   - ns: The nameserver to query (as a string, typically an IP or hostname).
//
// Returns:
//   - TCP: true if the nameserver responds to a SOA query over TCP, false otherwise.
//
// This function sets the DNS client to use TCP, performs a SOA query to the nameserver,
// and then restores the client to use UDP. If any answer is received, it returns true.
func checkTCP(domainName string, ns string) (TCP bool) {
	dnsClient.Net = "tcp"
	tcp, _, err := dnsUtils.GetRecordSetTCP(domainName, dns.TypeSOA, ns, dnsClient)
	dnsClient.Net = "udp"
	if err != nil {
		manageError(strings.Join([]string{"TCP: ", domainName, ns, err.Error()}, ""))
		return false
	} else {
		TCP = false
		for _, tcpa := range tcp.Answer {
			if tcpa != nil {
				TCP = true
				break
			}
		}
		return TCP
	}
}

// checkZoneTransfer attempts a DNS zone transfer (AXFR) for the specified domain and nameserver.
//
// Parameters:
//   - domainName: The fully qualified domain name (FQDN) to query for a zone transfer.
//   - ns: The nameserver to query (as a string, typically an IP address or hostname).
//
// Returns:
//   - zoneTransfer: true if the zone transfer was successful, false otherwise.
//
// This function uses dnsUtils.ZoneTransfer to initiate an AXFR request to the given nameserver.
// If the transfer is successful and no error is returned, it returns true. Otherwise, it logs the error
// (if debug mode is enabled) and returns false.
func checkZoneTransfer(domainName string, ns string) (zoneTransfer bool) {
	zoneTransfer = false
	zt, err := dnsUtils.ZoneTransfer(domainName, ns)
	if err != nil {
		manageError(strings.Join([]string{"zoneTransfer: ", domainName, ns, err.Error()}, ""))
	} else {
		val := <-zt
		if val != nil {
			if val.Error != nil {
			} else {
				//fmt.Printf("zone_transfer succeded oh oh!!")
				zoneTransfer = true
			}
		}
	}
	return zoneTransfer
}

// checkLOCQuery checks if a given nameserver returns a LOC (Location) DNS record for the specified domain.
//
// Parameters:
//   - domainName: The fully qualified domain name (FQDN) to query.
//   - ns: The nameserver to query (as a string, typically an IP address or hostname).
//
// Returns:
//   - locQuery: true if a LOC record is found in the DNS response, false otherwise.
//
// This function queries the specified nameserver for a LOC record of the given domain using the global DNS client.
// If a LOC record is found in the answer section, it returns true. If an error occurs or no LOC record is found, it returns false.
func checkLOCQuery(domainName string, ns string) (locQuery bool) {
	locQuery = false
	loc, _, err := dnsUtils.GetRecordSet(domainName, dns.TypeLOC, []string{ns}, dnsClient)
	if err != nil {
		manageError(strings.Join([]string{"locQuery: ", domainName, ns, err.Error()}, ""))
	} else {
		for _, loca := range loc.Answer {
			if _, ok := loca.(*dns.LOC); ok {
				locQuery = true
				break
			}
		}
	}
	return locQuery
}

// getAndSaveDomainIPv4 retrieves the IPv4 (A) records for a given domain using the provided nameservers,
// saves each found IP address to the database, and returns the last IP as a string.
//
// Parameters:
//   - domainName: The fully qualified domain name (FQDN) to query for A records.
//   - domainNameServers: Slice of nameserver IPs to use for the DNS query.
//   - domainId: The database identifier for the domain.
//   - runId: The identifier for the current data collection run.
//   - db: The database connection.
//
// Returns:
//   - server: The last IPv4 address found (as a string), or an empty string if none found or on error.
func getAndSaveDomainIPv4(domainName string, domainNameServers []string, domainId int, runId int, db *sql.DB) (server string) {
	ipv4, err := dnsUtils.GetARecords(domainName, domainNameServers, dnsClient)
	if err != nil {
		manageError(strings.Join([]string{"get A record: ", domainName, err.Error()}, ""))
	} else {
		for _, ip := range ipv4 {
			ips := net.IP.String(ip)
			server = ips
			dbController.SaveDomainIp(ips, domainId, runId, db)
		}
	}
	return
}

// getAndSaveDomainIPv6 retrieves the IPv6 (AAAA) records for a given domain using the provided nameservers,
// saves each found IP address to the database, and does not return any value.
//
// Parameters:
//   - domainName: The fully qualified domain name (FQDN) to query for AAAA records.
//   - domainNameServers: Slice of nameserver IPs to use for the DNS query.
//   - domainId: The database identifier for the domain.
//   - runId: The identifier for the current data collection run.
//   - db: The database connection.
//
// This function queries the specified nameservers for AAAA records of the given domain using the global DNS client.
// For each IPv6 address found, it saves the address to the database. If an error occurs, it logs the error using manageError.
func getAndSaveDomainIPv6(domainName string, domainNameServers []string, domainId int, runId int, db *sql.DB) {

	ipv6, err := dnsUtils.GetAAAARecords(domainName, domainNameServers, dnsClient)
	if err != nil {

		manageError(strings.Join([]string{"get AAAA record: ", domainName, err.Error()}, ""))
	} else {
		for _, ip := range ipv6 {
			ips := net.IP.String(ip)
			dbController.SaveDomainIp(ips, domainId, runId, db)
		}
	}
}

// getAndSaveDomainSOA retrieves the SOA (Start of Authority) record for a given domain
// using the provided nameservers, determines if an SOA record exists, and saves the result
// to the database.
//
// Parameters:
//   - domainName: The fully qualified domain name (FQDN) to query for the SOA record.
//   - domainNameServers: Slice of nameserver IPs to use for the DNS query.
//   - domainId: The database identifier for the domain.
//   - db: The database connection.
//
// This function queries the specified nameservers for an SOA record of the given domain
// using the global DNS client. If an SOA record is found in the answer section, it sets
// the SOA flag to true. The result is then saved to the database using dbController.SaveSoa.
func getAndSaveDomainSOA(domainName string, domainNameServers []string, domainId int, db *sql.DB) {
	/*check soa*/
	SOA := false
	soa, err := dnsUtils.CheckSOA(domainName, domainNameServers, dnsClient)
	if err != nil {
		manageError(strings.Join([]string{"check soa: ", domainName, err.Error()}, ""))
	} else {
		for _, soar := range soa.Answer {
			if _, ok := soar.(*dns.SOA); ok {
				SOA = true
			}
		}
	}
	dbController.SaveSoa(SOA, domainId, db)
}

// checkAndSaveDSs retrieves DS (Delegation Signer) records for a given domain, saves them to the database, and returns information about their presence.
//
// Parameters:
//   - domainName: The fully qualified domain name (FQDN) to query for DS records.
//   - servers: Slice of nameserver IPs to use for the DNS query.
//   - domainId: The database identifier for the domain.
//   - runId: The identifier for the current data collection run.
//   - db: The database connection.
//
// Returns:
//   - dsFound: true if at least one DS record is found, false otherwise.
//   - dsOk: always false (not evaluated in this function).
//   - dsRrset: Slice of dns.RR containing the found DS records, or nil if none found.
//
// This function queries the specified nameservers for DS records of the given domain using the global DNS client.
// For each DS record found, it saves the record to the database. If an error occurs, it returns immediately.
/*
func checkAndSaveDSs(domain_name string, servers []string, domain_id int, run_id int, db *sql.DB)(ds_found bool, ds_ok bool, ds_rrset []dns.RR){
	ds_found = false
	ds_ok = false
	dss, _, err := dnsUtils.GetRecordSet(domain_name, dns.TypeDS, config_servers, dns_client)
	if (err != nil) {
		//manageError(strings.Join([]string{"DS record", domain_name, err.Error()}, ""))
		return ds_found, ds_ok, nil
	}
	for _, ds := range dss.Answer {
		if ds1, ok := ds.(*dns.DS); ok {
			ds_found=true
			ds_rrset = append(ds_rrset,ds1)
			var algorithm = int(ds1.Algorithm)
			var keyTag int = int(ds1.KeyTag)
			var digestType int = int(ds1.DigestType)
			digest := ds1.Digest
			dbController.SaveDS(domain_id, algorithm, keyTag, digestType, digest, run_id, db)
		}
	}
	return ds_found, ds_ok,

}*/

// getAndSaveDNSSECinfo retrieves and stores DNSSEC-related information for a given domain.
//
// This function performs the following steps:
//  1. Queries for DS (Delegation Signer) records for the domain using the configured DNS servers.
//     - Saves each DS record found to the database.
//     - If DS records are found, attempts to validate their RRSIG signatures and updates the domain's DS status in the database.
//  2. Queries for DNSKEY records for the domain using the provided nameservers.
//     - Saves each DNSKEY record to the database, checking if it matches any DS record.
//     - Validates RRSIG signatures covering DNSKEY records and updates the domain's DNSKEY status in the database.
//  3. Checks for NSEC and NSEC3 records to determine non-existence of names and wildcards.
//     - Saves NSEC/NSEC3 records and their validation status to the database.
//
// Parameters:
//   - domainName: The fully qualified domain name (FQDN) to query.
//   - domainNameServers: Slice of nameserver IPs to use for DNSKEY and NSEC/NSEC3 queries.
//   - domainId: The database identifier for the domain.
//   - runId: The identifier for the current data collection run.
//   - db: The database connection.
//
// This function logs errors using manageError and updates the database with all relevant DNSSEC information.
func getAndSaveDNSSECinfo(domainName string, domainNameServers []string, domainId int, runId int, db *sql.DB) {

	/*check DNSSEC*/

	/*ds*/
	dss, _, err := dnsUtils.GetRecordSet(domainName, dns.TypeDS, configServers, dnsClient)
	if err != nil {
		manageError(strings.Join([]string{"DS record: ", domainName, err.Error()}, ""))
	} else {
		dsOk := false
		dsFound := false

		var dsRrset []dns.RR
		for _, ds := range dss.Answer {
			if ds1, ok := ds.(*dns.DS); ok {
				dsFound = true
				dsRrset = append(dsRrset, ds1)
				var algorithm = int(ds1.Algorithm)
				var keyTag = int(ds1.KeyTag)
				var digestType = int(ds1.DigestType)
				digest := ds1.Digest
				dbController.SaveDS(domainId, algorithm, keyTag, digestType, digest, runId, db)
			}
		}
		if dsFound {
			rrsigs, _, err := dnsUtils.GetRecordSetWithDNSSEC(domainName, dns.TypeDS, configServers, dnsClient)
			if err != nil {
				manageError(strings.Join([]string{"DS record: ", domainName, err.Error()}, ""))
			} else {
				for _, ds := range rrsigs.Answer {
					if rrsig, ok := ds.(*dns.RRSIG); ok {
						dbController.SaveRRSIG(rrsig, domainId, runId, db)
						expired := false
						keyFound := false
						verified := false
						var dnskeys *dns.Msg

						if rrsig.TypeCovered != dns.TypeDS {
							continue
						}
						if !rrsig.ValidityPeriod(time.Now().UTC()) {
							expired = true
						}
						//---------------DNSKEY----------------------------
						dnskeys, _, _ = dnsUtils.GetRecordSetWithDNSSEC(rrsig.SignerName, dns.TypeDNSKEY, configServers, dnsClient)
						if dnskeys != nil && dnskeys.Answer != nil {
							key := dnsUtils.FindKey(dnskeys, rrsig)
							if key != nil {
								keyFound = true
								if err := rrsig.Verify(key, dsRrset); err != nil {
									//fmt.Printf(";- Bogus signature, %s does not validate (DNSKEY %s/%d/%s) [%s] %s\n", rrsig.Hdr.Name, key.Header().Name, key.KeyTag(), "net", err, expired)
									verified = false
								} else {
									verified = true
								}
							}
						} else {
							//fmt.Println("DS error no key found")
						}
						if keyFound && verified && !expired {
							dsOk = true
							break
						}
					}
				}
			}
		}
		dbController.UpdateDomainDSInfo(domainId, dsFound, dsOk, db)
	}

	/*dnskeys*/

	dnskeysLine, _, err := dnsUtils.GetRecordSetWithDNSSEC(domainName, dns.TypeDNSKEY, domainNameServers, dnsClient)
	if err != nil {
		manageError(strings.Join([]string{"dnskey: ", domainName, err.Error()}, ""))
	} else {
		if len(dnskeysLine.Answer) != 0 {
			dnskeyFound := false
			dnskeyOk := false
			var dnskeyRrset []dns.RR
			/*si no tiene dnskey no busco nada de dnssec*/
			for _, dnskey := range dnskeysLine.Answer {
				if dnskey1, ok := dnskey.(*dns.DNSKEY); ok {
					dnskeyFound = true
					dnskeyRrset = append(dnskeyRrset, dnskey1)
					DSok := false
					if dnskey1.Flags == 1 {
						//check DS
						ds1 := dnskey1.ToDS(dnskey1.Algorithm)
						for _, ds := range dss.Answer {
							if ds2, ok := ds.(*dns.DS); ok {
								if ds2.Digest == ds1.Digest {
									DSok = true
								}
							}
						}
					}
					dbController.SaveDNSKEY(dnskey1, DSok, domainId, runId, db)
				}
			}
			rrsigs := dnskeysLine
			for _, rrsig := range rrsigs.Answer {
				if rrsig1, ok := rrsig.(*dns.RRSIG); ok {
					if rrsig1.TypeCovered != dns.TypeDNSKEY {
						continue
					}
					dbController.SaveRRSIG(rrsig1, domainId, runId, db)
					expired := false
					keyFound := false
					verified := false
					var dnskeys *dns.Msg

					if !rrsig1.ValidityPeriod(time.Now().UTC()) {
						expired = true
					}
					//---------------DNSKEY----------------------------
					dnskeys, _, _ = dnsUtils.GetRecordSetWithDNSSEC(rrsig1.SignerName, dns.TypeDNSKEY, configServers, dnsClient)
					if dnskeys != nil && dnskeys.Answer != nil {
						key := dnsUtils.FindKey(dnskeys, rrsig1)
						if key != nil {
							keyFound = true
							if err := rrsig1.Verify(key, dnskeyRrset); err != nil {
								verified = false
							} else {
								verified = true
							}
						}
					} else {
						//fmt.Println("DS error no key found")
					}
					if keyFound && verified && !expired {
						dnskeyOk = true
						break
					}
				}
			}

			dbController.UpdateDomainDNSKEYInfo(domainId, dnskeyFound, dnskeyOk, db)

			/*nsec/3*/
			{
				d := domainName
				line := weirdStringSubdomainName + "." + d
				t := dns.TypeA
				in, _, err := dnsUtils.GetRecordSetWithDNSSEC(line, t, domainNameServers, dnsClient)
				if err != nil {
					//fmt.Println(err.Error())
					manageError(strings.Join([]string{"nsec/3: ", line, err.Error()}, ""))
				} else {
					nonExistenceStatus := in.Rcode
					dbController.UpdateNonExistence(domainId, nonExistenceStatus, db)

					for _, ans := range in.Ns {
						//authority section
						if nsec, ok := ans.(*dns.NSEC); ok {
							ncover := false
							ncoverwc := false
							niswc := false
							last := nsec.Hdr.Name
							next := nsec.NextDomain
							ttl := int(nsec.Hdr.Ttl)
							//save nsec
							nsecId := dbController.SaveNsec(domainId, last, next, ttl, runId, db)
							/*verify nsec in other task*/

							if dnsUtils.Less(line, last) == 0 {
								niswc = true
							} else {
								wildcardline := "*." + d
								if dnsUtils.Less(wildcardline, next) < 0 {
									ncoverwc = true
								}
								if (dnsUtils.Less(line, next) < 0 && dnsUtils.Less(line, last) > 0) || (dnsUtils.Less(line, last) > 0 && next == d) {
									ncover = true
								}
							}
							expired := false
							keyFound := false
							verified := false
							for _, ats := range in.Ns {
								if rrsig, ok := ats.(*dns.RRSIG); ok {
									expired = false
									keyFound = false
									verified = false
									var dnskeys *dns.Msg
									if rrsig.TypeCovered != dns.TypeNSEC {
										continue
									}
									if !rrsig.ValidityPeriod(time.Now().UTC()) {
										expired = true
									}
									//---------------DNSKEY----------------------------
									if rrsig.SignerName != line {
										dnskeys, _, _ = dnsUtils.GetRecordSetWithDNSSEC(rrsig.SignerName, dns.TypeDNSKEY, configServers, dnsClient)
									} else {
										dnskeys = dnskeysLine
									}

									if dnskeys != nil && dnskeys.Answer != nil {
										key := dnsUtils.FindKey(dnskeys, rrsig)
										if key != nil {
											keyFound = true
											var rrset []dns.RR
											rrset = []dns.RR{nsec}
											if err := rrsig.Verify(key, rrset); err != nil {
												verified = false
											} else {
												verified = true

											}
										}
									}
									if keyFound && verified && !expired {
										break
									}
								}
							}

							dbController.UpdateNSEC(keyFound && verified && !expired, ncover, ncoverwc, niswc, nsecId, db)

						} else if nsec3, ok := ans.(*dns.NSEC3); ok {
							hashedName := nsec3.Hdr.Name
							nextHashedName := nsec3.NextDomain
							iterations := int(nsec3.Iterations)
							hashAlgorithm := int(nsec3.Hash)
							salt := nsec3.Salt
							nsec3Id := dbController.SaveNsec3(domainId, hashedName, nextHashedName, iterations, hashAlgorithm, salt, runId, db)
							n3cover := false
							n3coverwc := false
							n3match := false
							n3wc := false
							n3cover = nsec3.Cover(line)
							n3coverwc = nsec3.Cover("*." + d)
							n3match = nsec3.Match(d)
							n3wc = nsec3.Match("*." + d)
							expired := false
							keyFound := false
							verified := false
						firmas:
							for _, ats := range in.Ns {
								if rrsig, ok := ats.(*dns.RRSIG); ok {
									expired = false
									keyFound = false
									verified = false

									var dnskeys *dns.Msg
									if rrsig.TypeCovered != dns.TypeNSEC3 {
										continue firmas
									}
									if !rrsig.ValidityPeriod(time.Now().UTC()) {
										expired = true
									}

									//---------------DNSKEY----------------------------
									if rrsig.SignerName != line {
										dnskeys, _, _ = dnsUtils.GetRecordSetWithDNSSEC(rrsig.SignerName, dns.TypeDNSKEY, configServers, dnsClient)
									} else {
										dnskeys = dnskeysLine
									}
									if dnskeys != nil && dnskeys.Answer != nil {
										key := dnsUtils.FindKey(dnskeys, rrsig)
										if key != nil {
											keyFound = true

											var rrset []dns.RR
											rrset = []dns.RR{nsec3}
											if err := rrsig.Verify(key, rrset); err != nil {
												verified = false

											} else {
												verified = true

											}

										}
									}
									if keyFound && verified && !expired {
										break
									}
								}
							}

							dbController.UpdateNSEC3(keyFound && verified && !expired, keyFound, verified, expired, n3match, n3cover, n3coverwc, n3wc, nsec3Id, db)
						}
					}
				}
			}
		}
	}
}

// collectSingleDomainInfo collects DNS and DNSSEC information for a single domain and saves it to the database.
//
// This function performs the following steps:
//  1. Saves the domain in the database and obtains its ID.
//  2. Retrieves the NS records for the domain and processes each nameserver:
//     - Checks availability and authority of the nameserver.
//     - Saves the nameserver in the database.
//     - Retrieves and saves A and AAAA records for the nameserver.
//     - If the nameserver is available and authoritative, performs additional checks (recursivity, EDNS, TCP, zone transfer, LOC query).
//  3. If at least one IPv4 address for a nameserver is found, queries the domain for A, AAAA, SOA, and DNSSEC records using those nameservers and saves the results.
//
// Parameters:
//   - domainName: The fully qualified domain name (FQDN) to process.
//   - runId: The identifier for the current data collection run.
//   - db: The database connection.
func collectSingleDomainInfo(domainName string, runId int, db *sql.DB) {

	var domainId int
	// Create domain and save it in database
	domainId = dbController.SaveDomain(domainName, runId, db)

	// Obtain NS records for the domain
	var domainNameServers []string
	var domainNameServers4 []string

	{ //Check NSs of the domain
		// Obtain NS records for the domain
		var domainsNameservers = getDomainsNameservers(domainName)

		for _, nameserver := range domainsNameservers { //for each nameserver of the current domain_name
			if ns, ok := nameserver.(*dns.NS); ok {
				var nameserverId int
				resp, rtt, err := dnsUtils.CheckAvailability(domainName, ns, dnsClient) //check if IPv4 exists

				available := true
				authoritative := false
				if err != nil {
					available = false
				} else {
					authoritative = resp.Authoritative
				}
				nameserverId = dbController.CreateNS(ns, domainId, runId, db, available, authoritative) //create NS in database
				if err != nil {
					manageError(strings.Join([]string{"checkAvailability: ", domainName, ns.Ns, err.Error(), rtt.String()}, ""))
				} else if authoritative == false {
					manageError(strings.Join([]string{"checkAvailability: ", domainName, ns.Ns, "Not Authoritative", rtt.String()}, ""))
				} else {
					//get A records for NS
					ipv4, err := dnsUtils.GetARecords(ns.Ns, configServers, dnsClient)
					if err != nil {
						manageError(strings.Join([]string{"getANS: ", domainName, ns.Ns, err.Error()}, ""))
					} else { //If NS is ok then execute more tests
						for _, ip := range ipv4 {
							nameserverIpString := obtainNsIpv4Info(ip, domainName, nameserverId, runId, db)

							if nameserverIpString != "" {
								domainNameServers = append(domainNameServers, nameserverIpString)
								domainNameServers4 = append(domainNameServers4, nameserverIpString)
							}
						}
					}
					//get AAAA records for NS
					ipv6, err := dnsUtils.GetAAAARecords(ns.Ns, configServers, dnsClient)
					if err != nil {
						manageError(strings.Join([]string{"get AAAA NS ", domainName, ns.Ns, err.Error()}, ""))
					} else {
						for _, ip := range ipv6 {
							nameserverIpString := obtainNsIpv6Info(ip, nameserverId, runId, db)

							if nameserverIpString != "" {
								domainNameServers = append(domainNameServers, nameserverIpString)
							}
						}
					}

					// if there is at least one nameserver with IP...
					if len(domainNameServers) != 0 {
						recursivity := false
						EDNS := false
						locQuery := false
						TCP := false
						zoneTransfer := false
						if available {
							// edns, recursivity, tcp, zone_transfer, loc_query
							// Recursivity and EDNS
							recursivity, EDNS = checkRecursivityAndEDNS(domainName, ns.Ns)
							// TCP
							TCP = checkTCP(domainName, ns.Ns)
							// Zone transfer
							zoneTransfer = checkZoneTransfer(domainName, ns.Ns)
							// Wrong Queries (unusual types, ex: loc)
							locQuery = checkLOCQuery(domainName, ns.Ns)
						}
						dbController.SaveNS(recursivity, EDNS, TCP, zoneTransfer, locQuery, nameserverId, db)
					}
				}
			}
		}
	} // end check nameservers

	//Check domain info (asking to NS)
	if len(domainNameServers4) != 0 {

		//Get A and AAAA records
		getAndSaveDomainIPv4(domainName, domainNameServers4, domainId, runId, db)
		getAndSaveDomainIPv6(domainName, domainNameServers4, domainId, runId, db)
		// Check SOA record
		getAndSaveDomainSOA(domainName, domainNameServers4, domainId, db)
		// Get DNSSEC info
		getAndSaveDNSSECinfo(domainName, domainNameServers4, domainId, runId, db)
	}

}

// collectAvailabilityData performs SOA queries for each root server using both UDP and TCP protocols.
//
// This function iterates over the list of DNS root servers and, for each server, performs an SOA query
// using both IPv4 and (optionally) IPv6 addresses with UDP and TCP. The results, including the duration
// and success status of each query, are saved to the database. The function prints the outcome of each
// query to the standard output.
//
// Parameters:
//   - runId: The identifier for the current data collection run.
//   - db: The database connection.
//
// Note:
//   - The IPv6 queries are commented out by default, as some environments may not support IPv6 connectivity.
//     Uncomment the relevant section to enable IPv6 SOA queries if supported.
func collectAvailabilityData(runId int, db *sql.DB) {
	for _, server := range rootServers {
		for _, protocol := range []string{"udp", "tcp"} {
			// Perform SOA query using IPv4
			success, duration := querySOA(server.IPv4, protocol, dnsClient)

			availabilityResult := dbController.AvailabilityResult{
				RunID:     runId,
				Server:    server.Name,
				Transport: protocol,
				Duration:  duration,
				Correct:   success,
			}

			// Save the query duration and result to the database
			dbController.SaveAvailabilityResults(runId, availabilityResult, db)

			if success {
				fmt.Printf("Successful SOA query for %s (IPv4) with %s\n", server.Name, protocol)
			} else {
				fmt.Printf("Failed SOA query for %s (IPv4) with %s\n", server.Name, protocol)
			}

			/*
				// Perform SOA query using IPv6
				// Uncomment the following block if your environment supports IPv6 connectivity.

				success, duration = querySOA(server.IPv6, protocol, dnsClient)

				availabilityResult = dbController.AvailabilityResult{
					RunID:     runId,
					Server:    server.Name,
					Transport: protocol,
					Duration:  duration,
					Correct:   success,
				}

				dbController.SaveAvailabilityResults(runId, availabilityResult, db)

				if success {
					fmt.Printf("Successful SOA query for %s (IPv6) with %s\n", server.Name, protocol)
				} else {
					fmt.Printf("Failed SOA query for %s (IPv6) with %s\n", server.Name, protocol)
				}
			*/
		}
	}
}

// querySOA sends a DNS SOA (Start of Authority) query to the specified server using the given protocol.
//
// This function constructs and sends a DNS query for the SOA record of the root zone (".") to the provided server
// using the specified transport protocol ("udp" or "tcp") and the given DNS client. It measures the duration of the query,
// and returns whether a valid SOA record was received along with the elapsed time in seconds.
//
// Parameters:
//   - server:   The IP address (IPv4 or IPv6) of the DNS server to query.
//   - protocol: The transport protocol to use ("udp" or "tcp").
//   - c:        The DNS client to use for the query.
//
// Returns:
//   - bool:     true if an SOA record was received in the response, false otherwise.
//   - float64:  The duration of the query in seconds.
func querySOA(server string, protocol string, c *dns.Client) (bool, float64) {
	// Set timeout
	c.Timeout = 4 * time.Second

	//
	c.Net = protocol

	// Set protocol (UDP or TCP)
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeSOA)

	startTime := time.Now() // Start timer

	// Format the address correctly
	address := server
	if isIPv6(server) {
		address = "[" + server + "]" // Add brackets for IPv6 addresses
		fmt.Print("Esta es IPv6: ")
	} else {
		fmt.Print("Esta es IPv4: ")
	}

	// Perform the query
	r, _, err := c.Exchange(m, address+":53")
	duration := time.Since(startTime).Seconds() // Calculate duration

	if err != nil {
		fmt.Printf("Error querying %s with %s: %v\n", server, protocol, err)
		return false, duration // Return duration if error
	}

	// Check if an SOA record was received
	for _, ans := range r.Answer {
		if _, ok := ans.(*dns.SOA); ok {
			return true, duration // Consulta exitosa
		}
	}

	fmt.Printf("No SOA record received from %s with %s\n", server, protocol)
	return false, duration // No se recibió un SOA
}

// isIPv6 checks if the provided address string is an IPv6 address.
//
// Parameters:
//   - address: A string representing the IP address to check.
//
// Returns:
//   - bool: Returns true if the address is IPv6, false otherwise.
//
// This function parses the input string as an IP address and determines
// if it is IPv6 by checking if the result of To4() is nil.
func isIPv6(address string) bool {
	return net.ParseIP(address).To4() == nil
}

// isIPInDontProbeList checks if the given IP address is contained within any of the networks
// specified in the global dontProbeList.
//
// Parameters:
//   - ip: net.IP representing the IP address to check.
//
// Returns:
//   - bool: true if the IP is found in the dontProbeList, false otherwise.
//
// This function iterates over all networks in dontProbeList and returns true as soon as it finds
// a network that contains the provided IP address. If no match is found, it returns false.
func isIPInDontProbeList(ip net.IP) bool {
	var ipnet *net.IPNet
	for _, ipnet = range dontProbeList {
		if ipnet.Contains(ip) {
			//fmt.Println("DONT PROBE LIST ip: ", ip, " found in: ", ipnet)
			return true
		}
	}
	return false
}

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
