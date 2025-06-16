package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/korylprince/ipnetgen"
	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// giasn is a GeoIP2 reader used to lookup ASN and IP geolocation data.
var giasn *geoip2.Reader

// ip2int converts an IP address (IPv4 or IPv6) to a 32-bit unsigned integer.
// For IPv6 addresses, it uses only the last 4 bytes (assuming IPv4-mapped IPv6 addresses).
//
// Parameters:
// - ip: The net.IP object to convert.
//
// Returns:
// - A uint32 representing the IP address in big-endian byte order.
//
// Notes:
// - If the IP is IPv6, the function reads bytes 12 to 16 assuming an IPv4-mapped format (::ffff:a.b.c.d).
//
// Example:
//
//		ip := net.ParseIP("192.0.2.1")
//		intIP := ip2int(ip)
//	 returns 3221225985
func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

// int2ip converts a 32-bit unsigned integer to a net.IP IPv4 address.
//
// Parameters:
// - nn: A uint32 representing the IPv4 address in big-endian byte order.
//
// Returns:
// - A net.IP object representing the IPv4 address.
//
// Example:
//
//		ip := int2ip(3221225985)
//		fmt.Println(ip.String())
//	  prints "192.0.2.1"
func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

// readLines reads a text file and returns its contents as a slice of strings,
// where each element corresponds to a line in the file.
//
// Parameters:
// - path: A string representing the file path to read from.
//
// Returns:
// - A slice of strings ([]string), each representing a line in the file.
// - An error if the file cannot be opened or if a scanning error occurs.
//
// Notes:
// - The file is read line by line using a buffered scanner.
// - The function ensures the file is properly closed using defer.
//
// Example:
//
//	lines, err := readLines("data.txt")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, line := range lines {
//	    fmt.Println(line)
//	}
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

// TotalTime stores the accumulated time from concurrent operations.
var TotalTime int

// mutexTT protects access to TotalTime in concurrent contexts.
var mutexTT *sync.Mutex

// main is the entry point of the DNS Watcher application.
// It reads IP data from a file, initializes the GeoIP ASN database,
// processes each IP concurrently to gather resolver information,
// and measures the total execution time.
func main() {
	//inputFile := "CLparsed01082017.txt"
	inputFile := "port-53_2017-07-12.csv"
	lines, err := readLines(inputFile)
	if err != nil {
		fmt.Println(err.Error())
	}

	concurrency := 1
	t := time.Now()
	fmt.Println(t, concurrency, "threads")

	// init geoip asn db
	giasn, err = getGeoIpAsnDB()
	if err != nil {
		fmt.Println(err.Error())
	}

	getDataQueue := make(chan string, concurrency)
	wg := sync.WaitGroup{}
	wg.Add(concurrency)
	mutexTT = &sync.Mutex{}
	//Init n routines to read the queue
	for i := 0; i < concurrency; i++ {
		go func() {
			j := 0
			totalTime := 0
			for ip := range getDataQueue {
				t2 := time.Now()
				lookForResolver(ip)
				duration := time.Since(t2)
				mutexTT.Lock()
				totalTime += int(duration)
				mutexTT.Unlock()
				j++
			}
			wg.Done()
		}()
	}
	//fill the queue with data
	for _, line := range lines {
		//if(line=="") {
		//	continue
		//}
		cidr := getCIDR(line)
		gen, err := ipnetgen.New(cidr)
		if err != nil {
			fmt.Println(err.Error())
		}
		//fmt.Println("BLOCK:",cidr)
		for ip := gen.Next(); ip != nil; ip = gen.Next() {
			//fmt.Println(ip)
			//add ip to the queue
			getDataQueue <- ip.String()
		}
	}
	//Close the queue
	close(getDataQueue)
	//wait for routines to finish
	wg.Wait()
	TotalTime = (int)(time.Since(t).Nanoseconds())

}

// getCIDR parses a line containing an IP address and a count, and returns a CIDR notation string.
//
// Parameters:
// - line: A string expected to contain an IP address and optionally a count, separated by a comma.
//
// Returns:
// - A string in CIDR format (e.g., "192.0.2.0/24").
//
// Behavior:
// - If only the IP is provided, defaults the count to 1.
// - For IPv4 addresses, the count is converted to a subnet mask using log2(count).
// - For IPv6 addresses, the count is assumed to already represent the prefix length.
//
// Example input lines:
//
//	"192.168.1.0,256" → "192.168.1.0/24"
//	"2001:db8::,64"   → "2001:db8::/64"
func getCIDR(line string) string {
	l := strings.Split(line, ",")
	ips := ""
	counts := ""
	if len(l) == 1 {
		ips = l[0]
		counts = "1"
	} else {
		ips, counts = l[0], l[1]
	}
	//if(counts=="count") {
	//	continue
	//}
	ip := net.ParseIP(ips)
	count, err := strconv.ParseInt(counts, 10, 64)
	if err != nil {
		fmt.Println(err.Error())
	}
	mask := int64(0)
	if ip.To4() != nil {
		mask = 32 - int64(math.Log2(float64(count)))
		//continue
	} else {
		mask = int64(count)
	}
	//mask2 := int2ip(uint32(mask))
	//mask2 := math.Log2(float64(count))
	//fmt.Println(ip,"/",strconv.FormatInt(mask,10))
	cidr := ip.String() + "/" + strconv.FormatInt(mask, 10)
	return cidr
}

// getGeoIpAsnDB opens the MaxMind GeoLite2 ASN database from the default path.
//
// Returns:
// - A pointer to a geoip2.Reader if successful.
// - An error if the database file cannot be opened.
//
// The database file path is hardcoded as: "/usr/share/GeoIP/GeoLite2-ASN.mmdb".
// This function is typically used to enable IP-to-ASN lookups.
func getGeoIpAsnDB() (*geoip2.Reader, error) {
	file := "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
	gi, err := geoip2.Open(file)
	if err != nil {
		fmt.Printf("Could not open GeoIPASNUM database: %s\n", err)
		return nil, err
	}
	return gi, err
}

// lookForResolver queries a DNS resolver at the given IP address to gather DNS and ASN information.
//
// It performs the following steps:
//   - Sends a DNS A record query for "www.hola.com" to check if the resolver is responsive and supports recursion.
//   - If the resolver replies positively, attempts to perform a reverse DNS lookup on the IP.
//   - Retrieves ASN information using the global GeoIP ASN database reader (giasn).
//   - Sends a CHAOS class TXT query for "version.bind." to get the resolver's version string if available.
//   - Prints a CSV-formatted line with the IP, resolver version (if any), reverse DNS name, ASN number, ASN organization, and additional data.
//
// Parameters:
//   - ip: The IP address of the DNS resolver to query, as a string.
func lookForResolver(ip string) {
	//random := strconv.FormatInt(rand.Int63(),10)
	line := "www.hola.com"
	m := new(dns.Msg)
	//fmt.Println(dns.Fqdn(line))
	m.SetQuestion(dns.Fqdn(line), dns.TypeA)
	c := new(dns.Client)
	//fmt.Println(ip+":53")
	msg, _, err := c.Exchange(m, ip+":53")
	if err != nil {
		//fmt.Println(err.Error())
	}
	if msg != nil {
		if msg.Rcode != dns.RcodeRefused && msg.RecursionAvailable {
			//fmt.Println("-----------------------------------------")
			//fmt.Println(ip,msg.Answer)
			data := getName(ip)
			name, err := net.LookupAddr(ip)
			if err != nil {
				//fmt.Println(ip, "Name:\t", "", "\t", "\t", msg)

			}

			//get asn
			asn := ""
			asnName := ""
			ipNet := net.ParseIP(ip)
			record, err := giasn.ASN(ipNet)
			if err != nil {
				fmt.Println("error", err)
			} else {
				asn = strings.Join([]string{"ASN", strconv.Itoa(int(record.AutonomousSystemNumber))}, "")
				asnName = strings.Replace(record.AutonomousSystemOrganization, ",", "", -1)
			}
			/*if(as != ""){
				fmt.Println(as)
				asn = strings.Split(as, " ")[0]
				asn_name = strings.SplitAfterN(as, " ", 2)[1]
			}else{
				fmt.Println("ASN NIL",ip)
			}*/

			m2 := new(dns.Msg)
			m2.SetQuestion("version.bind.", dns.TypeTXT)
			m2.Question[0].Qclass = dns.ClassCHAOS
			msg2, _, err := c.Exchange(m2, ip+":53")
			if err != nil {
				//fmt.Println(err.Error())
				fmt.Println(ip, ", ,", name, ",", asn, ",", asnName, ",", data) //, msg)
			} else {
				if len(msg2.Answer) >= 1 {
					//r := regexp.MustCompile("[^\\]+")
					version := strings.Split(msg2.Answer[0].String(), "\"")[1]
					version = strings.Replace(version, ",", "", -1) //r.FindAllString(msg2.Answer[0].String(), -1)[4]
					fmt.Println(ip, ",", version, ",", name, ",", asn, ",", asnName, ",", data)
				} else {
					fmt.Println(ip, ", ,", name, ",", asn, ",", asnName, ",", data)
				}
			}

		}
	}
}

// getName performs a WHOIS query for the given IP address and extracts
// relevant network ownership information.
//
// The function:
//   - Executes a WHOIS query via the helper function RunWHOIS.
//   - Parses the WHOIS response line by line to extract fields like:
//     CIDR block, Organization ID (OrgId), Owner ID (ownerid), inetnum,
//     Organization Name (OrgName), and Owner.
//   - Returns a comma-separated string with inetnum, OwnerId, and Owner.
//
// Parameters:
//   - ip: The IP address to query WHOIS information for.
//
// Returns:
//   - A string summarizing inetnum, OwnerId, and Owner fields from the WHOIS response.
func getName(ip string) string {
	//addr,err :=dns.ReverseAddr(ip)
	//if(err!=nil) {
	//	fmt.Println("Error:", err.Error())
	//	return strings.Join([]string{"Error:", err.Error()}, " ")
	//}
	//fmt.Println(ip)
	wi := RunWHOIS(ip)
	//fmt.Println(wi.String())

	reader := bytes.NewReader(wi.Bytes())
	scanner := bufio.NewScanner(reader)
	// Scan lines
	scanner.Split(bufio.ScanLines)
	// Scan through lines and find CIDR and orgId
	CIDR := "" //"255.255.255.255/0"
	OrgId := ""
	OrgName := ""
	OwnerId := ""
	Owner := ""
	inetnum := ""
	for scanner.Scan() {
		line := scanner.Text()
		//fmt.Println(line)
		if strings.Contains(line, "# start") {
			//fmt.Println("---reset---")
			CIDR = ""
			OrgId = ""
			OwnerId = ""
		}
		if strings.Contains(line, "CIDR:") {
			// Trim the refer: on left
			CIDR = strings.TrimPrefix(line, "CIDR:")
			// Trim whitespace
			CIDR = strings.TrimSpace(CIDR)
		} else if strings.Contains(line, "OrgId:") {
			// Trim the refer: on left
			OrgId = strings.TrimPrefix(line, "OrgId:")
			// Trim whitespace
			OrgId = strings.TrimSpace(OrgId)
		} else if strings.Contains(line, "ownerid:") {
			// Trim the refer: on left
			OwnerId = strings.TrimPrefix(line, "ownerid:")
			// Trim whitespace
			OwnerId = strings.TrimSpace(OwnerId)
		} else if strings.Contains(line, "inetnum:") {
			// Trim the refer: on left
			inetnum = strings.TrimPrefix(line, "inetnum:")
			// Trim whitespace
			inetnum = strings.TrimSpace(inetnum)
		} else if strings.Contains(line, "OrgName:") {
			// Trim the refer: on left
			OrgName = strings.TrimPrefix(line, "OrgName:")
			// Trim whitespace
			OrgName = strings.TrimSpace(OrgName)
		} else if strings.Contains(line, "owner:") {
			// Trim the refer: on left
			Owner = strings.TrimPrefix(line, "owner:")
			// Trim whitespace
			Owner = strings.TrimSpace(Owner)
		}

	}
	s := []string{inetnum, OwnerId, Owner} //,"CIDR:",CIDR,"OrgId:",OrgId,"OrgName:",OrgName};
	//fmt.Printf(strings.Join(s, " "));
	return strings.Join(s, ", ")

	/*
		//fmt.Println("addr",addr)
		m := new(dns.Msg)
		//fmt.Println(dns.Fqdn(line))
		m.SetQuestion(addr, dns.TypePTR)
		c:=new(dns.Client)
		//fmt.Println(ip+":53")
		msg ,_ ,err := c.Exchange(m,ip+":53")
		if(err!=nil){
			//fmt.Println(err.Error())
		}
		//fmt.Println(msg.Extra)
		//fmt.Println(msg.Question)
		fmt.Println(msg.Answer)
		//fmt.Println(msg.Ns)
		for _, ns := range msg.Ns {
			if s, ok := ns.(*dns.SOA); ok {
				fmt.Println(s.Ns)
				fmt.Println(s.Mbox)

			}
		}
		//fmt.Println(msg)
	*/
}

// RunWHOIS performs a WHOIS lookup for the given IP address.
//
// The function:
//   - Validates the IP address format.
//   - Queries the IANA WHOIS server (whois.iana.org) to find the
//     authoritative WHOIS server for the IP address.
//   - Defaults to "whois.lacnic.net" if no referral is found.
//   - Queries the referred WHOIS server to get detailed registration data.
//   - Returns the raw WHOIS response as a bytes.Buffer.
//
// Parameters:
//   - ipAddr: The IP address to query WHOIS information for.
//
// Returns:
//   - A bytes.Buffer containing the full WHOIS response from the authoritative server.
func RunWHOIS(ipAddr string) bytes.Buffer {

	// Parse IP to make sure it is valid
	ipObj := net.ParseIP(ipAddr)
	if ipObj == nil {
		fmt.Println("Invalid IP Address!")
		return bytes.Buffer{}
	}

	// Use parsed IP for security reasons
	ipAddr = ipObj.String()

	// IANA WHOIS Server
	ianaServer := "whois.iana.org"

	// Run whois on IANA Server and get response
	ianaResponse := runWhoisCommand("-h", ianaServer, ipAddr)

	//Try to get the whois server to query from IANA Response

	// Default whois server in case we cannot find another one IANA
	whoisServer := "whois.lacnic.net"

	// Create a scanner to scan through IANA Response
	reader := bytes.NewReader(ianaResponse.Bytes())
	scanner := bufio.NewScanner(reader)
	// Scan lines
	scanner.Split(bufio.ScanLines)

	// Scan through lines and find refer server

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "refer:") {
			// Trim the refer: on left
			whoisServer = strings.TrimPrefix(line, "refer:")
			// Trim whitespace
			whoisServer = strings.TrimSpace(whoisServer)
		}

	}

	// Finally, run the actual whois command with the right whois servers
	whois := runWhoisCommand("-h", whoisServer, ipAddr)

	return whois
}

// runWhoisCommand executes the system "whois" command with the given arguments.
//
// It runs the "whois" command line tool passing the provided arguments,
// captures both standard output and standard error,
// and returns the combined output as a bytes.Buffer.
//
// Parameters:
//   - args: A variadic string slice representing the arguments to pass to the "whois" command.
//
// Returns:
//   - A bytes.Buffer containing the output (stdout and stderr) of the "whois" command execution.
func runWhoisCommand(args ...string) bytes.Buffer {
	// Store output on buffer
	var out bytes.Buffer

	// Execute command
	cmd := exec.Command("whois", args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Run()

	return out
}
