package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"github.com/korylprince/ipnetgen"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"github.com/miekg/dns"
	"bytes"
	"os/exec"
	"sync"
	"time"
	"github.com/oschwald/geoip2-golang"
)

var giasn *geoip2.Reader

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

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

var TotalTime int
var mutexTT *sync.Mutex

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

	/*init geoip asn db*/
	giasn, err = getGeoIpAsnDB()
	if err != nil {
		fmt.Println(err.Error())
	}

	getDataQueue := make(chan string, concurrency)
	wg := sync.WaitGroup{}
	wg.Add(concurrency)
	mutexTT = &sync.Mutex{}
	/*Init n routines to read the queue*/
	for i := 0; i < concurrency; i++ {
		go func() {
			j := 0
			totalTime := 0
			for ip := range getDataQueue {
				t2 := time.Now()
				//fmt.Println("Looking for:",ip)
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
	/*fill the queue with data*/
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
	/*Close the queue*/
	close(getDataQueue)
	/*wait for routines to finish*/
	wg.Wait()
	TotalTime = (int)(time.Since(t).Nanoseconds())

}
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

func getGeoIpAsnDB() (*geoip2.Reader, error) {
	file := "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
	gi, err := geoip2.Open(file)
	if err != nil {
		fmt.Printf("Could not open GeoIPASNUM database: %s\n", err)
		return nil, err
	}
	return gi, err
}

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
			//fmt.Println("----------------------------------------------------------------")
			//fmt.Println(ip,msg.Answer)
			data := getName(ip)
			name, err := net.LookupAddr(ip)
			if err != nil {
				//fmt.Println(ip, "Name:\t", "", "\t", "\t", msg)

			}

			/*get asn*/
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
				fmt.Println("ASN NIL!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",ip)
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

	/**
	    Try to get the whois server to query from IANA Response
	**/

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

// Run whois command and return buffer
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
