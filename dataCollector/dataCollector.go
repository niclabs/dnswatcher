package dataCollector

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/miekg/dns"
	"github.com/niclabs/Observatorio/dbController"
	"github.com/niclabs/Observatorio/dnsUtils"
	"github.com/niclabs/Observatorio/geoIPUtils"
	"github.com/niclabs/Observatorio/utils"
	"github.com/oschwald/geoip2-golang"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
)

var domain_list_size = 0

var concurrency = 100

var dontProbeList []*net.IPNet

var totalTime = 0

var debug = false
var verbose = false

var geoipCountryDb *geoip2.Reader
var geoipAsnDb *geoip2.Reader

var configServers []string

var weirdStringSubdomainName = "zskldhoisdh123dnakjdshaksdjasmdnaksjdh" //potentially nonexistent subdomain To use with NSEC

var dnsClient *dns.Client

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

func createCollectorRoutines(db *sql.DB, inputFile string, runId int) {
	startTime := time.Now()

	fmt.Println("EXECUTING WITH ", concurrency, " GOROUTINES;")

	domainsList, err := utils.ReadLines(inputFile)
	if err != nil {
		fmt.Println("Error reading domains list" + err.Error())
		return
	}

	domain_list_size = len(domainsList)

	//CREATES THE ROUTINES
	domainsQueue := make(chan string, concurrency)
	wg := sync.WaitGroup{}
	wg.Add(concurrency)
	/*Init n routines to read the queue*/
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

	/*Close the queue*/
	close(domainsQueue)

	/*wait for routines to finish*/
	wg.Wait()

	totalTime = (int)(time.Since(startTime).Nanoseconds())
	dbController.SaveCorrectRun(runId, totalTime, true, db)
	fmt.Println("Successful Run. run_id:", runId)
	db.Close()
}

func manageError(err string) {
	if debug {
		fmt.Println(err)
	}
}

func manageVerbosity(str string) {
	if verbose {
		fmt.Println(str)
	}
}

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
func obtainNsIpv6Info(ip net.IP, nameserverId int, runId int, db *sql.DB) (nameserverIpString string) {
	nameserverIpString = net.IP.String(ip)
	country := geoIPUtils.GetIPCountry(nameserverIpString, geoipCountryDb)
	asn := geoIPUtils.GetIPASN(nameserverIpString, geoipAsnDb)
	dbController.SaveNSIP(nameserverId, nameserverIpString, country, asn, false, runId, db)
	return nameserverIpString
}
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

// Collects info from a single domain (ran by a routine) and save it to the databses.
func collectSingleDomainInfo(domainName string, runId int, db *sql.DB) {

	var domainId int
	// Create domain and save it in database
	domainId = dbController.SaveDomain(domainName, runId, db)

	/*Obtener NS del dominio*/
	var domainNameServers []string
	var domainNameServers4 []string

	{ //Check NSs of the domain
		/*Obtener NSs del dominio*/
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
							// Recursividad y EDNS
							recursivity, EDNS = checkRecursivityAndEDNS(domainName, ns.Ns)
							// TCP
							TCP = checkTCP(domainName, ns.Ns)
							// Zone transfer
							zoneTransfer = checkZoneTransfer(domainName, ns.Ns)
							// Wrong Queries (tipos extraños como loc)
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
