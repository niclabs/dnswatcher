package geoIPUtils

import (
	"fmt"
	"github.com/niclabs/Observatorio/utils"
	"github.com/oschwald/geoip2-golang"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type GeoipDB struct {
	CountryDb *geoip2.Reader
	AsnDb     *geoip2.Reader
}

// Initialize GEO IP databases
func InitGeoIP(geoipPath string, geoipCountryDbName string, geoipAsnDbName string, geoipLicenseKey string) *GeoipDB {
	var err error
	checkDatabases(geoipPath, geoipCountryDbName, geoipAsnDbName, geoipLicenseKey)
	giCountryDb, err := getGeoIpCountryDB(geoipPath + "/" + geoipCountryDbName)
	if err != nil {
		fmt.Println(err.Error())
	}
	giAsnDb, err := getGeoIpAsnDB(geoipPath + "/" + geoipAsnDbName)
	if err != nil {
		fmt.Println(err.Error())
	}
	geoipDb := &GeoipDB{giCountryDb, giAsnDb}
	return geoipDb
}

func CloseGeoIP(geoipDB *GeoipDB) {
	err :=geoipDB.CountryDb.Close()
	if err!=nil{
		fmt.Println(err)
	}
	err = geoipDB.AsnDb.Close()
	if err!=nil{
		fmt.Println(err)
	}
}

func downloadGeoIp(licenseKey string, geoipPath string, geoipAsnFilename string, geoipCountryFilename string) bool {

	//check if directory exists (create if not exists)
	if _, err := os.Stat(geoipPath); os.IsNotExist(err) {
		err = os.Mkdir(geoipPath,os.ModePerm)
		if err!=nil{
			fmt.Println(err)
			return false
		}
	}
	urlAsn := "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key="+ licenseKey +"&suffix=tar.gz"
	urlCountry := "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key="+ licenseKey +"&suffix=tar.gz"

	var wg sync.WaitGroup
	wg.Add(2)

	go downloadFile(urlAsn, geoipPath+"/"+geoipAsnFilename, &wg)

	go downloadFile(urlCountry, geoipPath+"/"+geoipCountryFilename, &wg)
	wg.Wait()

	return true
}
func downloadFile(url string, filepath string,  wg *sync.WaitGroup ) {
	defer wg.Done()
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
		return
	}

	defer resp.Body.Close()
	// Create the file
	out, err := os.Create(filepath+".tar.gz")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer os.Remove(filepath+".tar.gz")
	defer out.Close()
	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err!=nil{
		log.Fatal(err)
	}

	targz, err := os.Open(filepath+".tar.gz")
	if err!=nil{
		log.Fatal(err)
	}
	defer targz.Close()
	newFolderName := utils.ExtractTarGz(targz)
	//defer os.RemoveAll(newFolderName)
	folderType :=""
	if strings.Contains(newFolderName,"ASN"){
		folderType = "ASN"
	}else{
		folderType = "Country"
	}
	newFilepath := newFolderName + "GeoLite2-" + folderType + ".mmdb"

	err = utils.MoveFile(newFilepath, filepath)

	//err = os.Rename(newFilepath, newLocation)
	if err != nil {
		log.Fatal(err)
	}


	return
}



//Checks if databases exists, if exists, check if they are updated, return (bool)databases_found and (bool)databases_updated
func checkDatabases(geoipPath string, geoipCountryDbName string, geoipAsnDbName string, geoipLicenseKey string) (bool, bool) {
	goAgain := true
	file := geoipPath +"/" +  geoipCountryDbName
	databasesFound := false
	databasesUpdated := false
	if(false) {
	checkdb:
		if fileInfo, err := os.Stat(file); err == nil {
			databasesFound = true
			if time.Now().After(fileInfo.ModTime().AddDate(0, 1, 0)) {
				fmt.Println("not updated geoip databases")
			} else {
				fmt.Println("geoipDBs ok!!")
				databasesUpdated = true
				if goAgain {
					goAgain = false
					file = geoipPath + "/" + geoipAsnDbName
					goto checkdb //now check asn db
				}
				return databasesFound, databasesUpdated
			}
		}
	}
	fmt.Println("Updating geoip databases")
	got := downloadGeoIp(geoipLicenseKey,geoipPath, geoipAsnDbName, geoipCountryDbName)
	if !got {
		fmt.Println("Attempting to Download failed!! :( ")
	} else {
		fmt.Println("Attempting to Download Succeded!!")
		databasesFound = true
		databasesUpdated = true
	}
	return databasesFound, databasesUpdated
}

// Finds and return the Country database
func getGeoIpCountryDB(file string) (*geoip2.Reader, error) {
	gi, err := geoip2.Open(file)
	if err != nil {
		fmt.Printf("Could not open GeoLite2 Country database: %s\n", err)
		return nil, err
	}
	fmt.Printf("GEOLITE2 country db opened\n")
	return gi, err
}

// Finds and return the ASN database
func getGeoIpAsnDB(file string) (*geoip2.Reader, error) {
	gi, err := geoip2.Open(file)
	if err != nil {
		fmt.Printf("Could not open GeoLite2 ASN database: %s\n", err)
		return nil, err
	}
	fmt.Printf("GEOLITE2 asn db opened\n")
	return gi, err
}

// Finds and returns the conuntry of the given ip
func GetIPCountry(ip string, giCountryDb *geoip2.Reader) (country string) {
	ipAddr := net.ParseIP(ip)
	var ctry, err = giCountryDb.Country(ipAddr)
	if err != nil {
		fmt.Printf("Could not get country: %s\n", err)
		return ""
	}
	country = ctry.Country.IsoCode
	return country
}

// Finds and returns the ASN of the given ip
func GetIPASN(ip string, giAsnDb *geoip2.Reader) (asn string) {
	ipAddr := net.ParseIP(ip)
	var asnum, _ = giAsnDb.ASN(ipAddr)
	asn = strconv.FormatUint(uint64(asnum.AutonomousSystemNumber), 10)
	return asn
}
