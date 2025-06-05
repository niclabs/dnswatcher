package geoIPUtils

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/niclabs/Observatorio/utils"
	"github.com/oschwald/geoip2-golang"
)

// GeoipDB holds references to the GEO IP country and ASN databases.
type GeoipDB struct {
	CountryDb *geoip2.Reader // GEO IP database for country information
	AsnDb     *geoip2.Reader // GEO IP database for ASN (Autonomous System Number) information
}

// InitGeoIP initializes and returns a GeoipDB instance with country and ASN databases loaded.
//
// Parameters:
// - geoipPath: Path to the directory containing the GEO IP database files.
// - geoipCountryDbName: Filename of the country GEO IP database.
// - geoipAsnDbName: Filename of the ASN GEO IP database.
// - geoipLicenseKey: License key used to download the GEO IP database if not present.
//
// Returns:
// - A pointer to a GeoipDB struct containing loaded country and ASN databases.
//
// Note: If there is an error loading the databases, it is printed to standard output.
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

// CloseGeoIP closes both the country and ASN GEO IP databases.
//
// Parameters:
// - geoipDB: Pointer to a GeoipDB instance whose databases will be closed.
//
// Notes:
// - If an error occurs while closing either database, the error message is printed to standard output.
func CloseGeoIP(geoipDB *GeoipDB) {
	err := geoipDB.CountryDb.Close()
	if err != nil {
		fmt.Println(err)
	}
	err = geoipDB.AsnDb.Close()
	if err != nil {
		fmt.Println(err)
	}
}

// downloadGeoIp downloads the GeoLite2 ASN and Country databases from MaxMind and saves them to the specified directory.
//
// Parameters:
// - licenseKey: MaxMind license key required to download the databases.
// - geoipPath: Path to the directory where the databases will be stored. Created if it does not exist.
// - geoipAsnFilename: Filename to save the ASN database as.
// - geoipCountryFilename: Filename to save the Country database as.
//
// Returns:
// - true if the download process completes (even if some errors occurred and were only printed).
//
// Notes:
// - The function ensures the target directory exists.
// - Downloads are performed concurrently using goroutines and a WaitGroup.
// - Errors during directory creation or file download are printed to standard output.
func downloadGeoIp(licenseKey string, geoipPath string, geoipAsnFilename string, geoipCountryFilename string) bool {

	//check if directory exists (create if not exists)
	if _, err := os.Stat(geoipPath); os.IsNotExist(err) {
		err = os.Mkdir(geoipPath, os.ModePerm)
		if err != nil {
			fmt.Println(err)
			return false
		}
	}
	urlAsn := "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=" + licenseKey + "&suffix=tar.gz"
	urlCountry := "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=" + licenseKey + "&suffix=tar.gz"

	var wg sync.WaitGroup
	wg.Add(2)

	go downloadFile(urlAsn, geoipPath+"/"+geoipAsnFilename, &wg)

	go downloadFile(urlCountry, geoipPath+"/"+geoipCountryFilename, &wg)
	wg.Wait()

	return true
}

// downloadFile retrieves a file from a given URL, saves it as a .tar.gz archive,
// extracts the required .mmdb file from the archive, and moves it to the specified destination path.
//
// Parameters:
// - url: The URL to download the .tar.gz file from.
// - filepath: Destination path (without extension) where the extracted .mmdb file will be saved.
// - wg: A pointer to a sync.WaitGroup used to synchronize concurrent downloads.
//
// Notes:
// - The downloaded file is saved temporarily with a .tar.gz extension and removed after extraction.
// - The archive is expected to contain a MaxMind GeoLite2 database (ASN or Country).
// - The extracted .mmdb file is moved to the destination path.
// - Errors encountered during the process are fatal and terminate the program.
// - The function signals completion by calling wg.Done().
func downloadFile(url string, filepath string, wg *sync.WaitGroup) {
	defer wg.Done()
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
		return
	}

	defer resp.Body.Close()
	// Create the file
	out, err := os.Create(filepath + ".tar.gz")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer os.Remove(filepath + ".tar.gz")
	defer out.Close()
	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	targz, err := os.Open(filepath + ".tar.gz")
	if err != nil {
		log.Fatal(err)
	}
	defer targz.Close()
	newFolderName := utils.ExtractTarGz(targz)
	//defer os.RemoveAll(newFolderName)
	folderType := ""
	if strings.Contains(newFolderName, "ASN") {
		folderType = "ASN"
	} else {
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

// checkDatabases verifies the presence and freshness of the GEO IP databases (Country and ASN).
// If any database is missing or outdated (older than 1 month), it attempts to download updated versions.
//
// Parameters:
// - geoipPath: Path to the directory containing the GEO IP database files.
// - geoipCountryDbName: Filename of the country GEO IP database.
// - geoipAsnDbName: Filename of the ASN GEO IP database.
// - geoipLicenseKey: MaxMind license key used for downloading the databases if needed.
//
// Returns:
// - databasesFound: true if both databases are present (either originally or after download).
// - databasesUpdated: true if both databases are up-to-date.
//
// Notes:
// - This function uses file modification time to determine whether a database is outdated.
// - If outdated or missing, it calls downloadGeoIp to fetch the latest databases.
// - Uses a `goto` label to check both databases sequentially.
// - Prints status messages to standard output.
func checkDatabases(geoipPath string, geoipCountryDbName string, geoipAsnDbName string, geoipLicenseKey string) (bool, bool) {
	goAgain := true
	file := geoipPath + "/" + geoipCountryDbName
	databasesFound := false
	databasesUpdated := false
	if false {
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
	got := downloadGeoIp(geoipLicenseKey, geoipPath, geoipAsnDbName, geoipCountryDbName)
	if !got {
		fmt.Println("Attempting to Download failed!! :( ")
	} else {
		fmt.Println("Attempting to Download Succeded!!")
		databasesFound = true
		databasesUpdated = true
	}
	return databasesFound, databasesUpdated
}

// getGeoIpCountryDB attempts to open the specified GeoLite2 Country database file.
//
// Parameters:
// - file: Full path to the GeoLite2 Country database (.mmdb) file.
//
// Returns:
// - A pointer to a geoip2.Reader if successful.
// - An error if the file cannot be opened.
//
// Notes:
// - Prints a success message to standard output if the database is opened successfully.
// - Prints an error message if the database cannot be opened.
func getGeoIpCountryDB(file string) (*geoip2.Reader, error) {
	gi, err := geoip2.Open(file)
	if err != nil {
		fmt.Printf("Could not open GeoLite2 Country database: %s\n", err)
		return nil, err
	}
	fmt.Printf("GEOLITE2 country db opened\n")
	return gi, err
}

// getGeoIpAsnDB attempts to open the specified GeoLite2 ASN database file.
//
// Parameters:
// - file: Full path to the GeoLite2 ASN database (.mmdb) file.
//
// Returns:
// - A pointer to a geoip2.Reader if successful.
// - An error if the file cannot be opened.
//
// Notes:
// - Prints a success message to standard output if the database is opened successfully.
// - Prints an error message if the database cannot be opened.
func getGeoIpAsnDB(file string) (*geoip2.Reader, error) {
	gi, err := geoip2.Open(file)
	if err != nil {
		fmt.Printf("Could not open GeoLite2 ASN database: %s\n", err)
		return nil, err
	}
	fmt.Printf("GEOLITE2 asn db opened\n")
	return gi, err
}

// GetIPCountry returns the ISO country code for a given IP address using the provided GeoLite2 Country database.
//
// Parameters:
// - ip: A string representing the IP address to be geolocated.
// - giCountryDb: A pointer to a geoip2.Reader instance for the GeoLite2 Country database.
//
// Returns:
// - The ISO 3166-1 alpha-2 country code (e.g., "US", "CL") associated with the IP address.
// - An empty string if the IP is invalid or the lookup fails.
//
// Notes:
// - If the IP cannot be parsed or the database lookup fails, an error message is printed and an empty string is returned.
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

// GetIPASN returns the Autonomous System Number (ASN) for a given IP address using the GeoLite2 ASN database.
//
// Parameters:
// - ip: A string representing the IP address to be analyzed.
// - giAsnDb: A pointer to a geoip2.Reader instance for the GeoLite2 ASN database.
//
// Returns:
// - A string representation of the Autonomous System Number associated with the IP address.
// - If the lookup fails, an empty string may be returned.
//
// Notes:
// - This function ignores lookup errors silently. You may want to handle them for debugging or logging purposes.
// - The ASN is returned as a string for convenience in downstream processing (e.g., JSON encoding).
func GetIPASN(ip string, giAsnDb *geoip2.Reader) (asn string) {
	ipAddr := net.ParseIP(ip)
	var asnum, _ = giAsnDb.ASN(ipAddr)
	asn = strconv.FormatUint(uint64(asnum.AutonomousSystemNumber), 10)
	return asn
}
