package dbController

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// CreateTables creates all necessary tables in the database for the DNS analysis application.
// If the `drop` parameter is true, it will drop each table before creating it, allowing for a clean setup.
// The function creates the following tables:
//   - runs: Stores information about each run, including timestamp, correctness, and duration.
//   - domain: Stores domain information and DNSSEC-related status.
//   - nameserver: Stores nameserver details and their characteristics.
//   - nameserver_ip: Stores IP addresses, country, ASN, and probe status for each nameserver.
//   - domain_ip: Stores IP addresses associated with each domain.
//   - dnskey: Stores DNSKEY records for domains.
//   - rrsig: Stores RRSIG records for domains.
//   - nsec: Stores NSEC records for domains.
//   - nsec3: Stores NSEC3 records for domains.
//   - ds: Stores DS records for domains.
//   - availability_metrics: Stores availability metrics by transport and address.
//
// Panics if any table creation fails.
func CreateTables(db *sql.DB, drop bool) {
	DropTable("runs", db, drop)
	_, err := db.Exec("CREATE TABLE  IF NOT EXISTS runs ( id SERIAL PRIMARY KEY, tstmp timestamp, correct_run bool, duration int)")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}

	DropTable("domain", db, drop)
	_, err = db.Exec("CREATE TABLE  IF NOT EXISTS domain ( id SERIAL PRIMARY KEY, run_id integer REFERENCES runs(id),name varchar(253), soa bool, non_existence_status int, nsec bool, nsecok bool, nsec3 bool, nsec3ok bool, wildcard bool, dnssec_ok bool, ds_found bool, ds_ok bool, dnskey_found bool, dnskey_ok bool)")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}

	DropTable("nameserver", db, drop)
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS nameserver ( id SERIAL PRIMARY KEY, run_id integer REFERENCES runs(id), domain_id  integer REFERENCES domain(id), name varchar(253), response bool, edns bool, recursivity bool, tcp bool, zone_transfer bool, loc_query bool, authoritative bool)")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
	DropTable("nameserver_ip", db, drop)
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS nameserver_ip ( id SERIAL PRIMARY KEY, run_id integer REFERENCES runs(id), nameserver_id integer REFERENCES nameserver(id), ip inet, country varchar(30), asn varchar(10), dont_probe bool )")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
	DropTable("domain_ip", db, drop)
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS domain_ip ( id SERIAL PRIMARY KEY, run_id integer REFERENCES runs(id), domain_id integer REFERENCES domain(id), ip inet)")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
	DropTable("dnskey", db, drop)
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS dnskey ( id SERIAL PRIMARY KEY, run_id integer REFERENCES runs(id), domain_id integer REFERENCES domain(id), public_key varchar(4096), owner varchar(253), ttl integer, type integer, protocol integer, algorithm integer, keytag integer, DSok bool)")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
	DropTable("rrsig", db, drop)
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS rrsig (id SERIAL PRIMARY KEY, run_id integer REFERENCES runs(id), domain_id integer REFERENCES domain(id), owner varchar(253), type_covered varchar(5), algorithm integer, labels integer, ttl integer, signature_expiration varchar(50), signature_inception varchar(50), keytag integer, signers_name varchar(48), signature varchar(1024))")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
	DropTable("nsec", db, drop)
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS nsec ( id SERIAL PRIMARY KEY, run_id integer REFERENCES runs(id), domain_id integer REFERENCES domain(id), name varchar(253),  next_name varchar(253), ttl integer, rrsig_ok bool, cover bool, coverwc bool, iswc bool)")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
	DropTable("nsec3", db, drop)
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS nsec3 ( id SERIAL PRIMARY KEY, run_id integer REFERENCES runs(id), domain_id integer REFERENCES domain(id), hashed_name varchar(253),  next_hashed_name varchar(253), iterations integer, hash_algorithm integer, salt varchar(255), rrsig_ok bool, match bool, cover bool, coverwc bool, n3wc bool, key_found bool, verified bool, expired bool)")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
	DropTable("ds", db, drop)
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS ds ( id SERIAL PRIMARY KEY, run_id integer REFERENCES runs(id), domain_id integer REFERENCES domain(id), algorithm int, hashed_name varchar(253) , key_tag integer, digest_type integer, digest varchar(255), ds_ok bool)")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
	// Creamos tabla para almacenar metricas de disponibilidad por transporte y dirección
	DropTable("availability_metrics", db, drop)
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS availability_metrics ( id SERIAL PRIMARY KEY, run_id integer REFERENCES runs(id), address VARCHAR(10), transport VARCHAR(10), duration FLOAT, correct bool, success_count INTEGER, total_count INTEGER, availability FLOAT)")
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}

}

// DropTable drops the specified table from the database if the `drop` flag is true.
// It executes a `DROP TABLE IF EXISTS` statement with the `CASCADE` option to remove
// the table and any dependent objects. If an error occurs during the operation,
// it prints the current database connection stats and panics.
//
// Parameters:
//   - table: the name of the table to drop.
//   - db: the database connection.
//   - drop: if true, the table will be dropped; if false, the function does nothing.
func DropTable(table string, db *sql.DB, drop bool) {
	if drop {
		_, err := db.Exec("DROP TABLE IF EXISTS " + table + " CASCADE")
		if err != nil {
			fmt.Println("OpenConnections", db.Stats())
			panic(err)
		}
	}
}

// NewRun inserts a new record into the `runs` table with the current timestamp.
// It returns the ID of the newly created run. If the insertion fails, the function
// prints the current database connection stats and panics.
//
// Parameters:
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - int: the ID of the newly created run.
func NewRun(db *sql.DB) int {
	var runId int
	err := db.QueryRow("INSERT INTO runs(tstmp) VALUES($1) RETURNING id", time.Now()).Scan(&runId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
	return runId
}

// SaveCorrectRun updates the `duration` and `correct_run` fields for a given run in the `runs` table.
//
// Parameters:
//   - runId: the ID of the run to update.
//   - duration: the duration of the run in nanoseconds.
//   - correct: whether the run was correct (true) or not (false).
//   - db: pointer to the SQL database connection.
//
// Panics if the update fails, printing the current database connection stats and the run ID.
func SaveCorrectRun(runId int, duration int, correct bool, db *sql.DB) {
	_, err := db.Exec("UPDATE runs SET duration = $1, correct_run = $2 WHERE id = $3", duration/1000000000, correct, runId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " run_id", runId)
		panic(err)
	}
}

// SaveDomain inserts a new domain record into the `domain` table with the specified name and run ID.
// It returns the ID of the newly created domain. If the insertion fails, it prints the current
// database connection stats and the domain name, and panics. If the error is due to "too many open files",
// the function will retry the operation recursively.
//
// Parameters:
//   - line: the domain name to insert.
//   - runId: the ID of the associated run.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - int: the ID of the newly created domain.
func SaveDomain(line string, runId int, db *sql.DB) int {
	var domainid int
	err := db.QueryRow("INSERT INTO domain(name, run_id) VALUES($1,$2) RETURNING id", line, runId).Scan(&domainid)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), "domain name", line)
		if strings.Contains(err.Error(), "too many open files") {
			return SaveDomain(line, runId, db)
		}
		panic(err)
	}
	return domainid
}

// SaveNSIP inserts a new record into the `nameserver_ip` table with the provided information.
//
// Parameters:
//   - nameserverid: the ID of the associated nameserver.
//   - ip: the IP address to insert (as a string).
//   - country: the country code or name associated with the IP.
//   - asn: the Autonomous System Number for the IP.
//   - dontProbe: whether this IP should be excluded from probing.
//   - runId: the ID of the current run.
//   - db: pointer to the SQL database connection.
//
// Panics if the insertion fails, printing the current database connection stats and the nameserver ID.
func SaveNSIP(nameserverid int, ip string, country string, asn string, dontProbe bool, runId int, db *sql.DB) {
	_, err := db.Exec("INSERT INTO nameserver_ip(ip, nameserver_id,country, asn, dont_probe,run_id) VALUES($1::inet, $2,$3, $4, $5,$6)", ip, nameserverid, country, asn, dontProbe, runId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " nameserverid: ", nameserverid)
		panic(err)
	}
}

// SaveSoa updates the `soa` field for a given domain in the `domain` table.
//
// Parameters:
//   - soa: boolean value indicating whether the domain has an SOA record.
//   - domainid: the ID of the domain to update.
//   - db: pointer to the SQL database connection.
//
// Panics if the update fails, printing the current database connection stats and the domain ID.
func SaveSoa(soa bool, domainid int, db *sql.DB) {
	_, err := db.Exec("UPDATE domain SET soa = $1 WHERE id = $2", soa, domainid)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " DomainId: ", domainid)
		panic(err)
	}
}

// SaveDNSKEY inserts a DNSKEY record into the `dnskey` table for a given domain and run.
// It stores all relevant DNSKEY fields, including the public key, owner, TTL, type, protocol, algorithm, key tag, and DS validation status.
//
// Parameters:
//   - dnskey: pointer to a dns.DNSKEY struct containing the DNSKEY record data.
//   - dsok: boolean indicating if the DNSKEY matches a DS record (DS validation OK).
//   - domainId: the ID of the domain to which the DNSKEY belongs.
//   - runId: the ID of the current run.
//   - db: pointer to the SQL database connection.
//
// Panics if the insertion fails, printing the current database connection stats and the domain ID.
func SaveDNSKEY(dnskey *dns.DNSKEY, dsok bool, domainId int, runId int, db *sql.DB) {
	_, err := db.Exec("INSERT INTO dnskey(domain_id, public_key, owner, ttl, type, protocol, algorithm, keytag, DSok, run_id)VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)", domainId, dnskey.PublicKey, dnskey.Hdr.Name, dnskey.Hdr.Ttl, dnskey.Hdr.Rrtype, dnskey.Protocol, dnskey.Algorithm, dnskey.KeyTag(), dsok, runId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " DomainId: ", domainId)
		panic(err)
	}
}

// SaveAvailabilityResults inserts a new record into the `availability_metrics` table
// with the provided availability result for a specific run.
//
// Parameters:
//   - runId: the ID of the current run.
//   - availability_result: an AvailabilityResult struct containing the metrics to store.
//   - db: pointer to the SQL database connection.
//
// If the insertion fails, it prints an error message to the console.
func SaveAvailabilityResults(runId int, availability_result AvailabilityResult, db *sql.DB) {
	_, err := db.Exec("INSERT INTO availability_metrics (run_id, address, transport, duration, correct) VALUES ($1, $2, $3, $4, $5)", availability_result.RunID, availability_result.TypeAddress, availability_result.Transport, availability_result.Duration, availability_result.Correct)
	if err != nil {
		fmt.Println("Error al guardar el resultado de disponibilidad:", err)
	}
}

// AvailabilityResult represents the result of an availability check for a DNS server.
// It contains information about the run, the server, the transport protocol used,
// the type of address, the duration of the query, and whether the result was correct.
//
// Fields:
//   - RunID: Identifier of the run associated with this result.
//   - Server: The DNS server being checked.
//   - Transport: The transport protocol used ("UDP" or "TCP").
//   - TypeAddress: The IP address of the server.
//   - Duration: The duration of the query in seconds.
//   - Correct: Indicates if the result was correct (true) or not (false).
type AvailabilityResult struct {
	RunID       int
	Server      string
	Transport   string  // "UDP" o "TCP"
	TypeAddress string  // IP address
	Duration    float64 // Query duration
	Correct     bool
}

// DNSKEY represents a DNSKEY record in the DNSSEC system.
//
// Fields:
//   - PublicKey: The public key as a string.
//   - Owner: The owner name of the DNSKEY record.
//   - Ttl: The time-to-live value for the record.
//   - KeyType: The type of the key (algorithm-specific).
//   - Protocol: The protocol value (should be 3 for DNSSEC).
//   - Algorithm: The cryptographic algorithm used.
//   - KeyTag: The key tag (identifier) for the DNSKEY.
type DNSKEY struct {
	PublicKey string
	Owner     string
	Ttl       int
	KeyType   int
	Protocol  int
	Algorithm int
	KeyTag    int
}

// getDNSKEYs retrieves all DNSKEY records for a given domain and run from the database.
//
// Parameters:
//   - domainId: the ID of the domain whose DNSKEY records are to be fetched.
//   - runId: the ID of the run associated with the DNSKEY records.
//   - db: pointer to the SQL database connection.
//   - dnskeys: a slice of DNSKEY structs where the results will be stored.
//
// Returns:
//   - size: the number of DNSKEY records retrieved and stored in the dnskeys slice.
//
// Panics if the database query fails or if scanning a row fails.
func getDNSKEYs(domainId int, runId int, db *sql.DB, dnskeys []DNSKEY) (size int) {
	query := `SELECT public_key, owner, ttl, type, protocol, algorithm, keytag 
				from dnskey where run_id=$1 and domain_id=$2;`

	rows, err := db.Query(query, runId, domainId)

	if err != nil {
		panic(err)
	}
	defer rows.Close()
	i := 0
	publicKey := ""
	owner := ""
	ttl := -1
	keyType := -1
	protocol := -1
	algorithm := -1
	keyTag := -1

	for rows.Next() {
		if err := rows.Scan(&publicKey, &owner, &ttl, &keyType, &protocol, &algorithm, &keyTag); err != nil {
			log.Fatal(err)
		}
		dnskeys[i] = DNSKEY{PublicKey: publicKey, Owner: owner, Ttl: ttl, KeyType: keyType, Protocol: protocol, Algorithm: algorithm, KeyTag: keyTag}
		i++
	}
	return i

}

// SaveRRSIG inserts an RRSIG record into the `rrsig` table for a given domain and run.
//
// Parameters:
//   - rrsig: pointer to a dns.RRSIG struct containing the RRSIG record data.
//   - domainId: the ID of the domain to which the RRSIG belongs.
//   - runId: the ID of the current run.
//   - db: pointer to the SQL database connection.
//
// The function converts the inception and expiration times to string format and stores all relevant RRSIG fields.
// If the insertion fails, it prints the current database connection stats, the domain ID, and the RRSIG data, then panics.
func SaveRRSIG(rrsig *dns.RRSIG, domainId int, runId int, db *sql.DB) {

	var inception = dns.TimeToString(rrsig.Inception)
	var expiration = dns.TimeToString(rrsig.Expiration)
	_, err := db.Exec("INSERT INTO rrsig(domain_id, owner,  type_covered,  algorithm, labels, ttl, signature_expiration, signature_inception, keytag, signers_name, signature, run_id) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)", domainId, rrsig.Hdr.Name, rrsig.TypeCovered, rrsig.Algorithm, rrsig.Labels, rrsig.OrigTtl, expiration, inception, rrsig.KeyTag, rrsig.SignerName, rrsig.Signature, runId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " DomainId: ", domainId)
		fmt.Println(domainId, rrsig.Hdr.Name, rrsig.TypeCovered, rrsig.Algorithm, rrsig.Labels, rrsig.OrigTtl, expiration, inception, rrsig.KeyTag, rrsig.SignerName, rrsig.Signature)
		panic(err)
	}
}

// SaveDS inserts a DS (Delegation Signer) record into the `ds` table for a given domain and run.
//
// Parameters:
//   - domainid: the ID of the domain to which the DS record belongs.
//   - algorithm: the cryptographic algorithm used for the DS record.
//   - keyTag: the key tag associated with the DNSKEY referenced by the DS record.
//   - digestType: the digest type used in the DS record.
//   - digest: the digest value as a string.
//   - runId: the ID of the current run.
//   - db: pointer to the SQL database connection.
//
// Panics if the insertion fails, printing the current database connection stats and the domain ID.
func SaveDS(domainid int, algorithm int, keyTag int, digestType int, digest string, runId int, db *sql.DB) {
	_, err := db.Exec("INSERT INTO ds(domain_id, algorithm, key_tag, digest_type, digest, run_id)VALUES($1, $2, $3, $4, $5, $6)", domainid, algorithm, keyTag, digestType, digest, runId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " DomainId: ", domainid)
		panic(err)
	}
}

// SaveDomainIp inserts a new IP address associated with a domain into the `domain_ip` table.
//
// Parameters:
//   - ip: the IP address to associate with the domain (as a string).
//   - domainid: the ID of the domain to which the IP belongs.
//   - runId: the ID of the current run.
//   - db: pointer to the SQL database connection.
//
// Panics if the insertion fails, printing the current database connection stats and the domain ID.
func SaveDomainIp(ip string, domainid int, runId int, db *sql.DB) {
	_, err := db.Exec("INSERT INTO domain_ip(ip, domain_id, run_id) VALUES($1, $2, $3)", ip, domainid, runId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " DomainId: ", domainid)
		panic(err)
	}
}

// CreateNS inserts a new nameserver record into the `nameserver` table for a given domain and run.
// It stores the nameserver name, domain ID, response status, authoritative status, and run ID.
// The function returns the ID of the newly created nameserver.
//
// Parameters:
//   - ns: pointer to a dns.NS struct containing the nameserver data.
//   - domainId: the ID of the domain to which the nameserver belongs.
//   - runId: the ID of the current run.
//   - db: pointer to the SQL database connection.
//   - available: boolean indicating if the nameserver responded.
//   - authoritative: boolean indicating if the nameserver is authoritative.
//
// Returns:
//   - int: the ID of the newly created nameserver.
//
// Panics if the insertion fails, printing the current database connection stats and the domain ID.
func CreateNS(ns *dns.NS, domainId int, runId int, db *sql.DB, available bool, authoritative bool) int {
	var nameserverid int

	err := db.QueryRow("INSERT INTO nameserver(name, domain_id, response, authoritative, run_id) VALUES($1, $2, $3, $4, $5) RETURNING id", ns.Ns, domainId, available, authoritative, runId).Scan(&nameserverid)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " DomainId: ", domainId)
		panic(err)
	}
	return nameserverid
}

// SaveNS updates the characteristics of a nameserver in the `nameserver` table.
//
// Parameters:
//   - recursivity: indicates if the nameserver supports recursion.
//   - EDNS: indicates if the nameserver supports EDNS.
//   - TCP: indicates if the nameserver supports TCP queries.
//   - zoneTransfer: indicates if the nameserver allows zone transfers.
//   - locQuery: indicates if the nameserver supports LOC queries.
//   - nameserverid: the ID of the nameserver to update.
//   - db: pointer to the SQL database connection.
//
// Panics if the update fails, printing the current database connection stats and the nameserver ID.
func SaveNS(recursivity bool, EDNS bool, TCP bool, zoneTransfer bool, locQuery bool, nameserverid int, db *sql.DB) {
	_, err := db.Exec("UPDATE nameserver SET recursivity = $1, edns = $2, tcp = $3, zone_transfer = $4, loc_query = $5 WHERE id = $6", recursivity, EDNS, TCP, zoneTransfer, locQuery, nameserverid)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " nameserverid: ", nameserverid)
		panic(err)

	}
}

// SaveNsec inserts a new NSEC record into the `nsec` table for a given domain and run.
// It stores the domain ID, owner name, next owner name, TTL, and run ID.
// If the insertion fails, it prints the current database connection stats and the domain ID, then panics.
//
// Parameters:
//   - domainid: the ID of the domain to which the NSEC record belongs.
//   - name: the owner name of the NSEC record.
//   - nextName: the next owner name in the NSEC record.
//   - ttl: the time-to-live value for the record.
//   - runId: the ID of the current run.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - int: the ID of the newly created NSEC record.
func SaveNsec(domainid int, name string, nextName string, ttl int, runId int, db *sql.DB) int {
	var nsecid int
	err := db.QueryRow("INSERT INTO nsec(domain_id, name, next_name, ttl, run_id) VALUES($1, $2, $3, $4, $5)RETURNING id", domainid, name, nextName, ttl, runId).Scan(&nsecid)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " DomainId: ", domainid)
		panic(err)
	}
	return nsecid
}

// SaveNsec3 inserts a new NSEC3 record into the `nsec3` table for a given domain and run.
// It stores the domain ID, hashed owner name, next hashed owner name, iteration count,
// hash algorithm, salt, and run ID. The function returns the ID of the newly created NSEC3 record.
//
// Parameters:
//   - domainid: the ID of the domain to which the NSEC3 record belongs.
//   - hashedName: the hashed owner name of the NSEC3 record.
//   - nextHashedName: the next hashed owner name in the NSEC3 record.
//   - iterations: the number of hash iterations used.
//   - hashAlgorithm: the hash algorithm identifier.
//   - salt: the salt value used in hashing.
//   - runId: the ID of the current run.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - int: the ID of the newly created NSEC3 record.
//
// Panics if the insertion fails, printing the current database connection stats and the domain ID.
func SaveNsec3(domainid int, hashedName string, nextHashedName string, iterations int, hashAlgorithm int, salt string, runId int, db *sql.DB) int {
	var nsec3id int
	err := db.QueryRow("INSERT INTO nsec3(domain_id, hashed_name, next_hashed_name, iterations, hash_algorithm, salt, run_id) VALUES($1, $2, $3, $4, $5, $6, $7)RETURNING id", domainid, hashedName, nextHashedName, iterations, hashAlgorithm, salt, runId).Scan(&nsec3id)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " DomainId: ", domainid)
		panic(err)
	}
	return nsec3id
}

// UpdateNonExistence updates the non_existence_status field for a specific domain in the domain table.
//
// Parameters:
//   - domainid: the ID of the domain to update.
//   - nonExistenceStatus: the new status value to set.
//   - db: pointer to the SQL database connection.
//
// Panics if the update fails, printing the current database connection stats and the domain ID.
func UpdateNonExistence(domainid int, nonExistenceStatus int, db *sql.DB) {
	_, err := db.Exec("UPDATE domain SET non_existence_status = $1 WHERE id = $2", nonExistenceStatus, domainid)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " DomainId: ", domainid)
		panic(err)
	}
}

// UpdateDomainNSECInfo updates the NSEC-related fields for a specific domain in the `domain` table.
//
// Parameters:
//   - domainId: the ID of the domain to update.
//   - nsecok: boolean indicating if the NSEC validation was successful.
//   - nsec: boolean indicating if NSEC records are present.
//   - wildcard: boolean indicating if a wildcard is present.
//   - db: pointer to the SQL database connection.
//
// Panics if the update fails, printing the current database connection stats and the domain ID.
func UpdateDomainNSECInfo(domainId int, nsecok bool, nsec bool, wildcard bool, db *sql.DB) {
	_, err := db.Exec("UPDATE domain SET nsec = $1, nsecok=$2, wildcard=$3 WHERE id = $4", nsec, nsecok, wildcard, domainId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " DomainId: ", domainId)
		panic(err)
	}
}

// UpdateDomainNSEC3Info updates the NSEC3-related fields for a specific domain in the `domain` table.
//
// Parameters:
//   - domainId: the ID of the domain to update.
//   - nsec3ok: boolean indicating if the NSEC3 validation was successful.
//   - nsec3: boolean indicating if NSEC3 records are present.
//   - wildcard: boolean indicating if a wildcard is present.
//   - db: pointer to the SQL database connection.
//
// Panics if the update fails, printing the current database connection stats and the domain ID.
func UpdateDomainNSEC3Info(domainId int, nsec3ok bool, nsec3 bool, wildcard bool, db *sql.DB) {
	_, err := db.Exec("UPDATE domain SET nsec3 = $1, nsec3ok=$2, wildcard=$3 WHERE id = $4", nsec3, nsec3ok, wildcard, domainId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " DomainId: ", domainId)
		panic(err)
	}
}

// GetNonExistenceStatus retrieves the domain name and its non-existence status from the `domain` table.
//
// Parameters:
//   - domainId: the ID of the domain to query.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - string: the name of the domain.
//   - int: the non-existence status value.
//   - error: any error encountered during the query or scan operation.
func GetNonExistenceStatus(domainId int, db *sql.DB) (string, int, error) {
	var name string
	var nonExistenceStatus int
	err := db.QueryRow("SELECT name, non_existence_status FROM domain WHERE id=$1", domainId).Scan(&name, &nonExistenceStatus)
	return name, nonExistenceStatus, err
}

// GetDomains retrieves all domain IDs associated with a specific run from the database.
//
// Parameters:
//   - runId: the ID of the run whose domains are to be fetched.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - *sql.Rows: a result set containing the IDs of the domains for the given run.
//   - error: any error encountered during the query execution.
func GetDomains(runId int, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query("SELECT id FROM domain WHERE run_id=$1", runId)

	return rows, err
}

// UpdateNSEC updates the fields related to NSEC record validation in the `nsec` table.
//
// Parameters:
//   - rrsigOk: indicates if the RRSIG validation for the NSEC record was successful.
//   - cover: indicates if the NSEC record covers the queried name.
//   - coverwc: indicates if the NSEC record covers a wildcard name.
//   - iswc: indicates if the NSEC record itself is a wildcard.
//   - nsecId: the ID of the NSEC record to update.
//   - db: pointer to the SQL database connection.
//
// Panics if the update fails, printing the current database connection stats and the NSEC record ID.
func UpdateNSEC(rrsigOk bool, cover bool, coverwc bool, iswc bool, nsecId int, db *sql.DB) {
	_, err := db.Exec("UPDATE nsec SET rrsig_ok = $1, cover=$2, coverwc=$3, iswc=$4 WHERE id = $5", rrsigOk, cover, coverwc, iswc, nsecId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " nsecId: ", nsecId)
		panic(err)
	}
}

// GetNSEC3s retrieves the NSEC3 records for a given domain from the database.
//
// Parameters:
//   - domainId: the ID of the domain whose NSEC3 records are to be fetched.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - *sql.Rows: a result set containing the fields rrsig_ok, match, cover, coverwc, and n3wc for each NSEC3 record.
//   - error: any error encountered during the query execution.
func GetNSEC3s(domainId int, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query("SELECT rrsig_ok, match, cover, coverwc, n3wc FROM nsec3 where domain_id = $1", domainId)
	return rows, err
}

// UpdateNSEC3 updates the fields related to NSEC3 record validation in the `nsec3` table.
//
// Parameters:
//   - rrsigOk: indicates if the RRSIG validation for the NSEC3 record was successful.
//   - keyFound: indicates if the key referenced by the NSEC3 record was found.
//   - verified: indicates if the NSEC3 record was successfully verified.
//   - expired: indicates if the NSEC3 record is expired.
//   - match: indicates if the NSEC3 record matches the queried name.
//   - cover: indicates if the NSEC3 record covers the queried name.
//   - coverwc: indicates if the NSEC3 record covers a wildcard name.
//   - n3wc: indicates if the NSEC3 record itself is a wildcard.
//   - nsec3Id: the ID of the NSEC3 record to update.
//   - db: pointer to the SQL database connection.
//
// Panics if the update fails, printing the current database connection stats and the NSEC3 record ID.
func UpdateNSEC3(rrsigOk bool, keyFound bool, verified bool, expired bool, match bool, cover bool, coverwc bool, n3wc bool, nsec3Id int, db *sql.DB) {
	_, err := db.Exec("UPDATE nsec3 SET rrsig_ok = $1, match=$2, cover=$3, coverwc=$4, n3wc=$5, key_found=$6, verified=$7, expired=$8 WHERE id = $9", rrsigOk, match, cover, coverwc, n3wc, keyFound, verified, expired, nsec3Id)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " nsec3Id: ", nsec3Id)
		panic(err)
	}
}

// UpdateDomainDSInfo updates the DS-related fields for a specific domain in the `domain` table.
//
// Parameters:
//   - domainId: the ID of the domain to update.
//   - dsFound: boolean indicating whether a DS record was found for the domain.
//   - dsOk: boolean indicating whether the DS record is valid.
//   - db: pointer to the SQL database connection.
//
// Panics if the update fails, printing the current database connection stats and the domain ID.
func UpdateDomainDSInfo(domainId int, dsFound bool, dsOk bool, db *sql.DB) {
	_, err := db.Exec("UPDATE domain SET ds_found = $1, ds_ok=$2 WHERE id = $3", dsFound, dsOk, domainId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " domain_id: ", domainId)
		panic(err)
	}
}

// UpdateDomainDNSKEYInfo updates the DNSKEY-related fields for a specific domain in the `domain` table.
//
// Parameters:
//   - domainId: the ID of the domain to update.
//   - dnskeyFound: boolean indicating whether a DNSKEY record was found for the domain.
//   - dnskeyOk: boolean indicating whether the DNSKEY record is valid.
//   - db: pointer to the SQL database connection.
//
// Panics if the update fails, printing the current database connection stats and the domain ID.
func UpdateDomainDNSKEYInfo(domainId int, dnskeyFound bool, dnskeyOk bool, db *sql.DB) {
	_, err := db.Exec("UPDATE domain SET dnskey_found = $1, dnskey_ok=$2 WHERE id = $3", dnskeyFound, dnskeyOk, domainId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " domain_id: ", domainId)
		panic(err)
	}
}

// GetNSECsInfo retrieves information about NSEC records for a given domain from the database.
//
// Parameters:
//   - domainId: the ID of the domain whose NSEC records are to be fetched.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - *sql.Rows: a result set containing the fields rrsig_ok, cover, coverwc, and iswc for each NSEC record.
//   - error: any error encountered during the query execution.
func GetNSECsInfo(domainId int, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query("SELECT rrsig_ok, cover, coverwc, iswc FROM nsec where domain_id = $1", domainId)
	return rows, err
}

// GetDSInfo retrieves the DS-related status for a specific domain from the `domain` table.
//
// Parameters:
//   - domainId: the ID of the domain to query.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - dsFound: true if a DS record was found for the domain, false otherwise.
//   - dsOk: true if the DS record is valid, false otherwise.
//
// If the query fails, both dsFound and dsOk will be set to false.
func GetDSInfo(domainId int, db *sql.DB) (dsFound bool, dsOk bool) {
	err := db.QueryRow("SELECT ds_found, ds_ok FROM domain WHERE id=$1", domainId).Scan(&dsFound, &dsOk)
	if err != nil {
		dsFound = false
		dsOk = false
	}
	return
}

// GetDNSKEYInfo retrieves the DNSKEY-related status for a specific domain from the `domain` table.
//
// Parameters:
//   - domainId: the ID of the domain to query.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - dnskeyFound: true if a DNSKEY record was found for the domain, false otherwise.
//   - dnskeyOk: true if the DNSKEY record is valid, false otherwise.
//
// If the query fails, both dnskeyFound and dnskeyOk will be set to false.
func GetDNSKEYInfo(domainId int, db *sql.DB) (dnskeyFound bool, dnskeyOk bool) {
	err := db.QueryRow("SELECT dnskey_found, dnskey_ok FROM domain WHERE id=$1", domainId).Scan(&dnskeyFound, &dnskeyOk)
	if err != nil {
		dnskeyFound = false
		dnskeyOk = false
	}
	return
}

// UpdateDomainDNSSEC updates the dnssec_ok field for a specific domain in the `domain` table.
//
// Parameters:
//   - domainId: the ID of the domain to update.
//   - dnssecOk: boolean indicating whether DNSSEC validation was successful for the domain.
//   - db: pointer to the SQL database connection.
//
// Panics if the update fails, printing the current database connection stats and the domain ID.
func UpdateDomainDNSSEC(domainId int, dnssecOk bool, db *sql.DB) {
	//TODO fix add dnssec_ok to domain table in  database(using wildcard_ok for now)
	_, err := db.Exec("UPDATE domain SET dnssec_ok = $1 WHERE id = $2", dnssecOk, domainId)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats(), " domain_id: ", domainId)
		panic(err)
	}
}

// CountNSPerDomain returns the number of domains grouped by the count of nameservers per domain for a given run.
// It executes a SQL query that counts how many domains have each possible number of nameservers.
//
// Parameters:
//   - runId: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - *sql.Rows: result set with columns numNs (number of nameservers) and num (number of domains with that count).
//   - error: any error encountered during the query execution.
func CountNSPerDomain(runId int, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query("SELECT numNs, COUNT(domain_id) AS num FROM(SELECT domain_id, COUNT(nameserver.id) AS numNs FROM nameserver WHERE run_id=$1 GROUP BY domain_id) AS counts GROUP BY numNs ORDER BY numNs;", runId)
	return rows, err
}

// CountASNPerDomain returns the number of domains grouped by the count of unique ASNs (Autonomous System Numbers)
// associated with their nameservers for a given run. It executes a SQL query that counts how many domains have
// each possible number of distinct ASNs among their nameservers.
//
// Parameters:
//   - runId: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - *sql.Rows: result set with columns numDomains (number of domains) and asnCount (number of unique ASNs per domain).
//   - error: any error encountered during the query execution.
func CountASNPerDomain(runId int, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query("SELECT COUNT(domain_id) as numDomains, asnCount FROM("+
		"SELECT NNN.domain_id, NCA.asnCount FROM("+
		"(Select domain_id, Count(nameserver.id) as numNs FROM nameserver WHERE run_id=$1 GROUP BY domain_id order by domain_id)AS NNN "+
		"JOIN (SELECT nameserver.domain_id, COUNT(distinct nameserver_ip.asn) AS asnCount FROM ("+
		"(SELECT * FROM nameserver WHERE run_id=$1)as nameserver "+
		"INNER JOIN (SELECT * FROM nameserver_ip WHERE run_id=$1)as nameserver_ip "+
		"ON nameserver.id=nameserver_ip.nameserver_id) GROUP BY nameserver.domain_id ORDER BY nameserver.domain_id) AS NCA "+
		"ON NNN.domain_id=NCA.domain_id))AS CNNN GROUP BY asnCount ORDER BY asnCount;", runId)
	return rows, err
}

// CountCountryPerDomain returns the number of domains grouped by the count of unique countries
// associated with their nameservers for a given run. It executes a SQL query that counts how many
// domains have each possible number of distinct countries among their nameservers.
//
// Parameters:
//   - runId: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - *sql.Rows: result set with columns numDomains (number of domains) and countryCount (number of unique countries per domain).
//   - error: any error encountered during the query execution.
func CountCountryPerDomain(runId int, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query(
		"SELECT COUNT(domain_id) as numDomains, countryCount FROM("+
			"SELECT NNN.domain_id, NCA.countryCount FROM("+
			"(Select domain_id, Count(nameserver.id) as numNs FROM (SELECT * FROM nameserver WHERE run_id=$1) AS nameserver GROUP BY domain_id order by domain_id)AS NNN "+
			"JOIN (SELECT nameserver.domain_id, COUNT(distinct nameserver_ip.country) AS countryCount  FROM "+
			"((SELECT * FROM nameserver WHERE run_id=$1) AS nameserver "+
			"INNER JOIN (SELECT * FROM nameserver_ip WHERE run_id=$1) AS nameserver_ip "+
			"ON nameserver.id=nameserver_ip.nameserver_id) GROUP BY nameserver.domain_id ORDER BY nameserver.domain_id) "+
			"AS NCA	ON NNN.domain_id=NCA.domain_id)"+
			")"+
			"AS CNNN GROUP BY countryCount ORDER BY countryCount ;", runId)
	return rows, err
}

// CountNSCountryASNPerDomain returns the number of domains grouped by the count of nameservers,
// unique ASNs, and unique countries associated with their nameservers for a given run.
// It executes a SQL query that aggregates domains by the number of nameservers (numNs),
// the number of distinct ASNs (asnCount), and the number of distinct countries (countryCount).
//
// Parameters:
//   - runId: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - *sql.Rows: result set with columns numDomains (number of domains), numNs (number of nameservers),
//     asnCount (number of unique ASNs), and countryCount (number of unique countries per domain).
//   - error: any error encountered during the query execution.
func CountNSCountryASNPerDomain(runId int, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query("SELECT COUNT(domain_id) as numDomains, numNs, asnCount, countryCount FROM"+
		"(SELECT NNN.domain_id, NNN.numNS, NCA.asnCount, NCA.countryCount FROM("+
		"(Select domain_id, Count(nameserver.id) as numNs FROM (SELECT * FROM nameserver WHERE run_id=$1) AS nameserver GROUP BY domain_id order by domain_id) AS NNN "+
		"JOIN (SELECT nameserver.domain_id, COUNT(distinct nameserver_ip.country) AS countryCount, COUNT(distinct nameserver_ip.asn) AS asnCount FROM "+
		"((SELECT * FROM nameserver WHERE run_id=$1) AS nameserver INNER JOIN (SELECT * FROM nameserver_ip WHERE run_id=$1) AS nameserver_ip ON nameserver.id=nameserver_ip.nameserver_id) GROUP BY nameserver.domain_id ORDER BY nameserver.domain_id) AS NCA "+
		"ON NNN.domain_id=NCA.domain_id)"+
		")AS CNNN GROUP BY numNs, asnCount, countryCount ORDER BY numNs, asnCount, countryCount;", runId)
	return rows, err
}

// CountDistinctNSWithIPv4 returns the number of distinct nameservers that have at least one IPv4 address
// associated with them for a given run. It executes a SQL query that counts the unique nameserver IDs
// in the nameserver_ip table where the IP address is IPv4 (family(ip) = 4) and matches the specified run ID.
//
// Parameters:
//   - runId: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - *sql.Rows: result set containing the count of distinct nameservers with IPv4 addresses.
//   - error: any error encountered during the query execution.
func CountDistinctNSWithIPv4(runId int, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query("select count(distinct nameserver_id) from nameserver_ip where family(ip)=4 and run_id=$1;", runId)
	return rows, err
}

// CountDistinctNSWithIPv6 returns the number of distinct nameservers that have at least one IPv6 address
// associated with them for a given run. It executes a SQL query that counts the unique nameserver IDs
// in the nameserver_ip table where the IP address is IPv6 (family(ip) = 6) and matches the specified run ID.
//
// Parameters:
//   - runId: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - *sql.Rows: result set containing the count of distinct nameservers with IPv6 addresses.
//   - error: any error encountered during the query execution.
func CountDistinctNSWithIPv6(runId int, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query("select count(distinct nameserver_id) from nameserver_ip where family(ip)=6 and run_id=$1;", runId)
	return rows, err
}

// CountDomainsWithCountNSIp returns the number of domains grouped by the total count of nameserver IPs,
// IPv4 addresses, and IPv6 addresses for each domain in a given run.
//
// It executes a SQL query that aggregates, for each domain, the total number of IPs, IPv4, and IPv6 addresses
// associated with its nameservers, and then groups the domains by these counts.
//
// Parameters:
//   - runId: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - *sql.Rows: result set with columns numDomains (number of domains), ipsCount (total IPs),
//     ipsv4Count (total IPv4 addresses), and ipsv6Count (total IPv6 addresses) per group.
//   - error: any error encountered during the query execution.
func CountDomainsWithCountNSIp(runId int, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query(`
	SELECT COUNT(domain_id) AS numDomains, ipsCount, ipsv4Count, ipsv6Count FROM(
		SELECT domain_id, SUM(ipCount2) AS ipsCount, SUM(ipv4Count2) AS ipsv4Count ,SUM(ipv6Count2) AS ipsv6Count FROM(
			select domain_id, (CASE WHEN ipCount IS NULL THEN 0 ELSE ipCount END) AS ipCount2,
			(CASE WHEN ipv4Count IS NULL THEN 0 ELSE ipv4Count END) as ipv4Count2,
			(CASE WHEN ipv6Count IS NULL THEN 0 ELSE ipv6Count END) as ipv6Count2 from(
				(select id, domain_id from (select * from nameserver where run_id=$1) AS nameserver1) as nameserver LEFT JOIN
				(SELECT nameserver_id, COUNT(ip) AS ipCount, SUM(CASE family(ip) WHEN 4 THEN 1 ELSE 0 END) AS ipv4Count,
				SUM(CASE family(ip) WHEN 6 THEN 1 ELSE 0 END) AS ipv6Count FROM
					 (select * from nameserver_ip where run_id=$1) AS nameserver_ip GROUP BY(nameserver_id)
				)AS IPC
				ON nameserver.id=IPC.nameserver_id
			)AS CDN1
		)as CDN2 GROUP BY domain_id
	)AS CDN1
	GROUP BY ipsCount, ipsv4Count, ipsv6Count ORDER BY ipsCount, ipsv4Count, ipsv6Count;`, runId)

	//"SELECT COUNT(domain_id) AS numDomains, ipsCount, ipsv4Count, ipsv6Count FROM (SELECT domain_id, SUM(ipCount) AS ipsCount, SUM(ipv4Count) AS ipsv4Count , SUM(ipv6Count) AS ipsv6Count FROM(nameserver left JOIN (SELECT nameserver_id, COUNT(ip) AS ipCount, SUM(CASE family(ip) WHEN 4 THEN 1 ELSE 0 END) AS ipv4Count, SUM(CASE family(ip) WHEN 6 THEN 1 ELSE 0 END) AS ipv6Count FROM nameserver_ip GROUP BY(nameserver_id)) AS IPC ON nameserver.id=IPC.nameserver_id) GROUP BY domain_id)AS CDN GROUP BY ipsCount, ipsv4Count, ipsv6Count ORDER BY ipsCount, ipsv4Count, ipsv6Count;")
	return rows, err
	//Count Distinct domains that have distinct counts of ips of nameservers.
}

// CountDomainsWithCountNSIPExclusive returns the number of domains grouped by the exclusive presence of nameserver IP families (IPv4, IPv6, or both) for a given run.
// The function executes a SQL query that classifies each domain based on the types of IP addresses (IPv4, IPv6, or both) associated with its nameservers.
// The result set contains the total number of domains (`numDomains`) for each IP family category (`family`), where:
//   - family = 4: only IPv4 addresses are present
//   - family = 6: only IPv6 addresses are present
//   - family = 10: both IPv4 and IPv6 addresses are present
//   - family = 0: no IP addresses are present
//
// Parameters:
//   - runId: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - *sql.Rows: result set with columns numDomains and family.
//   - error: any error encountered during the query execution.
func CountDomainsWithCountNSIPExclusive(runId int, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query("select sum(numDomains) as numDomains,family from(SELECT numDomains, (CASE  WHEN ipsv4Count>0 THEN (CASE WHEN ipsv6Count>0 THEN 10 ELSE 4 END) ELSE  (CASE WHEN ipsv6Count>0 THEN 6 ELSE 0 END)  END) AS family FROM(SELECT COUNT(domain_id) AS numDomains, ipsCount, ipsv4Count, ipsv6Count FROM "+
		"(SELECT domain_id, SUM(ipCount) AS ipsCount, SUM(ipv4Count) AS ipsv4Count , SUM(ipv6Count) AS ipsv6Count FROM"+
		"((select * from nameserver where run_id=$1) as nameserver1 left "+
		"JOIN (SELECT nameserver_id, COUNT(ip) AS ipCount, SUM(CASE family(ip) WHEN 4 THEN 1 ELSE 0 END) AS ipv4Count, SUM(CASE family(ip) WHEN 6 THEN 1 ELSE 0 END) AS ipv6Count FROM (select * from nameserver_ip where run_id=$1) as nameserver_ip GROUP BY(nameserver_id)) AS IPC "+
		"ON nameserver1.id=IPC.nameserver_id) GROUP BY domain_id)AS CDN GROUP BY ipsCount, ipsv4Count, ipsv6Count ORDER BY ipsCount, ipsv4Count, ipsv6Count) AS familyCount)as groupFamily GROUP BY family;", runId)
	return rows, err
}

// CountAvailabilityResults returns the number of successful and timeout responses
// for each address and transport type in the `availability_metrics` table for a given run.
//
// Parameters:
//   - runId: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - *sql.Rows: result set with columns `address`, `transport`, `correct_count` (number of successful responses),
//     and `timeout_count` (number of timeouts) for each address and transport combination.
//   - error: any error encountered during the query execution.
func CountAvailabilityResults(runId int, db *sql.DB) (*sql.Rows, error) {
	rows, err := db.Query("SELECT address, transport, SUM(CASE WHEN correct THEN 1 ELSE 0 END) AS correct_count, SUM(CASE WHEN NOT correct THEN 1 ELSE 0 END) AS timeout_count FROM availability_metrics WHERE run_id = $1 GROUP BY address, transport ORDER BY address, transport", runId)
	return rows, err
}

// GetRunTimestamp retrieves the timestamp of a specific run from the `runs` table.
//
// Parameters:
//   - runId: the ID of the run whose timestamp is to be fetched.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - string: the timestamp of the run as a string.
//
// Panics if the query fails, printing the current database connection stats.
func GetRunTimestamp(runId int, db *sql.DB) string {
	var ts string
	err := db.QueryRow("SELECT tstmp FROM runs WHERE id=$1", runId).Scan(&ts)
	if err != nil {
		fmt.Println("OpenConnections", db.Stats())
		panic(err)
	}
	return ts
}

// CountDomainsWithDNSSEC returns the number of domains with different DNSSEC statuses for a given run.
// It classifies domains into three categories:
//   - dnssecWrong: domains with DNSSEC enabled but validation failed (dnskey_found=true and dnssec_ok=false)
//   - dnssecOk: domains with DNSSEC enabled and validation succeeded (dnssec_ok=true)
//   - noDnssec: domains without DNSSEC (dnskey_found=false or dnskey_found is null)
//
// Parameters:
//   - runId: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - dnssecWrong: number of domains with DNSSEC errors.
//   - dnssecOk: number of domains with correct DNSSEC validation.
//   - noDnssec: number of domains without DNSSEC.
//
// If the query fails, all return values will be 0.
func CountDomainsWithDNSSEC(runId int, db *sql.DB) (dnssecWrong int, dnssecOk int, noDnssec int) {
	err := db.QueryRow(""+
		"select f.fid as dnssec_wrong, ok.cid as dnssec_ok, no.no_dnssec  from "+
		"(select count(id)as no_dnssec from domain where dnskey_found=false or dnskey_found is null and run_id=$1)as no,"+
		"(select count(id)as fid from domain where dnskey_found=true and dnssec_ok=false and run_id=$1)as f, "+
		"(select count(id)as cid from domain where dnssec_ok=true and run_id=$1)as ok;", runId).Scan(&dnssecWrong, &dnssecOk, &noDnssec)
	if err != nil {
		return 0, 0, 0
	}
	return
}

// CountDomainsWithDNSSECErrors returns the number of domains with specific DNSSEC validation errors for a given run.
//
// It classifies DNSSEC errors into three categories:
//   - denialProof: domains where denial-of-existence proof (NSEC/NSEC3) is missing or invalid.
//   - dnskeyValidation: domains where DNSKEY validation failed.
//   - dsValidation: domains where DS record validation failed.
//
// Parameters:
//   - runId: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - denialProof: number of domains with denial-of-existence proof errors.
//   - dnskeyValidation: number of domains with DNSKEY validation errors.
//   - dsValidation: number of domains with DS validation errors.
//
// If the query fails, all return values will be 0.
func CountDomainsWithDNSSECErrors(runId int, db *sql.DB) (denialProof int, dnskeyValidation int, dsValidation int) {
	query := `SELECT Denial.count as denial_proof, DNSKEY.count AS dnskey_validation, DS.count AS ds_validation from
		(select count(id) from domain where dnskey_found=true and run_id=$1 AND dnssec_ok=false AND (((nsec=false OR nsec IS NULL) AND (nsec3=false OR nsec3 IS NULL))OR((nsecok=false OR nsec IS NULL)AND (nsec3ok=false OR nsec3 IS NULL))))AS Denial,
		(select count(id) from domain where dnskey_found=true and run_id=$1 AND dnssec_ok=false AND dnskey_ok=false) AS DNSKEY,
		(select count(id) from domain where dnskey_found=true and run_id=$1 AND dnssec_ok=false AND (ds_found=false OR ds_ok=false)) AS DS;`
	err := db.QueryRow(query, runId).Scan(&denialProof, &dnskeyValidation, &dsValidation)
	if err != nil {
		return 0, 0, 0
	}
	return
}

// CountNameserverCharacteristics returns the counts of various characteristics
// (recursivity, EDNS, TCP, zone transfer, and LOC query support) for nameservers
// that responded in a given run.
//
// Parameters:
//   - runId: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - recursivity: number of nameservers with recursivity enabled.
//   - noRecursivity: number of nameservers with recursivity disabled.
//   - edns: number of nameservers with EDNS enabled.
//   - noEdns: number of nameservers with EDNS disabled.
//   - tcp: number of nameservers with TCP support enabled.
//   - noTcp: number of nameservers with TCP support disabled.
//   - zoneTransfer: number of nameservers allowing zone transfers.
//   - noZoneTransfer: number of nameservers not allowing zone transfers.
//   - locQuery: number of nameservers supporting LOC queries.
//   - noLocQuery: number of nameservers not supporting LOC queries.
//
// If the query fails, all return values will be 0.
func CountNameserverCharacteristics(runId int, db *sql.DB) (recursivity int, noRecursivity int, edns int, noEdns int, tcp int, noTcp int, zoneTransfer int, noZoneTransfer int, locQuery int, noLocQuery int) {
	query := `SELECT
		    SUM(CASE WHEN edns = true then 1 ELSE 0 END) as edns, SUM(CASE WHEN edns = false then 1 ELSE 0 END)  as no_edns,
		    SUM(CASE WHEN recursivity = false then 1 ELSE 0 END) as no_recursivity, SUM(CASE WHEN recursivity = true then 1 ELSE 0 END)  as recursivity,
		    SUM(CASE WHEN tcp = false then 1 ELSE 0 END) as no_tcp, SUM(CASE WHEN tcp = true then 1 ELSE 0 END)  as tcp,
		    SUM(CASE WHEN zone_transfer = false then 1 ELSE 0 END) as no_zone_transfer, SUM(CASE WHEN zone_transfer = true then 1 ELSE 0 END)  as zone_transfer,
		    SUM(CASE WHEN loc_query = false then 1 ELSE 0 END) as no_loc_query, SUM(CASE WHEN loc_query = true then 1 ELSE 0 END)  as loc_query
		from (select * from nameserver where run_id=$1 and response=true) as NS;`
	err := db.QueryRow(query, runId).Scan(&edns, &noEdns, &noRecursivity, &recursivity, &noTcp, &tcp, &noZoneTransfer, &zoneTransfer, &noLocQuery, &locQuery)
	if err != nil {
		return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	}
	return
}

// getNSs retrieves the counts of various nameserver characteristics for a given run.
// It executes a SQL query that aggregates the number of nameservers supporting or not supporting
// features such as EDNS, recursivity, TCP, zone transfer, and LOC query, considering only those
// nameservers that responded in the specified run.
//
// Parameters:
//   - run_id: the ID of the run to analyze.
//   - db: pointer to the SQL database connection.
//
// Returns:
//   - (edns, noEdns, recursivity, noRecursivity, tcp, noTcp, zoneTransfer, noZoneTransfer, locQuery, noLocQuery):
//     counts for each characteristic (int).
//   - error: any error encountered during the query execution.
//
// Note: This function is currently commented out.
/*func getNSs(run_id int, db *sql.DB){
	query:= `SELECT
		    SUM(CASE WHEN edns = true then 1 ELSE 0 END) as edns, SUM(CASE WHEN edns = false then 1 ELSE 0 END)  as no_edns,
		    SUM(CASE WHEN recursivity = false then 1 ELSE 0 END) as no_recursivity, SUM(CASE WHEN recursivity = true then 1 ELSE 0 END)  as recursivity,
		    SUM(CASE WHEN tcp = false then 1 ELSE 0 END) as no_tcp, SUM(CASE WHEN tcp = true then 1 ELSE 0 END)  as tcp,
		    SUM(CASE WHEN zone_transfer = false then 1 ELSE 0 END) as no_zone_transfer, SUM(CASE WHEN zone_transfer = true then 1 ELSE 0 END)  as zone_transfer,
		    SUM(CASE WHEN loc_query = false then 1 ELSE 0 END) as no_loc_query, SUM(CASE WHEN loc_query = true then 1 ELSE 0 END)  as loc_query
		from (select * from nameserver where run_id=$1 and response=true) as NS;`
}*/
