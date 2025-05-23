package dnsUtils

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ExchangeWithRetry sends a DNS query to a list of DNS servers with up to 3 retries.
//
// Parameters:
//   - m: The DNS message to be sent (query).
//   - c: The DNS client used to perform the exchange.
//   - server: A slice of server IP addresses (as strings) to send the query to.
//
// Returns:
//   - *dns.Msg: The DNS response message, if any.
//   - time.Duration: The round-trip time for the successful DNS exchange.
//   - error: Any error encountered during the request.
//
// Behavior:
//
//	The function attempts to send the DNS query up to 3 times, cycling through
//	the provided servers. If an error other than a timeout occurs, it stops retrying
//	immediately. If a response is received with at least one answer, it returns early.
func ExchangeWithRetry(m *dns.Msg, c *dns.Client, server []string) (*dns.Msg, time.Duration, error) {
	var records *dns.Msg
	var err error
	var rtt time.Duration
	for retry := 3; retry > 0; retry-- {
		records, rtt, err = c.Exchange(m, server[retry%len(server)]+":53")
		if err == nil {
			if len(records.Answer) > 0 {

				break
			}
		} else if strings.IndexAny(err.Error(), "timeout") < 0 { //si el error no es timeout
			break
		}
	}
	return records, rtt, err
}

// GetRecordSet performs a DNS query for a specific record type.
//
// Parameters:
//   - line: The domain name to query (e.g., "example.com.").
//   - t: The DNS record type (e.g., dns.TypeA, dns.TypeMX, etc.).
//   - server: A slice of DNS server IP addresses (as strings) to query.
//   - c: The DNS client used to perform the request.
//
// Returns:
//   - *dns.Msg: The DNS response message, if any.
//   - time.Duration: The round-trip time for the successful query.
//   - error: Any error encountered during the request.
//
// Behavior:
//
//	Constructs a DNS query message for the given domain and record type,
//	then calls ExchangeWithRetry to perform the query with retries.
func GetRecordSet(line string, t uint16, server []string, c *dns.Client) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(line, t)
	return ExchangeWithRetry(m, c, server)
}

// manageError prints an error message to standard output if debugging is enabled.
//
// Parameters:
//   - err: The error message to print.
//   - debug: A boolean flag indicating whether debug mode is active.
//
// Behavior:
//
//	If debug is true, the error message is printed using fmt.Println.
//	If debug is false, the function does nothing.
//
// Example usage:
//
//	manageError("DNS query failed", true)
func manageError(err string, debug bool) {
	if debug {
		fmt.Println(err)
	}
}

// CheckSOA verifies whether a SOA (Start of Authority) record exists for the given domain name.
//
// Parameters:
//   - line: The domain name to check (e.g., "example.com.").
//   - servers: A slice of DNS server IP addresses (as strings) to query.
//   - c: The DNS client used to perform the request.
//
// Returns:
//   - *dns.Msg: The DNS response message, potentially containing a SOA record.
//   - error: Any error encountered during the request.
//
// Behavior:
//
//	Sends a DNS query requesting a SOA record for the given domain by calling GetRecordSet.
//	Ignores the round-trip time result, returning only the response and any error.
func CheckSOA(line string, servers []string, c *dns.Client) (*dns.Msg, error) {
	var soaRecords *dns.Msg
	var err error
	soaRecords, _ /*rtt*/, err = GetRecordSet(line, dns.TypeSOA, servers, c)
	return soaRecords, err
}

// CheckAvailability checks if a domain name has an A record by querying a specific name server.
//
// Parameters:
//   - domain: The domain name to check (e.g., "example.com.").
//   - ns: A pointer to a dns.NS struct representing the name server to query.
//   - c: The DNS client used to perform the request.
//
// Returns:
//   - *dns.Msg: The DNS response message, potentially containing an A record.
//   - time.Duration: The round-trip time for the query.
//   - error: Any error encountered during the request.
//
// Behavior:
//
//	Sends a DNS query for an A record of the specified domain using the IP address
//	from the provided NS record. Uses GetRecordSet to perform the actual query with retries.
func CheckAvailability(domain string, ns *dns.NS, c *dns.Client) (*dns.Msg, time.Duration, error) {
	resp, rtt, err := GetRecordSet(domain, dns.TypeA, []string{ns.Ns}, c)

	return resp, rtt, err

}

// FindKey searches for the DNSKEY that matches the KeyTag of the given RRSIG.
//
// Parameters:
//   - dnskeys: A DNS message containing a set of DNSKEY records.
//   - rrsig: A pointer to the RRSIG record for which the corresponding signing key is needed.
//
// Returns:
//   - *dns.DNSKEY: The DNSKEY record that matches the RRSIG's KeyTag, or nil if not found.
//
// Behavior:
//
//	Iterates through the Answer section of the DNS message to find a DNSKEY
//	whose KeyTag matches the KeyTag specified in the RRSIG. Returns the matching
//	DNSKEY if found.
func FindKey(dnskeys *dns.Msg, rrsig *dns.RRSIG) *dns.DNSKEY {
	var key *dns.DNSKEY
	for _, dnskey := range dnskeys.Answer {
		if dnskey1, ok := dnskey.(*dns.DNSKEY); ok {
			if dnskey1.KeyTag() == rrsig.KeyTag {
				key = dnskey1
			}
		}
	}
	return key
}

// GetAAAARecords queries a domain for its AAAA (IPv6) records.
//
// Parameters:
//   - line: The domain name to query (e.g., "example.com.").
//   - servers: A slice of DNS server IP addresses (as strings) to query.
//   - c: The DNS client used to perform the request.
//
// Returns:
//   - []net.IP: A slice of IPv6 addresses (if any were found).
//   - error: Any error encountered during the query.
//
// Behavior:
//
//	Sends a DNS query for AAAA records of the specified domain using GetRecordSet.
//	If successful, it extracts and returns the IPv6 addresses from the response.
//
// Note:
//
//	This function only includes valid AAAA records in the result. If no records
//	are found or an error occurs, it returns nil or an empty slice.
//
// Example usage:
//
//	client := new(dns.Client)
//	ips, err := GetAAAARecords("example.com.", []string{"8.8.8.8"}, client)
func GetAAAARecords(line string, servers []string, c *dns.Client) ([]net.IP, error) {
	var aaaaRecords *dns.Msg
	var err error
	aaaaRecords, _, err = GetRecordSet(line, dns.TypeAAAA, servers, c)
	if err != nil {
		return nil, err
	}
	IPv6s := []net.IP{}
	for _, a := range aaaaRecords.Answer {
		if a1, err := a.(*dns.AAAA); err {
			IPv6s = append(IPv6s, a1.AAAA)
		}
	}
	return IPv6s, err
}

// GetARecords queries a domain for it's A (IPv4) records.
//
// Parameters:
//   - line: The domain name to query (e.g., "example.com.").
//   - servers: A slice of DNS server IP addresses (as strings) to query.
//   - c: The DNS client used to perform the request.
//
// Returns:
//   - []net.IP: A slice of IPv4 addresses (if any were found).
//   - error: Any error encountered during the query.
//
// Behavior:
//
//	Sends a DNS query for A records of the specified domain using GetRecordSet.
//	If the query succeeds, it parses the Answer section of the response and
//	extracts all IPv4 addresses from valid A records.
//
// Example usage:
//
//	client := new(dns.Client)
//	ips, err := GetARecords("example.com.", []string{"8.8.8.8"}, client)
func GetARecords(line string, servers []string, c *dns.Client) ([]net.IP, error) {
	var aRecords *dns.Msg
	var err error
	aRecords, _, err = GetRecordSet(line, dns.TypeA, servers, c)
	if err != nil {
		return nil, err
	}
	IPv4s := []net.IP{}
	for _, a := range aRecords.Answer {
		if a1, ok := a.(*dns.A); ok {
			IPv4s = append(IPv4s, a1.A)
		}
	}
	return IPv4s, nil
}

// GetRecordSetTCP performs a DNS query for a specific record type over TCP.
//
// Parameters:
//   - line: The domain name to query (e.g., "example.com.").
//   - t: The DNS record type (e.g., dns.TypeA, dns.TypeMX, etc.).
//   - server: The DNS server IP address (as a string) to query.
//   - c: The DNS client used to perform the request.
//
// Returns:
//   - *dns.Msg: The DNS response message, if any.
//   - time.Duration: The round-trip time for the query.
//   - error: Any error encountered during the request.
//
// Behavior:
//
//	Constructs a DNS query message for the given domain and record type,
//	sets the client to use TCP as the transport protocol, and performs the query
//	with retries using ExchangeWithRetry.
func GetRecordSetTCP(line string, t uint16, server string, c *dns.Client) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(line, t)
	c.Net = "tcp"
	return ExchangeWithRetry(m, c, []string{server})
}

// GetRecordSetWithDNSSEC performs a DNS query for a specific record type using DNSSEC and TCP.
//
// Parameters:
//   - line: The domain name to query (e.g., "example.com.").
//   - t: The DNS record type (e.g., dns.TypeA, dns.TypeMX, etc.).
//   - servers: A slice of DNS server IP addresses (as strings) to query.
//   - c: The DNS client used to perform the request (will be replaced internally).
//
// Returns:
//   - *dns.Msg: The DNS response message, if any.
//   - time.Duration: The round-trip time for the query.
//   - error: Any error encountered during the request.
//
// Behavior:
//
//	Creates a DNS query message for the given domain and record type, enables DNSSEC
//	by setting the EDNS0 DO bit, and uses TCP as the transport protocol. The function
//	instantiates a new DNS client with TCP, then performs the query with retries using ExchangeWithRetry.
func GetRecordSetWithDNSSEC(line string, t uint16, servers []string, c *dns.Client) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(line, t)
	m.SetEdns0(4096, true)
	c = new(dns.Client)
	c.Net = "tcp"
	return ExchangeWithRetry(m, c, servers)
}

// GetRecursivityAndEDNS performs a DNS query for a SOA record with EDNS enabled.
//
// Parameters:
//   - line: The domain name to query (e.g., "example.com.").
//   - server: The DNS server IP address (as a string) to query.
//   - port: The port to use for the DNS query (not used in this function).
//   - c: The DNS client used to perform the request.
//
// Returns:
//   - *dns.Msg: The DNS response message, if any.
//   - time.Duration: The round-trip time for the query.
//   - error: Any error encountered during the request.
//
// Behavior:
//
//	Creates a DNS query message for the given domain, enables EDNS with a buffer size of 4096,
//	and requests a SOA record. The query is sent to the specified server using ExchangeWithRetry.
func GetRecursivityAndEDNS(line string, server string, port string, c *dns.Client) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	m.SetQuestion(line, dns.TypeSOA)
	return ExchangeWithRetry(m, c, []string{server})
}

// ZoneTransfer performs a DNS zone transfer (AXFR) for a specific domain.
//
// Parameters:
//   - line: The domain name for which the zone transfer is requested (e.g., "example.com.").
//   - ns: The nameserver address to request the transfer from.
//
// Returns:
//   - chan *dns.Envelope: A channel delivering the transferred DNS records, if successful.
//   - error: Any error encountered during the transfer.
//
// Behavior:
//
//	Creates a DNS message configured for a zone transfer (AXFR) and sends it to the specified nameserver.
//	If the transfer is successful, closes the connection and returns the channel with the results and any error.
func ZoneTransfer(line string, ns string) (chan *dns.Envelope, error) {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.SetAxfr(line)
	t := new(dns.Transfer)
	zt, err := t.In(m, ns+":53")
	if err == nil {
		t.Close()
	}
	return zt, err
}

// Less compares two DNS names and returns their order in DNSSEC canonical form.
//
// Parameters:
//   - a: The first DNS name as a string.
//   - b: The second DNS name as a string.
//
// Returns:
//   - int: A negative value if a < b, 0 if a == b, or a positive value if a > b,
//     according to DNSSEC canonical ordering (RFC 4034 section 6.1).
//
// Behavior:
//
//	Iteratively compares each label of the DNS names from right to left (least significant label first).
//	For each label, it decodes any escaped octets, then compares the byte slices.
//	The function does not lowercase the names before comparison, as required by the canonical order.
//	Returns as soon as a difference is found, or 0 if the names are equal.
//
// Reference:
//   - RFC 4034 section 6.1 (DNSSEC canonical name order)
//   - https://bert-hubert.blogspot.co.uk/2015/10/how-to-do-fast-canonical-ordering-of.html
func Less(a, b string) int {
	i := 1
	aj := len(a)
	bj := len(b)
	for {
		ai, oka := dns.PrevLabel(a, i)
		bi, okb := dns.PrevLabel(b, i)
		if oka && okb {
			return 0
		}

		// sadly this []byte will allocate...
		// for a name, otherwise compare the strings.
		ab := []byte(a[ai:aj])
		bb := []byte(b[bi:bj])
		doDDD(ab)
		doDDD(bb)

		res := bytes.Compare(ab, bb)
		if res != 0 {
			return res
		}

		i++
		aj, bj = ai, bi
	}
}

// doDDD decodes escaped decimal byte sequences (e.g., "\123") in a DNS label.
//
// Parameters:
//   - b: A byte slice representing a DNS label, possibly containing escaped decimal sequences.
//
// Behavior:
//
//	Scans the byte slice for patterns of the form "\DDD" (where D is a digit).
//	When found, replaces the sequence with the corresponding byte value and shifts the remaining bytes left.
//	This is used to ensure canonical comparison of DNS labels in the Less function.
//
// Note:
//
//	This function modifies the input slice in place and reduces its effective length for each replacement.
func doDDD(b []byte) {
	lb := len(b)
	for i := 0; i < lb; i++ {
		if i+3 < lb && b[i] == '\\' && isDigit(b[i+1]) && isDigit(b[i+2]) && isDigit(b[i+3]) {
			b[i] = dddToByte(b[i:])
			for j := i + 1; j < lb-3; j++ {
				b[j] = b[j+3]
			}
			lb -= 3
		}
	}
}

// isDigit checks if a given byte represents an ASCII digit ('0' to '9').
//
// Parameters:
//   - b: The byte to check.
//
// Returns:
//   - bool: true if b is an ASCII digit, false otherwise.
//
// Behavior:
//
//	Returns true if the byte value is between '0' and '9' inclusive.
//	Used as a helper in the Less function for DNS label comparison.
func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// dddToByte converts a three-digit decimal escape sequence (e.g., "\123") in a DNS label to its byte value.
//
// Parameters:
//   - s: A byte slice where s[1], s[2], and s[3] are ASCII digits representing a decimal value.
//
// Returns:
//   - byte: The byte value corresponding to the decimal digits.
//
// Behavior:
//
//	Calculates the byte value by converting the three ASCII digits to their numeric value.
//	Used by doDDD to decode escaped decimal sequences in DNS labels.
func dddToByte(s []byte) byte { return (s[1]-'0')*100 + (s[2]-'0')*10 + (s[3] - '0') }
