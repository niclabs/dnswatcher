package LISTADO

/*
import (
	// "database/sql" -> Vincular la dirección a la db
	"time"
)

// Disponibilidad
func SaveAvailability(db DB, runID int, d DomainRow, ip string, ipVer int, proto string, ok bool, lat time.Duration) error {
	_, err := db.Exec(
		`INSERT INTO availability_observations(run_id, domain_id, ip, ip_version, photo, ok, latency_ms)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		runID, d.ID, ip, ipVer, photo, ok, int(lat/time.Millisecond),
	)
	return err
}

// Correctness
type CorrectnessRow struct {
	IP         string
	Version    string
	TotalPos   int
	SuccessPos int
	FailPos    int
	TotalNeg   int
	SuccessNeg int
	FailNeg    int
}

func SaveCorrectness(db DB, runID int, r CorrectnessRow) error {
	_, err := db.Exec(
		`INSERT INTO correctness_stats(run_id, ip, version, total_pos, success_pos, fail_pos, total_neg, success_neg, fail_neg)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		runID, r.IP, r.Version, r.TotalPos, r.SuccessPos, r.FailPos, r.TotalNeg, r.SuccessNeg, r.FailNeg,
	)
	return err
}

// DNSSEC
func SaveDNSSEC(db DB, runID int, d DomainRow, total, success, fail int, details []string) error {
	var id int
	if err := db.QueryRow(
		`INSERT INTO dnssec_stats(run_id, domain_id, total, success, fail)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		runID, d.ID, total, success, fail,
	).Scan(&id); err != nil {
		return err
	}
	for _, det := range details {
		if _, err := db.Exec(
			`INSERT INTO dnssec_fail_details(dnssec_stat_id, detail) VALUES ($1,$2)`, id, det,
		); err != nil {
			return err
		}
	}
	return nil
}

// Redundancia
func SaveRedundancia(db DB, runID int, d DomainRow, subnetCount int) error {
	_, err := db.Exec(
		`INSERT INTO redundancy_distribution(run_id, domain_id, subnet_count) VALUES ($1,$2,$3)`,
		runID, d.ID, subnetCount,
	)
	return err
}

// NSID
func SaveNSID(db DB, runID int, d DomainRow, server, nsid, errStr string, lat time.Duration) error {
	_, err := db.Exec(
		`INSERT INTO nsid_results(run_id, domain_id, server, nsid, error, latency_ms)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		runID, d.ID, server, nsid, errStr, int(lat/time.Millisecond),
	)
	return errs
}

// WebPresence
func SaveWebPresence(db DB, runID int, d DomainRow, hostKind, scheme, url, final string, status int, reachable bool, tlsCN, bodyHash, errStr string, lat time.Duration) error {
	_, err := db.Exec(
		`INSERT INTO web_presence(run_id, domain_id, host_kind, scheme, url, final_url, status_code, reachable, tls_cn, latency_ms, body_hash, error)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		runID, d.ID, hostKind, scheme, url, final, status, reachable, tlsCN, int(lat/time.Millisecond), bodyHash, errStr,
	)
	return err
}*/
