-- ESTO DSP PODEMOS AGREGARLO A createTable() del obs original

CREATE TABLE IF NOT EXISTS runs (
  id SERIAL PRIMARY KEY,
  started_at TIMESTAMP NOT NULL DEFAULT now(),
  note TEXT
);

-- Dominios a procesar 
CREATE TABLE IF NOT EXISTS domains (
  id SERIAL PRIMARY KEY,
  name VARCHAR(253) UNIQUE NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE
);

--  Disponibilidad (IPs, latencias, transporte)
CREATE TABLE IF NOT EXISTS availability_observations (
  id SERIAL PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  domain_id INTEGER NOT NULL REFERENCES domains(id),
  ip INET NOT NULL,
  ip_version SMALLINT NOT NULL, -- 4 o 6
  proto VARCHAR(3) NOT NULL,    -- 'UDP' o 'TCP'
  ok BOOLEAN NOT NULL,
  latency_ms INTEGER,           -- milisegundos
  observed_at TIMESTAMP NOT NULL DEFAULT now()
);

--  Correctness por IP de TLD
CREATE TABLE IF NOT EXISTS correctness_stats (
  id SERIAL PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  ip TEXT NOT NULL,
  version VARCHAR(3) NOT NULL,  -- "-v4" o "-v6"
  total_pos INTEGER NOT NULL,
  success_pos INTEGER NOT NULL,
  fail_pos INTEGER NOT NULL,
  total_neg INTEGER NOT NULL,
  success_neg INTEGER NOT NULL,
  fail_neg INTEGER NOT NULL
);

--  DNSSEC 
CREATE TABLE IF NOT EXISTS dnssec_stats (
  id SERIAL PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  domain_id INTEGER NOT NULL REFERENCES domains(id),
  total INTEGER NOT NULL,
  success INTEGER NOT NULL,
  fail INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS dnssec_fail_details (
  id SERIAL PRIMARY KEY,
  dnssec_stat_id INTEGER NOT NULL REFERENCES dnssec_stats(id) ON DELETE CASCADE,
  detail TEXT NOT NULL
);

--  Redundancia 
CREATE TABLE IF NOT EXISTS redundancy_distribution (
  id SERIAL PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  domain_id INTEGER NOT NULL REFERENCES domains(id),
  subnet_count INTEGER NOT NULL
);

--  NSID
CREATE TABLE IF NOT EXISTS nsid_results (
  id SERIAL PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  domain_id INTEGER NOT NULL REFERENCES domains(id),
  server TEXT NOT NULL,
  nsid TEXT,
  error TEXT,
  latency_ms INTEGER
);

--  WebPresence 
CREATE TABLE IF NOT EXISTS web_presence (
  id SERIAL PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES runs(id),
  domain_id INTEGER NOT NULL REFERENCES domains(id),
  host_kind VARCHAR(3) NOT NULL,    -- 'APX' o 'WWW'
  scheme VARCHAR(5) NOT NULL,       -- 'http'/'https'
  url TEXT NOT NULL,
  final_url TEXT,
  status_code INTEGER,
  reachable BOOLEAN NOT NULL,
  tls_cn TEXT,
  latency_ms INTEGER,
  body_hash TEXT,
  error TEXT
);
