PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('Admin', 'Officer', 'Laboratory', 'Custodian', 'Reviewer')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL UNIQUE,
    fir_number TEXT NOT NULL,
    crime_type TEXT NOT NULL,
    police_station TEXT NOT NULL,
    officer TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',
    created_by INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL REFERENCES cases(case_id),
    evidence_type TEXT NOT NULL,
    description TEXT,
    serial_no TEXT,
    seizure_location TEXT,
    seizure_at TEXT,
    seal_no TEXT,
    file_name TEXT,
    stored_path TEXT,
    sha256 TEXT,
    condition TEXT,
    location TEXT,
    notes TEXT,
    registered_by INTEGER NOT NULL REFERENCES users(id),
    registered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS custody_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    action TEXT NOT NULL,
    from_user TEXT,
    to_user TEXT,
    location TEXT,
    condition TEXT,
    notes TEXT,
    event_time TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    ip_address TEXT,
    logged_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_custody_evid ON custody_events(evidence_id);
