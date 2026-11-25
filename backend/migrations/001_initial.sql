CREATE TABLE IF NOT EXISTS roles (name text PRIMARY KEY);
INSERT INTO roles VALUES ('Admin'),('Analyst'),('Viewer') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS users (
 id text PRIMARY KEY, email text UNIQUE NOT NULL, password_hash text NOT NULL,
 role text NOT NULL REFERENCES roles(name), totp_secret text, totp_pending text,
 totp_last bigint NOT NULL DEFAULT -1, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS scan_jobs (
 id text PRIMARY KEY, owner_id text NOT NULL REFERENCES users(id), target text NOT NULL,
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','completed','failed')),
 progress text NOT NULL DEFAULT 'Queued', created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scan_jobs_owner ON scan_jobs(owner_id,created_at DESC);
CREATE INDEX IF NOT EXISTS scan_jobs_queue ON scan_jobs(status,created_at);
CREATE TABLE IF NOT EXISTS scan_reports (job_id text PRIMARY KEY REFERENCES scan_jobs(id) ON DELETE CASCADE, report jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS waf_audit_logs (id bigserial PRIMARY KEY, occurred_at timestamptz NOT NULL DEFAULT now(), rule text NOT NULL, method text NOT NULL);
