CREATE TABLE IF NOT EXISTS release_traffic (
 id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
 release_id TEXT NOT NULL REFERENCES correction_releases(id), cohort TEXT NOT NULL,
 baseline_action TEXT NOT NULL, candidate_action TEXT NOT NULL,
 outcome TEXT NOT NULL, latency_ms INTEGER NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS correction_appeals (
 id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
 traffic_id TEXT NOT NULL UNIQUE REFERENCES release_traffic(id),
 expected_action TEXT NOT NULL, reason TEXT NOT NULL, actor TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS security_outbox (
 id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
 event_type TEXT NOT NULL, payload_json TEXT NOT NULL, status TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS prompt_versions (
 id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
 name TEXT NOT NULL, version INTEGER NOT NULL, template TEXT NOT NULL,
 sha256 TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(project_id, name, version)
);
CREATE TABLE IF NOT EXISTS provenance_events (
 id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
 session_id TEXT NOT NULL, guard_id TEXT NOT NULL UNIQUE,
 phase TEXT NOT NULL, source TEXT NOT NULL, tool_name TEXT,
 decision TEXT NOT NULL, risk_level TEXT NOT NULL,
 sequence_risk TEXT NOT NULL, content_sha256 TEXT NOT NULL,
 labels_json TEXT NOT NULL, parent_guard_ids_json TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS security_signals_session_idx ON security_signals(project_id, session_id, created_at);
CREATE INDEX IF NOT EXISTS provenance_session_idx ON provenance_events(project_id, session_id, created_at);
CREATE INDEX IF NOT EXISTS provenance_sequence_idx ON provenance_events(project_id, sequence_risk, created_at);
CREATE INDEX IF NOT EXISTS release_traffic_release_idx ON release_traffic(release_id, created_at);
CREATE INDEX IF NOT EXISTS security_incidents_project_idx ON security_incidents(project_id, created_at);
CREATE INDEX IF NOT EXISTS outbox_status_idx ON security_outbox(project_id, status);
