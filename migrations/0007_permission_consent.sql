-- Permission outreach invites (site-owner Yes/No + terms)
-- Applied via: wrangler d1 migrations apply blt-netguardian

CREATE TABLE IF NOT EXISTS permission_invites (
  id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  host_key TEXT NOT NULL,
  domain_url TEXT NOT NULL,
  contact_email TEXT NOT NULL,
  contact_source TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending',
  terms_version TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  responded_at INTEGER,
  created_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_permission_invites_org_host
  ON permission_invites (org_id, host_key, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_permission_invites_token
  ON permission_invites (token);
