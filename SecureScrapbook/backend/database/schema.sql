-- =====================================================================
-- SecureScrapbook Database Schema (PostgreSQL)
-- Architecture: Next.js Frontend + Express API on AWS EC2 + RDS PostgreSQL
-- Security: Application-Layer AES-256 Encryption & Zero Plaintext Storage
-- =====================================================================

-- Enable cryptographic UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =====================================================================
-- ENUMS & DOMAINS
-- =====================================================================

-- RBAC Roles supported by SecureScrapbook
DO $$ BEGIN
    CREATE TYPE user_role_type AS ENUM ('Owner', 'Editor', 'Viewer');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Audit Log Status types
DO $$ BEGIN
    CREATE TYPE audit_status_type AS ENUM ('SUCCESS', 'FAILURE', 'UNAUTHORIZED', 'FORBIDDEN');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- =====================================================================
-- TABLE: users
-- Core identity store. Sensitive credentials protected via bcrypt.
-- =====================================================================
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL, -- bcrypt (cost factor >= 12)
    full_name VARCHAR(100) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ NULL,
    last_login_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(LOWER(email));
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);

-- =====================================================================
-- TABLE: scrapbooks
-- Main container for personal memoirs and pages.
-- Title & description are stored strictly as AES-256-GCM ciphertexts
-- with corresponding Initialization Vector (IV) and Authentication Tag.
-- =====================================================================
CREATE TABLE IF NOT EXISTS scrapbooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- AES-256-GCM encrypted title and auth parameters (zero plaintext)
    title_encrypted TEXT NOT NULL,
    title_iv VARCHAR(64) NOT NULL,
    title_tag VARCHAR(64) NOT NULL,
    -- AES-256-GCM encrypted description and auth parameters
    description_encrypted TEXT,
    description_iv VARCHAR(64),
    description_tag VARCHAR(64),
    cover_image_key VARCHAR(512), -- Encrypted S3 object key or sanitized reference
    is_archived BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scrapbooks_owner_id ON scrapbooks(owner_id);
CREATE INDEX IF NOT EXISTS idx_scrapbooks_created_at ON scrapbooks(created_at DESC);

-- =====================================================================
-- TABLE: scrapbook_pages
-- Individual digital pages inside a scrapbook.
-- Memoirs, notes, and media metadata are AES-256-GCM encrypted.
-- =====================================================================
CREATE TABLE IF NOT EXISTS scrapbook_pages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scrapbook_id UUID NOT NULL REFERENCES scrapbooks(id) ON DELETE CASCADE,
    page_number INT NOT NULL,
    -- AES-256-GCM encrypted page title
    title_encrypted TEXT NOT NULL,
    title_iv VARCHAR(64) NOT NULL,
    title_tag VARCHAR(64) NOT NULL,
    -- AES-256-GCM encrypted personal memoir content
    content_encrypted TEXT NOT NULL,
    content_iv VARCHAR(64) NOT NULL,
    content_tag VARCHAR(64) NOT NULL,
    -- AES-256-GCM encrypted media metadata (captions, tags, layout JSON)
    media_metadata_encrypted TEXT,
    media_metadata_iv VARCHAR(64),
    media_metadata_tag VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Ensure ordered, unique page numbers per scrapbook
    CONSTRAINT uq_scrapbook_page_number UNIQUE (scrapbook_id, page_number)
);

CREATE INDEX IF NOT EXISTS idx_scrapbook_pages_scrapbook_id ON scrapbook_pages(scrapbook_id);
CREATE INDEX IF NOT EXISTS idx_scrapbook_pages_ordering ON scrapbook_pages(scrapbook_id, page_number ASC);

-- =====================================================================
-- TABLE: scrapbook_permissions
-- RBAC mapping layer. Assigns roles ('Owner', 'Editor', 'Viewer')
-- via user email address for granular application-level authorization.
-- =====================================================================
CREATE TABLE IF NOT EXISTS scrapbook_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scrapbook_id UUID NOT NULL REFERENCES scrapbooks(id) ON DELETE CASCADE,
    user_email VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL, -- Resolved if account exists
    role user_role_type NOT NULL DEFAULT 'Viewer',
    granted_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Prevent duplicate permission records for same scrapbook & email
    CONSTRAINT uq_scrapbook_user_email UNIQUE (scrapbook_id, user_email)
);

CREATE INDEX IF NOT EXISTS idx_permissions_email ON scrapbook_permissions(LOWER(user_email));
CREATE INDEX IF NOT EXISTS idx_permissions_scrapbook_id ON scrapbook_permissions(scrapbook_id);
CREATE INDEX IF NOT EXISTS idx_permissions_user_id ON scrapbook_permissions(user_id);

-- =====================================================================
-- TABLE: audit_logs
-- Immutable structured audit trail for compliance and CloudWatch streaming.
-- Captures authentication, CRUD operations, permission changes, and breaches.
-- =====================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    user_email VARCHAR(255),
    ip_address VARCHAR(45) NOT NULL, -- Supports IPv4 and IPv6
    user_agent TEXT,
    action VARCHAR(64) NOT NULL,     -- e.g., 'AUTH_LOGIN', 'SCRAPBOOK_DELETE', 'UNAUTHORIZED_ACCESS'
    resource_type VARCHAR(64) NOT NULL, -- e.g., 'SCRAPBOOK', 'PAGE', 'AUTH', 'PERMISSION'
    resource_id VARCHAR(128),        -- Target UUID or endpoint path
    status audit_status_type NOT NULL, -- SUCCESS, FAILURE, UNAUTHORIZED, FORBIDDEN
    http_method VARCHAR(10),
    request_uri VARCHAR(512),
    details JSONB DEFAULT '{}'::jsonb, -- Context metadata, sanitized diffs, reason codes
    risk_score INT NOT NULL DEFAULT 0  -- Anomaly weight (0=info, 50=warning, 90+=critical breach attempt)
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_email ON audit_logs(LOWER(user_email));
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_status ON audit_logs(status);
CREATE INDEX IF NOT EXISTS idx_audit_logs_risk_score ON audit_logs(risk_score) WHERE risk_score >= 50;

-- =====================================================================
-- AUTOMATIC TIMESTAMP TRIGGER
-- =====================================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();

DROP TRIGGER IF EXISTS trg_scrapbooks_updated_at ON scrapbooks;
CREATE TRIGGER trg_scrapbooks_updated_at BEFORE UPDATE ON scrapbooks FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();

DROP TRIGGER IF EXISTS trg_scrapbook_pages_updated_at ON scrapbook_pages;
CREATE TRIGGER trg_scrapbook_pages_updated_at BEFORE UPDATE ON scrapbook_pages FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();

DROP TRIGGER IF EXISTS trg_scrapbook_permissions_updated_at ON scrapbook_permissions;
CREATE TRIGGER trg_scrapbook_permissions_updated_at BEFORE UPDATE ON scrapbook_permissions FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
