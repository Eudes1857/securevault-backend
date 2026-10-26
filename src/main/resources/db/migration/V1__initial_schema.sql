-- =============================================================================
-- SecureVault — Migration V1 : Schéma initial
-- Sécurité : Row Level Security activé sur les tables sensibles
-- =============================================================================

-- Extension pour UUID v4
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- TABLE : users
-- =============================================================================
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT  gen_random_uuid(),
    email           VARCHAR(320) NOT NULL UNIQUE,       -- chiffré au niveau app
    email_hash      VARCHAR(64) NOT NULL UNIQUE,        -- SHA-256 pour recherche
    password_hash   VARCHAR(60) NOT NULL,               -- bcrypt $2a$12$...
    mfa_secret      VARCHAR(512),                       -- chiffré AES-GCM
    mfa_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    role            VARCHAR(20) NOT NULL DEFAULT 'USER' CHECK ( role IN ('USER', 'ADMIN', 'AUDITOR') ),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email_hash ON users(email_hash);

-- =============================================================================
-- TABLE : secrets
-- =============================================================================
CREATE TABLE secrets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(255)  NOT NULL,
    description     VARCHAR(1000),
    category        VARCHAR(20) NOT NULL DEFAULT 'PASSWORD' CHECK ( category IN ('PASSWORD', 'TOKEN', 'CERTIFICATE', 'NOTE', 'KEY') ),
    -- Données chiffrées AES-256-GCM
    encrypted_value TEXT NOT NULL,          -- ciphertext en base64
    iv              VARCHAR(32) NOT NULL,   -- nonce GCM en base64 (12 bytes)
    salt            VARCHAR(32) NOT NULL,   -- sel PBKDF2 en base64 (16 bytes)
    -- Métadonnées
    tags            TEXT[],
    expires_at      TIMESTAMPTZ,
    last_accessed   TIMESTAMPTZ,
    access_count    INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Contrainte : un user ne peut pas avoir deux secrets avec le même nom
    CONSTRAINT uq_secrets_owner_name UNIQUE (owner_id, name)
);

CREATE INDEX idx_secrets_owner ON secrets(owner_id);
CREATE INDEX idx_secrets_expires ON secrets(expires_at) WHERE expires_at IS NOT NULL;

-- =============================================================================
-- TABLE : audit_events
-- Table append-only — aucun UPDATE ou DELETE autorisé (trigger ci-dessous)
-- =============================================================================

CREATE TABLE  audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID,
    event_type      VARCHAR(50) NOT NULL,
    ip_address      INET NOT NULL,
    user_agent      VARCHAR(500),
    resource_type   VARCHAR(50),
    resource_id     UUID,
    details         JSONB,
    severity        VARCHAR(10) NOT NULL DEFAULT  'INFO' CHECK ( severity IN ('INFO', 'WARNING', 'CRITICAL') ),
    -- Hash de la ligne précédente pour détecter toute altération
    chain_hash      VARCHAR(64) NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL  DEFAULT NOW()
);

CREATE INDEX idx_audit_user             ON audit_events(user_id);
CREATE INDEX idx_audit_type             ON audit_events(event_type);
CREATE INDEX idx_audit_timestamp        ON audit_events(timestamp DESC);
CREATE INDEX idx_audit_severity         ON audit_events(severity) WHERE severity != 'INFO';

-- Trigger : interdire UPDATE et DELETE sur audit_events (immutabilité)
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Les événements d''audit sont immuables. Opération interdite.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_immutable_update
    BEFORE  UPDATE ON audit_events
    FOR EACH  ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TRIGGER audit_immutable_delete
    BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- =============================================================================
-- TABLE : refresh_tokens (backup PostgreSQL, source de vérité = Redis)
-- =============================================================================
CREATE TABLE refresh_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash          VARCHAR(64) NOT NULL UNIQUE,
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked             BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user    ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash    ON refresh_tokens(token_hash);

-- =============================================================================
-- Trigger : updated_at automatique
-- =============================================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- =============================================================================
-- Row Level Security (RLS)
-- Un utilisateur ne peut voir QUE ses propres secrets
-- =============================================================================
ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;

CREATE POLICY secrets_owner_policy ON secrets
       USING (owner_id = current_setting('app.current_user_id', TRUE)::UUID);

-- Les admins et auditeurs accèdent via le compte service (bypass RLS)
ALTER TABLE secrets FORCE ROW LEVEL SECURITY;