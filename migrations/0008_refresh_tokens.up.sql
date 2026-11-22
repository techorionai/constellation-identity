-- A family is the chain of refresh tokens of one authorization code flow. A
-- delete of the session deletes its families, so the purger of the sessions
-- never fails for a session that has families.
CREATE TABLE refresh_token_families (
    id          uuid PRIMARY KEY,
    session_id  uuid NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    client_id   text NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    scope       text NOT NULL,
    oidc_scopes text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL,
    revoked_at  timestamptz
);

CREATE INDEX refresh_token_families_session_id_idx ON refresh_token_families (session_id);
CREATE INDEX refresh_token_families_client_id_idx ON refresh_token_families (client_id);

-- token_hash is the hex SHA-256 of the token value. The value is never stored.
CREATE TABLE refresh_tokens (
    token_hash text PRIMARY KEY,
    family_id  uuid NOT NULL REFERENCES refresh_token_families (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    used_at    timestamptz,
    expires_at timestamptz NOT NULL
);

CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expires_at_idx ON refresh_tokens (expires_at);
