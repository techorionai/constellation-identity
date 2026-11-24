-- Personal API tokens. The table stores the SHA-256 hash of the token and never
-- the token. The migration only adds a table, so the previous version of the
-- service runs on the new schema.
CREATE TABLE api_tokens (
    id            uuid PRIMARY KEY,
    token_hash    text NOT NULL UNIQUE,
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    scope         text NOT NULL,
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    last_used_at  timestamptz,
    revoked_at    timestamptz
);

CREATE INDEX api_tokens_user_created ON api_tokens (user_id, created_at DESC, id DESC);
CREATE INDEX api_tokens_expires ON api_tokens (expires_at);
