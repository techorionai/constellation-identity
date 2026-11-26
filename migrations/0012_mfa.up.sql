-- TOTP secret of a user. The secret is an envelope of the platform-go secrets
-- package. It is never in clear text.
CREATE TABLE user_totp (
    user_id        uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret         bytea NOT NULL,
    key_id         text NOT NULL,
    last_used_step bigint NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL,
    last_used_at   timestamptz
);

-- Recovery codes. The table has the SHA-256 hash of the normalized code.
CREATE TABLE recovery_codes (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    used_at    timestamptz
);
CREATE INDEX recovery_codes_user_id ON recovery_codes(user_id);

-- The authentication methods of a session (amr). A row from before this
-- migration has the empty list.
ALTER TABLE sessions ADD COLUMN amr text[] NOT NULL DEFAULT '{}';

-- A refresh token family keeps the auth time and the methods of the code flow
-- that made it. A family from before this migration has NULL and the empty list.
ALTER TABLE refresh_token_families ADD COLUMN auth_time timestamptz;
ALTER TABLE refresh_token_families ADD COLUMN amr text[] NOT NULL DEFAULT '{}';
