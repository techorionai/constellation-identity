-- Passkeys (WebAuthn credentials) of a user. The table has the public key and
-- the data that the service needs to check an assertion. It has no private key.
CREATE TABLE webauthn_credentials (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   bytea NOT NULL UNIQUE,
    public_key      bytea NOT NULL,
    sign_count      bigint NOT NULL,
    aaguid          bytea NOT NULL,
    transports      text[] NOT NULL DEFAULT '{}',
    backup_eligible boolean NOT NULL,
    backup_state    boolean NOT NULL,
    name            text NOT NULL,
    created_at      timestamptz NOT NULL,
    last_used_at    timestamptz
);
CREATE INDEX webauthn_credentials_user_created ON webauthn_credentials(user_id, created_at, id);

-- The user handle of WebAuthn. It is 32 random bytes that the service makes at
-- the first registration. It is not the user ID and not the email.
ALTER TABLE users ADD COLUMN webauthn_user_handle bytea UNIQUE;
