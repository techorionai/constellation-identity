CREATE TABLE signing_keys (
    kid              text PRIMARY KEY,
    alg              text NOT NULL,
    public_jwk       jsonb NOT NULL,
    private_key_name text NOT NULL UNIQUE,
    state            text NOT NULL CHECK (state IN ('pending', 'active', 'retired')),
    created_at       timestamptz NOT NULL,
    activates_at     timestamptz NOT NULL,
    retired_at       timestamptz
);

CREATE INDEX signing_keys_state_idx ON signing_keys (state);
