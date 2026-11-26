-- The upstream auth_time of a login with an upstream identity provider stays
-- inside the service. The flag is true if the ID token of the login had a valid
-- auth_time (P23, P24). The flag is not in any token.
ALTER TABLE sessions ADD COLUMN upstream_auth_valid boolean NOT NULL DEFAULT false;
ALTER TABLE refresh_token_families ADD COLUMN upstream_auth_valid boolean NOT NULL DEFAULT false;

-- The access tokens that come from a login with a valid upstream auth_time. The
-- key is the jti of the access token. A row ends at the expiry of the token.
CREATE TABLE upstream_auth_tokens (
    jti        uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);

CREATE INDEX upstream_auth_tokens_expires_at ON upstream_auth_tokens (expires_at);
