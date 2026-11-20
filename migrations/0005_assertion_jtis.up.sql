-- The one-time use record of client assertions. The key is the hex SHA-256 of
-- the client ID, a zero byte, and the jti. A row stays until expires_at.
CREATE TABLE client_assertion_jtis (
    key        text PRIMARY KEY,
    expires_at timestamptz NOT NULL
);

CREATE INDEX client_assertion_jtis_expires_at_idx ON client_assertion_jtis (expires_at);
