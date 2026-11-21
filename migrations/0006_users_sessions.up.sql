CREATE TABLE users (
    id            uuid PRIMARY KEY,
    email         text NOT NULL UNIQUE CHECK (email = lower(email)),
    name          text NOT NULL,
    status        text NOT NULL CHECK (status IN ('invited', 'active', 'disabled')),
    password_hash text,
    created_at    timestamptz NOT NULL,
    updated_at    timestamptz NOT NULL
);

-- No foreign key to roles. A role that is not in the current manifest is
-- pending. A manifest publish never changes this table.
CREATE TABLE user_roles (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    app     text NOT NULL,
    role    text NOT NULL,
    source  text NOT NULL DEFAULT 'api' CHECK (source IN ('config', 'api')),
    PRIMARY KEY (user_id, app, role)
);

-- The key is the hex SHA-256 of the token value. The value is never stored.
CREATE TABLE one_time_tokens (
    token_hash text PRIMARY KEY,
    purpose    text NOT NULL CHECK (purpose IN ('setup', 'invite')),
    user_id    uuid REFERENCES users (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL,
    CHECK ((purpose = 'invite') = (user_id IS NOT NULL))
);

CREATE INDEX one_time_tokens_user_id_idx ON one_time_tokens (user_id);
CREATE INDEX one_time_tokens_expires_at_idx ON one_time_tokens (expires_at);

-- token_hash is the hex SHA-256 of the cookie value.
CREATE TABLE sessions (
    id              uuid PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash      text NOT NULL UNIQUE,
    created_at      timestamptz NOT NULL,
    last_seen_at    timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    user_agent      text NOT NULL DEFAULT '',
    ip_address      text NOT NULL DEFAULT ''
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
