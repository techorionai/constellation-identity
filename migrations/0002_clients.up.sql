CREATE TABLE clients (
    id         text PRIMARY KEY,
    type       text NOT NULL CHECK (type IN ('service', 'public')),
    app        text NOT NULL,
    name       text NOT NULL,
    disabled   boolean NOT NULL DEFAULT false,
    source     text NOT NULL CHECK (source IN ('config', 'api')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE client_keys (
    client_id  text NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    kid        text NOT NULL,
    public_jwk jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (client_id, kid)
);
