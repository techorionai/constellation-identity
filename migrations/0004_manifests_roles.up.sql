CREATE TABLE apps (
    key              text PRIMARY KEY,
    manifest_version integer NOT NULL,
    manifest_hash    text NOT NULL,
    published_at     timestamptz NOT NULL,
    published_by     text NOT NULL
);

CREATE TABLE permissions (
    key         text PRIMARY KEY,
    app         text NOT NULL REFERENCES apps (key) ON DELETE CASCADE,
    description text NOT NULL
);

CREATE TABLE roles (
    app         text NOT NULL REFERENCES apps (key) ON DELETE CASCADE,
    key         text NOT NULL,
    name        text NOT NULL,
    description text NOT NULL,
    PRIMARY KEY (app, key)
);

CREATE TABLE role_permissions (
    app        text NOT NULL,
    role       text NOT NULL,
    permission text NOT NULL REFERENCES permissions (key) ON DELETE CASCADE,
    PRIMARY KEY (app, role, permission),
    FOREIGN KEY (app, role) REFERENCES roles (app, key) ON DELETE CASCADE
);

-- No foreign key to roles. An assignment of a role that is not in the current
-- manifest is pending. A manifest publish never changes this table.
CREATE TABLE client_roles (
    client_id text NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    app       text NOT NULL,
    role      text NOT NULL,
    source    text NOT NULL CHECK (source IN ('config', 'api')),
    PRIMARY KEY (client_id, app, role)
);
