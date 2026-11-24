-- Agents and their role assignments. The migration only adds tables, so the
-- previous version of the service runs on the new schema.
CREATE TABLE agents (
    id          uuid PRIMARY KEY,
    name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    client_id   text NOT NULL REFERENCES clients (id),
    enabled     boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    CONSTRAINT agents_name_key UNIQUE (name)
);
CREATE INDEX agents_created ON agents (created_at DESC, id DESC);
CREATE INDEX agents_client ON agents (client_id);

-- No foreign key to roles. An assignment of a role that is not in the current
-- manifest is pending. A manifest publish never changes this table.
CREATE TABLE agent_roles (
    agent_id uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    app      text NOT NULL,
    role     text NOT NULL,
    source   text NOT NULL CHECK (source IN ('config', 'api')),
    PRIMARY KEY (agent_id, app, role)
);
