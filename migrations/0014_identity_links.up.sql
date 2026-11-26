-- Links between users and accounts at upstream identity providers. The subject
-- is the key of the upstream account (sub for Google, and tid:oid for
-- Microsoft). It is never shown. The email is the email claim at the last login.
CREATE TABLE identity_links (
    id           uuid PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider     text NOT NULL,
    subject      text NOT NULL,
    email        text,
    created_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    UNIQUE (provider, subject),
    UNIQUE (user_id, provider)
);

-- The amr of the session that made a personal API token. A removal of a login
-- method revokes the tokens that the method made. A token from before this
-- migration has an empty list, so no removal revokes it.
ALTER TABLE api_tokens ADD COLUMN amr text[] NOT NULL DEFAULT '{}';
