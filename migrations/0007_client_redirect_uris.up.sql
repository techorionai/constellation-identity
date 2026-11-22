-- The redirect URIs of a public client. kind is login (redirect_uris) or
-- post_logout (post_logout_redirect_uris). The old version of the service
-- ignores this table.
CREATE TABLE client_redirect_uris (
    client_id text NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    uri       text NOT NULL,
    kind      text NOT NULL CHECK (kind IN ('login', 'post_logout')),
    PRIMARY KEY (client_id, kind, uri)
);
