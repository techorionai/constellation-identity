DROP TABLE upstream_auth_tokens;
ALTER TABLE refresh_token_families DROP COLUMN upstream_auth_valid;
ALTER TABLE sessions DROP COLUMN upstream_auth_valid;
