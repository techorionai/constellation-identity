ALTER TABLE refresh_token_families DROP COLUMN amr;
ALTER TABLE refresh_token_families DROP COLUMN auth_time;
ALTER TABLE sessions DROP COLUMN amr;
DROP TABLE recovery_codes;
DROP TABLE user_totp;
