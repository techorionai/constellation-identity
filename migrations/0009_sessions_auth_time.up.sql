-- auth_time is the time of the last login of the session. The default now()
-- fills the column for an insert of the old version of the service. For a new
-- session it is equal to created_at.
ALTER TABLE sessions ADD COLUMN auth_time timestamptz NOT NULL DEFAULT now();

UPDATE sessions SET auth_time = created_at;
