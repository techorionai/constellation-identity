-- A retired key needs a retired_at time, or the manager never deletes it.
UPDATE signing_keys SET retired_at = now() WHERE state = 'retired' AND retired_at IS NULL;

ALTER TABLE signing_keys
    ADD CONSTRAINT signing_keys_retired_at_check CHECK (state <> 'retired' OR retired_at IS NOT NULL);

-- One key signs at a time.
CREATE UNIQUE INDEX signing_keys_one_active_idx ON signing_keys (state) WHERE state = 'active';
