-- A table holding a secret number used for nonces; the same across all instances
CREATE TABLE nonce_secret (
    id uuid NOT NULL
);

ALTER TABLE nonce_secret ADD CONSTRAINT secrets_primary_key PRIMARY KEY (id);

-- Create the secret for this database
INSERT INTO nonce_secret SELECT gen_random_uuid();