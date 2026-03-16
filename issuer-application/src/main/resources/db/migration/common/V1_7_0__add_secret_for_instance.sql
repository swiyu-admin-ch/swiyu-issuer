-- A table holding a secret number used for nonces; the same across all instances
CREATE TABLE issuer_secret (
    id uuid NOT NULL
);

ALTER TABLE issuer_secret ADD CONSTRAINT secrets_primary_key PRIMARY KEY (id);

-- Create the secret for this database
INSERT INTO issuer_secret SELECT gen_random_uuid();

COMMENT ON TABLE issuer_secret IS 'This table holder only a single value that serves as a unique secret for the issuer, used in hash processes.';