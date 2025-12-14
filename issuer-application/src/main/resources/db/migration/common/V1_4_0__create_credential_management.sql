BEGIN;

-- Create new table
CREATE TABLE credential_management (
    id uuid NOT NULL,
    access_token uuid,
    refresh_token uuid,
    dpop_key jsonb,
    access_token_expiration_timestamp bigint,
    credential_management_status text,
    renewal_request_cnt int NOT NULL DEFAULT 0,
    renewal_response_cnt int NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_modified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE credential_management ADD CONSTRAINT credential_management_pkey PRIMARY KEY (id);

ALTER TABLE credential_offer ADD COLUMN credential_management_id uuid NOT NULL;

-- Copy data from credential_offer into credential_management
INSERT INTO credential_management (
    id,
    access_token,
    refresh_token,
    dpop_key,
    access_token_expiration_timestamp,
    credential_management_status,
    renewal_request_cnt,
    renewal_response_cnt,
    created_at,
    last_modified_at
)
SELECT
    id,
    access_token,
    refresh_token,
    dpop_key,
    token_expiration_timestamp,
    CASE WHEN credential_status IN ('ISSUED', 'SUSPENDED', 'REVOKED') THEN credential_status ELSE NULL END,
    0,
    0,
    created_at,
    last_modified_at
FROM credential_offer;

-- Set credential mgmt id in offer table
UPDATE credential_offer
SET credential_management_id = cm.id
FROM credential_management cm
WHERE credential_offer.id = cm.id;

-- Update status in credential offers in offer table
UPDATE credential_offer
SET credential_status = 'ISSUED'
WHERE credential_status IN ('SUSPENDED', 'REVOKED') ;

-- Make the new column NOT NULL and add foreign key constraint
ALTER TABLE credential_offer ALTER COLUMN credential_management_id SET NOT NULL;
ALTER TABLE credential_offer
    ADD CONSTRAINT fk_credential_offer_credential_management FOREIGN KEY (credential_management_id)
    REFERENCES credential_management (id);

-- Drop columns that were migrated
ALTER TABLE credential_offer DROP COLUMN IF EXISTS access_token;
ALTER TABLE credential_offer DROP COLUMN IF EXISTS refresh_token;
ALTER TABLE credential_offer DROP COLUMN IF EXISTS dpop_key;

ALTER TABLE credential_offer DROP COLUMN IF EXISTS token_expiration_timestamp;

COMMIT;