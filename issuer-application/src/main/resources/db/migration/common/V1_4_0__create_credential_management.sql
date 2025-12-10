-- Migration V1_4_0
-- Create table credential_management and migrate token fields from credential_offer

BEGIN;

-- 1) Create new table
CREATE TABLE credential_management (
    id uuid NOT NULL,
    access_token uuid,
    refresh_token uuid,
    dpop_key jsonb,
    pre_authorized_code uuid,
    access_token_expiration_timestamp bigint,
    credential_management_status text,
    renewal_request_cnt int NOT NULL DEFAULT 0,
    renewal_response_cnt int NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_modified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
ALTER TABLE credential_management ADD CONSTRAINT credential_management_pkey PRIMARY KEY (id);

ALTER TABLE credential_offer ADD COLUMN credential_management_id uuid NOT NULL;

-- 2) Copy data from credential_offer into credential_management
-- Copy the status only when it is ISSUED, SUSPENDED or REVOKED as requested
-- INSERT INTO credential_management (
--     id,
--     access_token,
--     refresh_token,
--     dpop_key,
--     pre_authorized_code,
--     access_token_expiration_timestamp,
--     credential_status,
--     renewal_request_cnt,
--     renewal_response_cnt,
--     created_at,
--     updated_at
-- )
-- SELECT
--     id,
--     access_token,
--     refresh_token,
--     dpop_key,
--     pre_authorized_code,
--     token_expiration_timestamp,
--     CASE WHEN credential_status IN ('ISSUED', 'SUSPENDED', 'REVOKED') THEN credential_status ELSE NULL END,
--     0,
--     0,
--     created_at,
--     updated_at
-- FROM credential_offer;
--
-- -- 3) Add credential_management_id column to credential_offer and populate it
-- ALTER TABLE credential_offer ADD COLUMN credential_management_id uuid;
--
-- UPDATE credential_offer
-- SET credential_management_id = cm.id
-- FROM credential_management cm
-- WHERE credential_offer.id = cm.id;
--
-- -- 4) Make the new column NOT NULL and add foreign key constraint
-- ALTER TABLE credential_offer ALTER COLUMN credential_management_id SET NOT NULL;
-- ALTER TABLE credential_offer
--     ADD CONSTRAINT fk_credential_offer_credential_management FOREIGN KEY (credential_management_id)
--     REFERENCES credential_management (id);
--
-- -- 5) Drop columns that were migrated
-- ALTER TABLE credential_offer DROP COLUMN IF EXISTS access_token;
-- ALTER TABLE credential_offer DROP COLUMN IF EXISTS refresh_token;
-- ALTER TABLE credential_offer DROP COLUMN IF EXISTS dpop_key;
-- -- TODO check
-- -- ALTER TABLE credential_offer DROP COLUMN IF EXISTS pre_authorized_code;
-- ALTER TABLE credential_offer DROP COLUMN IF EXISTS token_expiration_timestamp;
--
-- COMMIT;