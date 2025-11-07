-- Create new credential management table form existing data - performing partially the data migration
CREATE TABLE CREDENTIAL_MANAGEMENT as
SELECT id, access_token, token_expiration_timestamp as access_token_expiration_timestamp, refresh_token, dpop_key
FROM CREDENTIAL_OFFER;

ALTER TABLE CREDENTIAL_MANAGEMENT
    ADD CONSTRAINT credential_management_pkey PRIMARY KEY (id);
CREATE INDEX credential_management_access_token ON CREDENTIAL_MANAGEMENT (access_token);
CREATE INDEX credential_management_refresh_token ON CREDENTIAL_MANAGEMENT (refresh_token);


ALTER TABLE credential_offer
    ADD COLUMN credential_management_id uuid default null;

-- Set the foreign key reference. As we created the credential_management form a select and
-- reuse the IDs of the old credential_offer, it is enough to just set it to the id.
UPDATE credential_offer
SET credential_management_id = id;

ALTER TABLE credential_offer
    ADD CONSTRAINT credential_offer_credential_management_fk FOREIGN KEY (credential_management_id)
        REFERENCES CREDENTIAL_MANAGEMENT (id);