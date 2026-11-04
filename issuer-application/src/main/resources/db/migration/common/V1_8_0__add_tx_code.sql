-- Add columns for transaction code and tracking how many retries were used to enter this code correctly
ALTER TABLE CREDENTIAL_OFFER ADD COLUMN tx_code TEXT DEFAULT NULL;
ALTER TABLE CREDENTIAL_OFFER ADD COLUMN tx_code_retries INTEGER DEFAULT 0;
ALTER TABLE CREDENTIAL_OFFER ADD COLUMN tx_code_description TEXT DEFAULT NULL;