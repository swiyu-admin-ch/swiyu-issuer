ALTER TABLE credential_offer
    ALTER COLUMN credential_valid_from TYPE timestamp USING credential_valid_from::timestamp,
    ALTER COLUMN credential_valid_until TYPE timestamp USING credential_valid_until::timestamp;

ALTER TABLE credential_offer_status ALTER COLUMN index TYPE int USING index::int;
ALTER TABLE credential_offer ALTER COLUMN offer_expiration_timestamp TYPE bigint;