ALTER TABLE credential_offer
    ADD COLUMN holder_jwks TEXT ARRAY;

UPDATE credential_offer set holder_jwks = string_to_array(holder_jwk, '');

ALTER TABLE credential_offer DROP COLUMN holder_jwk;