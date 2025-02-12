ALTER TABLE credential_offer
    ADD COLUMN token_expiration_timestamp bigint;

ALTER TABLE credential_offer
    RENAME COLUMN holder_binding_nonce to nonce;
