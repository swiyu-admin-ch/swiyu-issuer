ALTER TABLE credential_offer
    ADD COLUMN credential_request jsonb default null;

ALTER TABLE credential_offer
    ADD COLUMN transaction_id uuid default null;

ALTER TABLE credential_offer
    ADD COLUMN holder_jwk text default null;