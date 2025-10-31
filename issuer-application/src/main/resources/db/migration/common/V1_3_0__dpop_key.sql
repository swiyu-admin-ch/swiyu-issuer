ALTER TABLE credential_offer
    ADD COLUMN dpop_key jsonb default null;

ALTER TABLE credential_offer
    ADD COLUMN refresh_token uuid default null;