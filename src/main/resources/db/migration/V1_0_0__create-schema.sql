CREATE TABLE credential_offer (
                                  id uuid NOT NULL,
                                  credential_status text NOT NULL,
                                  metadata_credential_supported_id text NOT NULL,
                                  offer_data json,
                                  holder_binding_nonce uuid NOT NULL,
                                  access_token uuid, -- Generated when token is fetched
                                  offer_expiration_timestamp integer, -- if null, offer is infinite
                                  credential_valid_from text, -- if null, credential is valid from the time it's issued
                                  credential_valid_until text -- if null, credential does not expire on its own
);

ALTER TABLE credential_offer ADD CONSTRAINT credential_offer_pkey PRIMARY KEY (id);
