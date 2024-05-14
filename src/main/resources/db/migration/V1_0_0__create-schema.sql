
CREATE TABLE credential_management (
    id uuid NOT NULL,
    credential_status text NOT NULL
);


CREATE TABLE credential_offer (
    id uuid NOT NULL,
    metadata_credential_supported_id text NOT NULL,
    offer_data json NOT NULL,
    pin text,
    management_id uuid NOT NULL,
    is_selective_disclosure boolean NOT NULL,
    access_token uuid,
    offer_expiration_timestamp integer,
    nonce uuid NOT NULL,
    credential_valid_from text,
    credential_valid_until text
);

CREATE TABLE credential_metadata (
    id uuid NOT NULL,
    credential_metadata json
);

ALTER TABLE ONLY credential_management
    ADD CONSTRAINT credential_management_pkey PRIMARY KEY (id);

ALTER TABLE ONLY credential_metadata
    ADD CONSTRAINT credential_metadata_pkey PRIMARY KEY (id);


ALTER TABLE ONLY credential_offer
    ADD CONSTRAINT credential_offer_pkey PRIMARY KEY (id);

ALTER TABLE ONLY credential_offer
    ADD CONSTRAINT credential_offer_management_id_fkey FOREIGN KEY (management_id) REFERENCES credential_management(id);
