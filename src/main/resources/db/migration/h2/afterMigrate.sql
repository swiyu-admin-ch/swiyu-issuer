DROP TABLE credential_offer_status;
DROP TABLE status_list;
CREATE TABLE status_list
(
    id              uuid NOT NULL,
    type            text NOT NULL,
    config          jsonb,
    uri             text NOT NULL,
    status_zipped   text NOT NULL,
    last_used_index int  NOT NULL,
    max_length      int  NOT NULL,
    PRIMARY KEY (id),
    --
    -- We want the same constraint name as in postgres!
    --
    CONSTRAINT status_list_uri_key unique (uri)
);

CREATE TABLE credential_offer_status
(
    credential_offer_id uuid NOT NULL,
    status_list_id      uuid NOT NULL,
    index               int  NOT NULL,
    PRIMARY KEY (credential_offer_id, status_list_id),
    FOREIGN KEY (status_list_id) REFERENCES status_list (id),
    FOREIGN KEY (credential_offer_id) REFERENCES credential_offer (id)
);

ALTER TABLE status_list ALTER COLUMN last_used_index rename to next_free_index;

-- V1_0_1 (without data migration)
alter table credential_offer add column metadata_credential_supported_id_new jsonb;
alter table credential_offer drop column metadata_credential_supported_id;
alter table credential_offer rename column metadata_credential_supported_id_new TO metadata_credential_supported_id;
alter table credential_offer alter column offer_data set data type jsonb;

-- V1_0_6 (without data migration)
ALTER TABLE credential_offer ALTER COLUMN credential_valid_from timestamp;
ALTER TABLE credential_offer ALTER COLUMN credential_valid_until timestamp;
ALTER TABLE credential_offer ALTER COLUMN offer_expiration_timestamp TYPE bigint;

