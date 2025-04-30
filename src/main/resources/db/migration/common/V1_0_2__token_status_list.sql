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
    unique (uri)
);

CREATE TABLE credential_offer_status
(
    credential_offer_id uuid     NOT NULL,
    status_list_id      uuid     NOT NULL,
    index               SMALLINT NOT NULL,
    PRIMARY KEY (credential_offer_id, status_list_id),
    FOREIGN KEY (status_list_id) REFERENCES status_list (id),
    FOREIGN KEY (credential_offer_id) REFERENCES credential_offer (id)
);