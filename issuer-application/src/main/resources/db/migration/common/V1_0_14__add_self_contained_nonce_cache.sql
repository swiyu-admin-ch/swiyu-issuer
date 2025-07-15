CREATE TABLE nonce_cache (
    nonce uuid NOT NULL,
    timestamp TIMESTAMP NOT NULL
);

ALTER TABLE nonce_cache ADD CONSTRAINT nonce_cache_pkey PRIMARY KEY (nonce);