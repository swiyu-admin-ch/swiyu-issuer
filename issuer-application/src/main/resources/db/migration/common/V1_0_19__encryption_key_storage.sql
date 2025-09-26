CREATE TABLE encryption_key (
    id uuid primary key,
    jwks jsonb,
    creation_timestamp timestamp
);