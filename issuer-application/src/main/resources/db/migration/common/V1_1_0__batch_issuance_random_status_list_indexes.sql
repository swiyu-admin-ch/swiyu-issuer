create
or replace view available_status_list_indexes as (
    with status_list_indexes as (
        select id, uri, generate_series(0, max_length-1) index from status_list),
    used_indexes as (
        select status_list_id, index from credential_offer_status
    ),
    free_indexes as (
       select i.index as free_index, i.uri as status_list_uri from status_list_indexes i where i.index NOT IN
            (select index from used_indexes u where u.status_list_id = i.id)
    )
   select status_list_uri as id, array_agg(free_index) as free_indexes, status_list_uri from free_indexes group by status_list_uri
);
COMMENT ON VIEW available_status_list_indexes IS 'Selection of still unused indexes in a status list. Allows randomly selecting a free index.';

-- Allow next_free_index to be null
alter table status_list alter column next_free_index drop NOT NULL;
-- Use index as part of the primary key
alter table credential_offer_status drop constraint credential_offer_status_pkey;
alter table credential_offer_status add constraint credential_offer_status_pkey primary key (credential_offer_id, status_list_id, index);
alter table credential_offer_status add constraint credential_offer_status_index_unique_index unique (status_list_id, index);
