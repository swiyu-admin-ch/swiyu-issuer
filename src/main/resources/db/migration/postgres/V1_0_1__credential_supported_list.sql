-- Add new Column
alter table credential_offer add column metadata_credential_supported_id_new jsonb;
-- Migrate old data
with old_data as (select id, '["' || metadata_credential_supported_id || '"]' as prepared_data from credential_offer),
     converted_data as (select id, prepared_data::jsonb as prepared_data from old_data)
update credential_offer set metadata_credential_supported_id_new = converted_data.prepared_data from converted_data where converted_data.id = credential_offer.id ;
-- remove old column
alter table credential_offer drop column metadata_credential_supported_id;
-- rename new column to the old name
alter table credential_offer rename column metadata_credential_supported_id_new TO metadata_credential_supported_id;
-- use jsonb also for credential offer
alter table credential_offer alter column offer_data set data type jsonb;