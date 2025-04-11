-- credential_offer
ALTER TABLE credential_offer ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE credential_offer ADD COLUMN created_by VARCHAR(255) DEFAULT 'system';
ALTER TABLE credential_offer ADD COLUMN last_modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE credential_offer ADD COLUMN last_modified_by VARCHAR(255) DEFAULT 'system';

-- credential_offer_status
ALTER TABLE credential_offer_status ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE credential_offer_status ADD COLUMN created_by VARCHAR(255) DEFAULT 'system';
ALTER TABLE credential_offer_status ADD COLUMN last_modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE credential_offer_status ADD COLUMN last_modified_by VARCHAR(255) DEFAULT 'system';

-- status_list
ALTER TABLE status_list ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE status_list ADD COLUMN created_by VARCHAR(255) DEFAULT 'system';
ALTER TABLE status_list ADD COLUMN last_modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE status_list ADD COLUMN last_modified_by VARCHAR(255) DEFAULT 'system';

-- token_set
ALTER TABLE token_set ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE token_set ADD COLUMN created_by VARCHAR(255) DEFAULT 'system';
ALTER TABLE token_set ADD COLUMN last_modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE token_set ADD COLUMN last_modified_by VARCHAR(255) DEFAULT 'system';