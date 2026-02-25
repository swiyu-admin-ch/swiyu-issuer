-- status_list
-- Remove legacy column `type` (was used in early schema versions)
ALTER TABLE status_list
    DROP COLUMN IF EXISTS type;
