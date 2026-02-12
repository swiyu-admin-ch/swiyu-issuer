ALTER TABLE credential_management
    ADD COLUMN metadata_tenant_id uuid default null;

-- Populate metadata_tenant_id in credential_management from the earliest associated credential_offer tenant_id
WITH metadata_tenant_ids AS (
    SELECT
        m.id,
        o.metadata_tenant_id,
        ROW_NUMBER() OVER (PARTITION BY m.id ORDER BY o.created_at ASC) AS rn
    FROM credential_management as m
    LEFT JOIN credential_offer as o
        ON m.id = o.credential_management_id
)
UPDATE credential_management
SET metadata_tenant_id = sub.metadata_tenant_id
FROM (
    SELECT t.id, t.metadata_tenant_id
    FROM metadata_tenant_ids t
    WHERE t.rn = 1
) AS sub
WHERE credential_management.id = sub.id;