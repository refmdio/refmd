LOCK TABLE git_repository_state IN EXCLUSIVE MODE;

WITH ranked AS (
    SELECT
        ctid,
        ROW_NUMBER() OVER (
            PARTITION BY workspace_id
            ORDER BY updated_at DESC NULLS LAST,
                     initialized_at DESC NULLS LAST,
                     workspace_id
        ) AS rn
    FROM git_repository_state
)
DELETE FROM git_repository_state grs
USING ranked r
WHERE grs.ctid = r.ctid
  AND r.rn > 1;

ALTER TABLE git_repository_state
    DROP CONSTRAINT IF EXISTS git_repository_state_pkey;

ALTER TABLE git_repository_state
    ADD CONSTRAINT git_repository_state_pkey PRIMARY KEY (workspace_id);
