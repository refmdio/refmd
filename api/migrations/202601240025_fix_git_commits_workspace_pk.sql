LOCK TABLE git_commits IN EXCLUSIVE MODE;

ALTER TABLE git_commits
    DROP CONSTRAINT IF EXISTS git_commits_parent_commit_id_fkey;

ALTER TABLE git_commits
    DROP CONSTRAINT IF EXISTS git_commits_pkey;

ALTER TABLE git_commits
    ADD CONSTRAINT git_commits_pkey PRIMARY KEY (workspace_id, commit_id);

ALTER TABLE git_commits
    ADD CONSTRAINT git_commits_parent_commit_fk
        FOREIGN KEY (workspace_id, parent_commit_id)
        REFERENCES git_commits(workspace_id, commit_id);
