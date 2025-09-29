CREATE TABLE IF NOT EXISTS git_repository_state (
    user_id UUID PRIMARY KEY,
    initialized BOOLEAN NOT NULL DEFAULT false,
    default_branch TEXT NOT NULL DEFAULT 'main',
    initialized_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS git_commits (
    commit_id BYTEA PRIMARY KEY,
    parent_commit_id BYTEA NULL REFERENCES git_commits(commit_id),
    user_id UUID NOT NULL,
    message TEXT,
    author_name TEXT,
    author_email TEXT,
    committed_at TIMESTAMPTZ NOT NULL,
    pack_key TEXT NOT NULL,
    file_hash_index JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_git_commits_user ON git_commits(user_id, committed_at DESC);
