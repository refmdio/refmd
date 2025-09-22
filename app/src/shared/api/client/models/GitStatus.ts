/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type GitStatus = {
    current_branch?: string | null;
    has_remote: boolean;
    last_sync?: string | null;
    last_sync_commit_hash?: string | null;
    last_sync_message?: string | null;
    last_sync_status?: string | null;
    repository_initialized: boolean;
    sync_enabled: boolean;
    uncommitted_changes: number;
    untracked_files: number;
};

