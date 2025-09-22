/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { GitDiffLine } from './GitDiffLine';
export type GitDiffResult = {
    diff_lines: Array<GitDiffLine>;
    file_path: string;
    new_content?: string | null;
    old_content?: string | null;
};

