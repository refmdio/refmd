/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AddPatternsRequest } from '../models/AddPatternsRequest';
import type { CheckIgnoredRequest } from '../models/CheckIgnoredRequest';
import type { CreateGitConfigRequest } from '../models/CreateGitConfigRequest';
import type { GitChangesResponse } from '../models/GitChangesResponse';
import type { GitConfigResponse } from '../models/GitConfigResponse';
import type { GitDiffResult } from '../models/GitDiffResult';
import type { GitHistoryResponse } from '../models/GitHistoryResponse';
import type { GitStatus } from '../models/GitStatus';
import type { GitSyncRequest } from '../models/GitSyncRequest';
import type { GitSyncResponse } from '../models/GitSyncResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class GitService {
    /**
     * @returns GitChangesResponse
     * @throws ApiError
     */
    public static getChanges(): CancelablePromise<GitChangesResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/git/changes',
        });
    }
    /**
     * @returns any
     * @throws ApiError
     */
    public static getConfig(): CancelablePromise<GitConfigResponse | null> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/git/config',
        });
    }
    /**
     * @returns GitConfigResponse
     * @throws ApiError
     */
    public static createOrUpdateConfig({
        requestBody,
    }: {
        requestBody: CreateGitConfigRequest,
    }): CancelablePromise<GitConfigResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/git/config',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @returns void
     * @throws ApiError
     */
    public static deleteConfig(): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/git/config',
        });
    }
    /**
     * @returns any OK
     * @throws ApiError
     */
    public static deinitRepository(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/git/deinit',
        });
    }
    /**
     * @returns GitDiffResult
     * @throws ApiError
     */
    public static getCommitDiff({
        from,
        to,
    }: {
        /**
         * From
         */
        from: string,
        /**
         * To
         */
        to: string,
    }): CancelablePromise<Array<GitDiffResult>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/git/diff/commits/{from}/{to}',
            path: {
                'from': from,
                'to': to,
            },
        });
    }
    /**
     * @returns GitDiffResult
     * @throws ApiError
     */
    public static getWorkingDiff(): CancelablePromise<Array<GitDiffResult>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/git/diff/working',
        });
    }
    /**
     * @returns any OK
     * @throws ApiError
     */
    public static checkPathIgnored({
        requestBody,
    }: {
        requestBody: CheckIgnoredRequest,
    }): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/git/gitignore/check',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @returns any OK
     * @throws ApiError
     */
    public static getGitignorePatterns(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/git/gitignore/patterns',
        });
    }
    /**
     * @returns any OK
     * @throws ApiError
     */
    public static addGitignorePatterns({
        requestBody,
    }: {
        requestBody: AddPatternsRequest,
    }): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/git/gitignore/patterns',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @returns GitHistoryResponse
     * @throws ApiError
     */
    public static getHistory(): CancelablePromise<GitHistoryResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/git/history',
        });
    }
    /**
     * @returns any OK
     * @throws ApiError
     */
    public static ignoreDocument({
        id,
    }: {
        /**
         * Document ID
         */
        id: string,
    }): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/git/ignore/doc/{id}',
            path: {
                'id': id,
            },
        });
    }
    /**
     * @returns any OK
     * @throws ApiError
     */
    public static ignoreFolder({
        id,
    }: {
        /**
         * Folder ID
         */
        id: string,
    }): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/git/ignore/folder/{id}',
            path: {
                'id': id,
            },
        });
    }
    /**
     * @returns any OK
     * @throws ApiError
     */
    public static initRepository(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/git/init',
        });
    }
    /**
     * @returns GitStatus
     * @throws ApiError
     */
    public static getStatus(): CancelablePromise<GitStatus> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/git/status',
        });
    }
    /**
     * @returns GitSyncResponse
     * @throws ApiError
     */
    public static syncNow({
        requestBody,
    }: {
        requestBody: GitSyncRequest,
    }): CancelablePromise<GitSyncResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/git/sync',
            body: requestBody,
            mediaType: 'application/json',
            errors: {
                409: `Conflicts during rebase/pull`,
            },
        });
    }
}
