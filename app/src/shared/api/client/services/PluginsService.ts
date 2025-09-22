/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CreateRecordBody } from '../models/CreateRecordBody';
import type { ExecBody } from '../models/ExecBody';
import type { ExecResultResponse } from '../models/ExecResultResponse';
import type { InstallFromUrlBody } from '../models/InstallFromUrlBody';
import type { InstallResponse } from '../models/InstallResponse';
import type { KvValueBody } from '../models/KvValueBody';
import type { KvValueResponse } from '../models/KvValueResponse';
import type { ManifestItem } from '../models/ManifestItem';
import type { RecordsResponse } from '../models/RecordsResponse';
import type { UninstallBody } from '../models/UninstallBody';
import type { UpdateRecordBody } from '../models/UpdateRecordBody';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class PluginsService {
    /**
     * @returns InstallResponse
     * @throws ApiError
     */
    public static pluginsInstallFromUrl({
        requestBody,
    }: {
        requestBody: InstallFromUrlBody,
    }): CancelablePromise<InstallResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/me/plugins/install-from-url',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @returns ManifestItem
     * @throws ApiError
     */
    public static pluginsGetManifest(): CancelablePromise<Array<ManifestItem>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/me/plugins/manifest',
        });
    }
    /**
     * @returns void
     * @throws ApiError
     */
    public static pluginsUninstall({
        requestBody,
    }: {
        requestBody: UninstallBody,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/me/plugins/uninstall',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @returns any Plugin event stream
     * @throws ApiError
     */
    public static sseUpdates(): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/me/plugins/updates',
        });
    }
    /**
     * @returns KvValueResponse
     * @throws ApiError
     */
    public static pluginsGetKv({
        plugin,
        docId,
        key,
        token,
    }: {
        /**
         * Plugin ID
         */
        plugin: string,
        /**
         * Document ID
         */
        docId: string,
        /**
         * Key
         */
        key: string,
        /**
         * Share token
         */
        token?: string | null,
    }): CancelablePromise<KvValueResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/plugins/{plugin}/docs/{doc_id}/kv/{key}',
            path: {
                'plugin': plugin,
                'doc_id': docId,
                'key': key,
            },
            query: {
                'token': token,
            },
        });
    }
    /**
     * @returns void
     * @throws ApiError
     */
    public static pluginsPutKv({
        plugin,
        docId,
        key,
        requestBody,
        token,
    }: {
        /**
         * Plugin ID
         */
        plugin: string,
        /**
         * Document ID
         */
        docId: string,
        /**
         * Key
         */
        key: string,
        requestBody: KvValueBody,
        /**
         * Share token
         */
        token?: string | null,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'PUT',
            url: '/api/plugins/{plugin}/docs/{doc_id}/kv/{key}',
            path: {
                'plugin': plugin,
                'doc_id': docId,
                'key': key,
            },
            query: {
                'token': token,
            },
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @returns RecordsResponse
     * @throws ApiError
     */
    public static listRecords({
        plugin,
        docId,
        kind,
        limit,
        offset,
        token,
    }: {
        /**
         * Plugin ID
         */
        plugin: string,
        /**
         * Document ID
         */
        docId: string,
        /**
         * Record kind
         */
        kind: string,
        /**
         * Limit
         */
        limit?: number | null,
        /**
         * Offset
         */
        offset?: number | null,
        /**
         * Share token
         */
        token?: string | null,
    }): CancelablePromise<RecordsResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/plugins/{plugin}/docs/{doc_id}/records/{kind}',
            path: {
                'plugin': plugin,
                'doc_id': docId,
                'kind': kind,
            },
            query: {
                'limit': limit,
                'offset': offset,
                'token': token,
            },
        });
    }
    /**
     * @returns any
     * @throws ApiError
     */
    public static pluginsCreateRecord({
        plugin,
        docId,
        kind,
        requestBody,
        token,
    }: {
        /**
         * Plugin ID
         */
        plugin: string,
        /**
         * Document ID
         */
        docId: string,
        /**
         * Record kind
         */
        kind: string,
        requestBody: CreateRecordBody,
        /**
         * Share token
         */
        token?: string | null,
    }): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/plugins/{plugin}/docs/{doc_id}/records/{kind}',
            path: {
                'plugin': plugin,
                'doc_id': docId,
                'kind': kind,
            },
            query: {
                'token': token,
            },
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @returns ExecResultResponse
     * @throws ApiError
     */
    public static pluginsExecAction({
        plugin,
        action,
        requestBody,
    }: {
        /**
         * Plugin ID
         */
        plugin: string,
        /**
         * Action
         */
        action: string,
        requestBody: ExecBody,
    }): CancelablePromise<ExecResultResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/plugins/{plugin}/exec/{action}',
            path: {
                'plugin': plugin,
                'action': action,
            },
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @returns void
     * @throws ApiError
     */
    public static pluginsDeleteRecord({
        plugin,
        id,
    }: {
        /**
         * Plugin ID
         */
        plugin: string,
        /**
         * Record ID
         */
        id: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/plugins/{plugin}/records/{id}',
            path: {
                'plugin': plugin,
                'id': id,
            },
        });
    }
    /**
     * @returns any
     * @throws ApiError
     */
    public static pluginsUpdateRecord({
        plugin,
        id,
        requestBody,
    }: {
        /**
         * Plugin ID
         */
        plugin: string,
        /**
         * Record ID
         */
        id: string,
        requestBody: UpdateRecordBody,
    }): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'PATCH',
            url: '/api/plugins/{plugin}/records/{id}',
            path: {
                'plugin': plugin,
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
        });
    }
}
