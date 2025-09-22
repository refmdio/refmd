/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ActiveShareItem } from '../models/ActiveShareItem';
import type { ApplicableShareItem } from '../models/ApplicableShareItem';
import type { CreateShareRequest } from '../models/CreateShareRequest';
import type { CreateShareResponse } from '../models/CreateShareResponse';
import type { MaterializeResponse } from '../models/MaterializeResponse';
import type { ShareBrowseResponse } from '../models/ShareBrowseResponse';
import type { ShareDocumentResponse } from '../models/ShareDocumentResponse';
import type { ShareItem } from '../models/ShareItem';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class SharingService {
    /**
     * @returns CreateShareResponse Share link created
     * @throws ApiError
     */
    public static createShare({
        requestBody,
    }: {
        requestBody: CreateShareRequest,
    }): CancelablePromise<CreateShareResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/shares',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @returns ActiveShareItem Active shares
     * @throws ApiError
     */
    public static listActiveShares(): CancelablePromise<Array<ActiveShareItem>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/shares/active',
        });
    }
    /**
     * @returns ApplicableShareItem Shares that include the document
     * @throws ApiError
     */
    public static listApplicableShares({
        docId,
    }: {
        /**
         * Document ID
         */
        docId: string,
    }): CancelablePromise<Array<ApplicableShareItem>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/shares/applicable',
            query: {
                'doc_id': docId,
            },
        });
    }
    /**
     * @returns ShareBrowseResponse Share tree
     * @throws ApiError
     */
    public static browseShare({
        token,
    }: {
        /**
         * Share token
         */
        token: string,
    }): CancelablePromise<ShareBrowseResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/shares/browse',
            query: {
                'token': token,
            },
        });
    }
    /**
     * @returns ShareItem OK
     * @throws ApiError
     */
    public static listDocumentShares({
        id,
    }: {
        /**
         * Document ID
         */
        id: string,
    }): CancelablePromise<Array<ShareItem>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/shares/documents/{id}',
            path: {
                'id': id,
            },
        });
    }
    /**
     * @returns MaterializeResponse Created doc shares
     * @throws ApiError
     */
    public static materializeFolderShare({
        token,
    }: {
        /**
         * Folder share token
         */
        token: string,
    }): CancelablePromise<MaterializeResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/shares/folders/{token}/materialize',
            path: {
                'token': token,
            },
        });
    }
    /**
     * @returns ShareDocumentResponse Document info
     * @throws ApiError
     */
    public static validateShareToken({
        token,
    }: {
        /**
         * Share token
         */
        token: string,
    }): CancelablePromise<ShareDocumentResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/shares/validate',
            query: {
                'token': token,
            },
        });
    }
    /**
     * @returns void
     * @throws ApiError
     */
    public static deleteShare({
        token,
    }: {
        /**
         * Share token
         */
        token: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/shares/{token}',
            path: {
                'token': token,
            },
        });
    }
}
