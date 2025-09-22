/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Document } from '../models/Document';
import type { PublicDocumentSummary } from '../models/PublicDocumentSummary';
import type { PublishResponse } from '../models/PublishResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class PublicDocumentsService {
    /**
     * @returns PublishResponse Published status
     * @throws ApiError
     */
    public static getPublishStatus({
        id,
    }: {
        /**
         * Document ID
         */
        id: string,
    }): CancelablePromise<PublishResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/public/documents/{id}',
            path: {
                'id': id,
            },
        });
    }
    /**
     * @returns PublishResponse Published
     * @throws ApiError
     */
    public static publishDocument({
        id,
    }: {
        /**
         * Document ID
         */
        id: string,
    }): CancelablePromise<PublishResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/public/documents/{id}',
            path: {
                'id': id,
            },
        });
    }
    /**
     * @returns void
     * @throws ApiError
     */
    public static unpublishDocument({
        id,
    }: {
        /**
         * Document ID
         */
        id: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/public/documents/{id}',
            path: {
                'id': id,
            },
        });
    }
    /**
     * @returns PublicDocumentSummary Public documents for user
     * @throws ApiError
     */
    public static listUserPublicDocuments({
        name,
    }: {
        /**
         * Owner name
         */
        name: string,
    }): CancelablePromise<Array<PublicDocumentSummary>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/public/users/{name}',
            path: {
                'name': name,
            },
        });
    }
    /**
     * @returns Document Document metadata
     * @throws ApiError
     */
    public static getPublicByOwnerAndId({
        name,
        id,
    }: {
        /**
         * Owner name
         */
        name: string,
        /**
         * Document ID
         */
        id: string,
    }): CancelablePromise<Document> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/public/users/{name}/{id}',
            path: {
                'name': name,
                'id': id,
            },
        });
    }
    /**
     * @returns any Document content
     * @throws ApiError
     */
    public static getPublicContentByOwnerAndId({
        name,
        id,
    }: {
        /**
         * Owner name
         */
        name: string,
        /**
         * Document ID
         */
        id: string,
    }): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/public/users/{name}/{id}/content',
            path: {
                'name': name,
                'id': id,
            },
        });
    }
}
