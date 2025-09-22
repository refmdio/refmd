/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { BacklinksResponse } from '../models/BacklinksResponse';
import type { CreateDocumentRequest } from '../models/CreateDocumentRequest';
import type { Document } from '../models/Document';
import type { DocumentListResponse } from '../models/DocumentListResponse';
import type { OutgoingLinksResponse } from '../models/OutgoingLinksResponse';
import type { SearchResult } from '../models/SearchResult';
import type { UpdateDocumentRequest } from '../models/UpdateDocumentRequest';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class DocumentsService {
    /**
     * @returns DocumentListResponse
     * @throws ApiError
     */
    public static listDocuments({
        query,
        tag,
    }: {
        /**
         * Search query
         */
        query?: string | null,
        /**
         * Filter by tag
         */
        tag?: string | null,
    }): CancelablePromise<DocumentListResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/documents',
            query: {
                'query': query,
                'tag': tag,
            },
        });
    }
    /**
     * @returns Document
     * @throws ApiError
     */
    public static createDocument({
        requestBody,
    }: {
        requestBody: CreateDocumentRequest,
    }): CancelablePromise<Document> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/documents',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @returns SearchResult
     * @throws ApiError
     */
    public static searchDocuments({
        q,
    }: {
        /**
         * Query
         */
        q?: string | null,
    }): CancelablePromise<Array<SearchResult>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/documents/search',
            query: {
                'q': q,
            },
        });
    }
    /**
     * @returns Document
     * @throws ApiError
     */
    public static getDocument({
        id,
        token,
    }: {
        /**
         * Document ID
         */
        id: string,
        /**
         * Share token (optional)
         */
        token?: string | null,
    }): CancelablePromise<Document> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/documents/{id}',
            path: {
                'id': id,
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
    public static deleteDocument({
        id,
    }: {
        /**
         * Document ID
         */
        id: string,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'DELETE',
            url: '/api/documents/{id}',
            path: {
                'id': id,
            },
        });
    }
    /**
     * @returns Document
     * @throws ApiError
     */
    public static updateDocument({
        id,
        requestBody,
    }: {
        /**
         * Document ID
         */
        id: string,
        requestBody: UpdateDocumentRequest,
    }): CancelablePromise<Document> {
        return __request(OpenAPI, {
            method: 'PATCH',
            url: '/api/documents/{id}',
            path: {
                'id': id,
            },
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @returns BacklinksResponse
     * @throws ApiError
     */
    public static getBacklinks({
        id,
    }: {
        /**
         * Document ID
         */
        id: string,
    }): CancelablePromise<BacklinksResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/documents/{id}/backlinks',
            path: {
                'id': id,
            },
        });
    }
    /**
     * @returns any
     * @throws ApiError
     */
    public static getDocumentContent({
        id,
    }: {
        /**
         * Document ID
         */
        id: string,
    }): CancelablePromise<any> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/documents/{id}/content',
            path: {
                'id': id,
            },
        });
    }
    /**
     * @returns OutgoingLinksResponse
     * @throws ApiError
     */
    public static getOutgoingLinks({
        id,
    }: {
        /**
         * Document ID
         */
        id: string,
    }): CancelablePromise<OutgoingLinksResponse> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/documents/{id}/links',
            path: {
                'id': id,
            },
        });
    }
}
