/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class OpenGraphService {
    /**
     * @returns string HTML page with OpenGraph metadata
     * @throws ApiError
     */
    public static publicDocumentOg({
        name,
        id,
    }: {
        /**
         * Public profile name
         */
        name: string,
        /**
         * Public document ID
         */
        id: string,
    }): CancelablePromise<string> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/og/public/users/{name}/{id}',
            path: {
                'name': name,
                'id': id,
            },
            errors: {
                404: `Document not found or not public`,
                500: `Failed to generate OpenGraph preview`,
            },
        });
    }
}
