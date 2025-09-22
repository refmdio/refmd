/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class RealtimeService {
    /**
     * @returns void
     * @throws ApiError
     */
    public static axumWsEntry({
        id,
        token,
        authorization,
    }: {
        /**
         * Document ID (UUID)
         */
        id: string,
        /**
         * JWT or share token
         */
        token?: string | null,
        /**
         * Bearer token (JWT or share token)
         */
        authorization?: string | null,
    }): CancelablePromise<void> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/yjs/{id}',
            path: {
                'id': id,
            },
            headers: {
                'Authorization': authorization,
            },
            query: {
                'token': token,
            },
            errors: {
                401: `Unauthorized`,
            },
        });
    }
}
