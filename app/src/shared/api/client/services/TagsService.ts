/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TagItem } from '../models/TagItem';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class TagsService {
    /**
     * @returns TagItem
     * @throws ApiError
     */
    public static listTags({
        q,
    }: {
        /**
         * Filter contains
         */
        q?: string | null,
    }): CancelablePromise<Array<TagItem>> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/tags',
            query: {
                'q': q,
            },
        });
    }
}
