/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RenderManyRequest } from '../models/RenderManyRequest';
import type { RenderManyResponse } from '../models/RenderManyResponse';
import type { RenderRequest } from '../models/RenderRequest';
import type { RenderResponseBody } from '../models/RenderResponseBody';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class MarkdownService {
    /**
     * @returns RenderResponseBody
     * @throws ApiError
     */
    public static renderMarkdown({
        requestBody,
    }: {
        requestBody: RenderRequest,
    }): CancelablePromise<RenderResponseBody> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/markdown/render',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
    /**
     * @returns RenderManyResponse
     * @throws ApiError
     */
    public static renderMarkdownMany({
        requestBody,
    }: {
        requestBody: RenderManyRequest,
    }): CancelablePromise<RenderManyResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/markdown/render-many',
            body: requestBody,
            mediaType: 'application/json',
        });
    }
}
