/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { HealthResp } from '../models/HealthResp';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class HealthService {
    /**
     * @returns HealthResp
     * @throws ApiError
     */
    public static health(): CancelablePromise<HealthResp> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/health',
        });
    }
}
