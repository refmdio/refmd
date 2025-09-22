/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { UploadFileMultipart } from '../models/UploadFileMultipart';
import type { UploadFileResponse } from '../models/UploadFileResponse';
import type { CancelablePromise } from '../core/CancelablePromise';
import { OpenAPI } from '../core/OpenAPI';
import { request as __request } from '../core/request';
export class FilesService {
    /**
     * POST /api/files (multipart/form-data)
     * Fields:
     * - file: binary file (required)
     * - document_id: uuid (required by current schema)
     * @returns UploadFileResponse File uploaded
     * @throws ApiError
     */
    public static uploadFile({
        formData,
    }: {
        formData: UploadFileMultipart,
    }): CancelablePromise<UploadFileResponse> {
        return __request(OpenAPI, {
            method: 'POST',
            url: '/api/files',
            formData: formData,
            mediaType: 'multipart/form-data',
        });
    }
    /**
     * GET /api/files/documents/{filename}?document_id=uuid -> bytes
     * @returns binary OK
     * @throws ApiError
     */
    public static getFileByName({
        filename,
        documentId,
    }: {
        /**
         * File name
         */
        filename: string,
        /**
         * Document ID
         */
        documentId: string,
    }): CancelablePromise<Blob> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/files/documents/{filename}',
            path: {
                'filename': filename,
            },
            query: {
                'document_id': documentId,
            },
        });
    }
    /**
     * GET /api/files/{id} -> bytes (fallback; primary is /uploads/{filename})
     * @returns binary OK
     * @throws ApiError
     */
    public static getFile({
        id,
    }: {
        /**
         * File ID
         */
        id: string,
    }): CancelablePromise<Blob> {
        return __request(OpenAPI, {
            method: 'GET',
            url: '/api/files/{id}',
            path: {
                'id': id,
            },
        });
    }
}
