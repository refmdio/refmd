/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ActiveShareItem = {
    created_at: string;
    document_id: string;
    document_title: string;
    /**
     * 'document' or 'folder'
     */
    document_type: string;
    expires_at?: string | null;
    id: string;
    parent_share_id?: string | null;
    permission: string;
    token: string;
    url: string;
};

