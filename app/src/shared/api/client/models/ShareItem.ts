/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ShareItem = {
    expires_at?: string | null;
    id: string;
    /**
     * If present, this document share was materialized from a folder share
     */
    parent_share_id?: string | null;
    permission: string;
    /**
     * document | folder
     */
    scope: string;
    token: string;
    url: string;
};

