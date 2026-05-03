--
-- PostgreSQL database dump
--

\restrict MpFqZU2s1B4fsyMI3w4JiEiOKDLsLcsQkO1kCwSHDHBNsZQ5MdoT2iaTA5fMoAA

-- Dumped from database version 17.7 (Debian 17.7-3.pgdg13+1)
-- Dumped by pg_dump version 18.3

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: oban_job_state; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.oban_job_state AS ENUM (
    'available',
    'scheduled',
    'executing',
    'retryable',
    'completed',
    'discarded',
    'cancelled'
);


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: device_encrypted_umks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_encrypted_umks (
    user_id uuid NOT NULL,
    device_id uuid NOT NULL,
    sender_device_id uuid NOT NULL,
    encrypted_umk bytea NOT NULL,
    nonce bytea NOT NULL,
    created_at timestamp without time zone NOT NULL,
    CONSTRAINT umk_ciphertext_size CHECK ((octet_length(encrypted_umk) = 48)),
    CONSTRAINT umk_nonce_size CHECK ((octet_length(nonce) = 24))
);


--
-- Name: device_registrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_registrations (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    device_type text NOT NULL,
    ecdh_public_key bytea NOT NULL,
    signing_public_key bytea NOT NULL,
    client_nonce bytea NOT NULL,
    ip_address text,
    created_at timestamp without time zone NOT NULL,
    expires_at timestamp without time zone NOT NULL
);


--
-- Name: device_revocation_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_revocation_events (
    user_id uuid NOT NULL,
    device_id uuid NOT NULL,
    revoked_by_device_id uuid NOT NULL,
    revocation_mode text NOT NULL,
    signature bytea NOT NULL,
    revoked_at bigint NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.devices (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    device_type text NOT NULL,
    ecdh_public_key bytea NOT NULL,
    signing_public_key bytea NOT NULL,
    identity_signature bytea NOT NULL,
    client_nonce bytea NOT NULL,
    last_seen_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone NOT NULL,
    revoked_at timestamp without time zone
);


--
-- Name: document_encrypted_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.document_encrypted_keys (
    document_id uuid NOT NULL,
    key_version integer NOT NULL,
    encrypted_dek bytea NOT NULL,
    nonce bytea NOT NULL,
    kek_version integer NOT NULL,
    is_active boolean NOT NULL,
    created_at timestamp without time zone NOT NULL,
    CONSTRAINT dek_ciphertext_size CHECK ((octet_length(encrypted_dek) = 48)),
    CONSTRAINT dek_kek_version_positive CHECK ((kek_version > 0)),
    CONSTRAINT dek_key_version_positive CHECK ((key_version > 0)),
    CONSTRAINT dek_nonce_size CHECK ((octet_length(nonce) = 24))
);


--
-- Name: document_signer_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.document_signer_keys (
    id bigint NOT NULL,
    document_id uuid NOT NULL,
    signer_kind text NOT NULL,
    share_id uuid,
    principal_id uuid,
    user_id uuid,
    device_id uuid NOT NULL,
    display_name text NOT NULL,
    signing_public_key bytea NOT NULL,
    encryption_public_key bytea NOT NULL,
    first_seen_at timestamp without time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp without time zone DEFAULT now() NOT NULL,
    context_key text NOT NULL,
    CONSTRAINT document_signer_keys_encryption_key_size CHECK ((octet_length(encryption_public_key) = 32)),
    CONSTRAINT document_signer_keys_kind_check CHECK ((signer_kind = ANY (ARRAY['workspace'::text, 'share_participant'::text, 'mounted_share'::text]))),
    CONSTRAINT document_signer_keys_signing_key_size CHECK ((octet_length(signing_public_key) = 32))
);


--
-- Name: document_signer_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.document_signer_keys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: document_signer_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.document_signer_keys_id_seq OWNED BY public.document_signer_keys.id;


--
-- Name: document_snapshot_archives; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.document_snapshot_archives (
    id uuid NOT NULL,
    document_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    label text NOT NULL,
    notes text,
    kind text NOT NULL,
    created_by uuid,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: document_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.document_snapshots (
    id uuid NOT NULL,
    document_id uuid NOT NULL,
    parent_snapshot_id uuid,
    latest_version bigint DEFAULT 0 NOT NULL,
    data bytea NOT NULL,
    nonce bytea NOT NULL,
    key_version integer NOT NULL,
    signature bytea NOT NULL,
    ciphertext_hash text NOT NULL,
    clocks jsonb DEFAULT '{}'::jsonb NOT NULL,
    parent_snapshot_update_clocks jsonb DEFAULT '{}'::jsonb NOT NULL,
    parent_snapshot_proof text DEFAULT ''::text NOT NULL,
    device_id uuid NOT NULL,
    created_by_device text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: document_updates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.document_updates (
    id bigint NOT NULL,
    document_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    clock integer,
    version bigint NOT NULL,
    device_id uuid,
    device_signing_pub_key text,
    update_data bytea NOT NULL,
    nonce bytea NOT NULL,
    key_version integer NOT NULL,
    update_hash text NOT NULL,
    signature bytea,
    mac bytea,
    share_id uuid,
    "timestamp" bigint NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT document_updates_auth_check CHECK (((signature IS NOT NULL) AND (mac IS NULL) AND (clock IS NOT NULL) AND (device_signing_pub_key IS NOT NULL) AND (device_id IS NOT NULL) AND (share_id IS NULL)))
);


--
-- Name: document_updates_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.document_updates_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: document_updates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.document_updates_id_seq OWNED BY public.document_updates.id;


--
-- Name: documents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.documents (
    id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    parent_id uuid,
    "position" integer DEFAULT 0 NOT NULL,
    title text DEFAULT 'Untitled'::text NOT NULL,
    encrypted_title bytea,
    encrypted_title_nonce bytea,
    encrypted_title_key_version integer,
    slug text NOT NULL,
    path text,
    doc_type text DEFAULT 'document'::text NOT NULL,
    is_encrypted boolean DEFAULT true NOT NULL,
    needs_dek_rotation boolean DEFAULT false NOT NULL,
    needs_rotation_snapshot boolean DEFAULT false NOT NULL,
    min_dek_version integer DEFAULT 1 NOT NULL,
    created_by uuid,
    archived_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    active_snapshot_id uuid
);


--
-- Name: guest_invitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.guest_invitations (
    id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    token_hash text NOT NULL,
    token_prefix text NOT NULL,
    target_scope text NOT NULL,
    target_document_id uuid,
    permission text NOT NULL,
    encrypted_kek bytea NOT NULL,
    kek_nonce bytea NOT NULL,
    kek_version integer NOT NULL,
    max_redemptions integer DEFAULT 1 NOT NULL,
    redemption_count integer DEFAULT 0 NOT NULL,
    invited_by uuid NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone NOT NULL,
    revoked_at timestamp without time zone,
    CONSTRAINT guest_invitations_encrypted_kek_length CHECK ((length(encrypted_kek) = 48)),
    CONSTRAINT guest_invitations_kek_nonce_length CHECK ((length(kek_nonce) = 24)),
    CONSTRAINT guest_invitations_kek_version_positive CHECK ((kek_version > 0)),
    CONSTRAINT guest_invitations_max_redemptions_positive CHECK ((max_redemptions > 0)),
    CONSTRAINT guest_invitations_permission_check CHECK ((permission = ANY (ARRAY['view'::text, 'edit'::text]))),
    CONSTRAINT guest_invitations_redemption_count_bounded CHECK ((redemption_count <= max_redemptions)),
    CONSTRAINT guest_invitations_redemption_count_non_negative CHECK ((redemption_count >= 0)),
    CONSTRAINT guest_invitations_target_required CHECK ((((target_scope = 'workspace'::text) AND (target_document_id IS NULL)) OR ((target_scope = ANY (ARRAY['document'::text, 'folder'::text])) AND (target_document_id IS NOT NULL)))),
    CONSTRAINT guest_invitations_target_scope_check CHECK ((target_scope = ANY (ARRAY['workspace'::text, 'document'::text, 'folder'::text]))),
    CONSTRAINT guest_invitations_token_hash_format CHECK ((token_hash ~ '^[A-Za-z0-9\-_]{43}$'::text)),
    CONSTRAINT guest_invitations_token_hash_length CHECK ((length(token_hash) = 43)),
    CONSTRAINT guest_invitations_token_prefix_format CHECK ((token_prefix ~ '^[A-Za-z0-9\-_]{4}$'::text)),
    CONSTRAINT guest_invitations_token_prefix_length CHECK ((length(token_prefix) = 4))
);


--
-- Name: oban_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oban_jobs (
    id bigint NOT NULL,
    state public.oban_job_state DEFAULT 'available'::public.oban_job_state NOT NULL,
    queue text DEFAULT 'default'::text NOT NULL,
    worker text NOT NULL,
    args jsonb DEFAULT '{}'::jsonb NOT NULL,
    errors jsonb[] DEFAULT ARRAY[]::jsonb[] NOT NULL,
    attempt integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 20 NOT NULL,
    inserted_at timestamp without time zone DEFAULT timezone('UTC'::text, now()) NOT NULL,
    scheduled_at timestamp without time zone DEFAULT timezone('UTC'::text, now()) NOT NULL,
    attempted_at timestamp without time zone,
    completed_at timestamp without time zone,
    attempted_by text[],
    discarded_at timestamp without time zone,
    priority integer DEFAULT 0 NOT NULL,
    tags text[] DEFAULT ARRAY[]::text[],
    meta jsonb DEFAULT '{}'::jsonb,
    cancelled_at timestamp without time zone,
    CONSTRAINT attempt_range CHECK (((attempt >= 0) AND (attempt <= max_attempts))),
    CONSTRAINT positive_max_attempts CHECK ((max_attempts > 0)),
    CONSTRAINT queue_length CHECK (((char_length(queue) > 0) AND (char_length(queue) < 128))),
    CONSTRAINT worker_length CHECK (((char_length(worker) > 0) AND (char_length(worker) < 128)))
);


--
-- Name: TABLE oban_jobs; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.oban_jobs IS '12';


--
-- Name: oban_jobs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.oban_jobs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: oban_jobs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.oban_jobs_id_seq OWNED BY public.oban_jobs.id;


--
-- Name: oban_peers; Type: TABLE; Schema: public; Owner: -
--

CREATE UNLOGGED TABLE public.oban_peers (
    name text NOT NULL,
    node text NOT NULL,
    started_at timestamp without time zone NOT NULL,
    expires_at timestamp without time zone NOT NULL
);


--
-- Name: password_reset_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.password_reset_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    token_hash text NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: pop_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pop_challenges (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    device_id uuid NOT NULL,
    challenge_hash bytea NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: public_documents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.public_documents (
    document_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    slug character varying(255) NOT NULL,
    title character varying(255) NOT NULL,
    content text NOT NULL,
    content_hash character varying(255) NOT NULL,
    noindex boolean DEFAULT false NOT NULL,
    published_by uuid,
    published_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: public_slug_histories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.public_slug_histories (
    id uuid NOT NULL,
    old_slug character varying(255) NOT NULL,
    document_id uuid,
    action character varying(255) NOT NULL,
    created_at timestamp without time zone NOT NULL,
    CONSTRAINT public_slug_histories_action_check CHECK (((action)::text = ANY ((ARRAY['redirect'::character varying, 'gone'::character varying])::text[])))
);


--
-- Name: recovery_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.recovery_challenges (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    challenge_hash bytea NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version bigint NOT NULL,
    inserted_at timestamp(0) without time zone
);


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sessions (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    device_id uuid,
    token_hash text NOT NULL,
    remember_me boolean NOT NULL,
    is_recovery boolean DEFAULT false NOT NULL,
    ip_address text,
    user_agent text,
    expires_at timestamp without time zone NOT NULL,
    last_seen_at timestamp without time zone NOT NULL,
    last_verified_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL,
    device_registration_id uuid
);


--
-- Name: share_exclusions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.share_exclusions (
    share_id uuid NOT NULL,
    document_id uuid NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: share_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.share_keys (
    share_id uuid NOT NULL,
    document_id uuid NOT NULL,
    encrypted_dek bytea NOT NULL,
    nonce bytea,
    dek_server_nonce bytea NOT NULL,
    server_key_id character varying(255) NOT NULL,
    manage_token_hash character varying(255) NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    salt bytea,
    kdf_params jsonb,
    encrypted_auth_key bytea,
    auth_key_nonce bytea,
    CONSTRAINT share_keys_auth_key_nonce_size CHECK (((auth_key_nonce IS NULL) OR (octet_length(auth_key_nonce) = 12))),
    CONSTRAINT share_keys_dek_server_nonce_size CHECK ((octet_length(dek_server_nonce) = 12)),
    CONSTRAINT share_keys_nonce_size CHECK (((nonce IS NULL) OR (octet_length(nonce) = 24))),
    CONSTRAINT share_keys_salt_size CHECK (((salt IS NULL) OR (octet_length(salt) = 16)))
);


--
-- Name: share_mounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.share_mounts (
    id uuid NOT NULL,
    share_id uuid NOT NULL,
    target_document_id uuid NOT NULL,
    target_kind character varying(255) NOT NULL,
    user_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    parent_id uuid,
    "position" integer DEFAULT 0 NOT NULL,
    created_at timestamp without time zone NOT NULL,
    CONSTRAINT share_mounts_position_non_negative CHECK (("position" >= 0)),
    CONSTRAINT share_mounts_target_kind_check CHECK (((target_kind)::text = ANY ((ARRAY['document'::character varying, 'folder'::character varying])::text[])))
);


--
-- Name: share_participant_devices; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.share_participant_devices (
    id uuid NOT NULL,
    share_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    signing_public_key bytea NOT NULL,
    encryption_public_key bytea NOT NULL,
    last_seen_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    CONSTRAINT share_participant_devices_encryption_key_size CHECK ((octet_length(encryption_public_key) = 32)),
    CONSTRAINT share_participant_devices_signing_key_size CHECK ((octet_length(signing_public_key) = 32))
);


--
-- Name: share_participant_pop_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.share_participant_pop_challenges (
    id uuid NOT NULL,
    share_id uuid NOT NULL,
    device_id uuid NOT NULL,
    challenge_hash bytea NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: share_participant_principals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.share_participant_principals (
    id uuid NOT NULL,
    share_id uuid NOT NULL,
    display_name character varying(255) NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: share_participant_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.share_participant_sessions (
    id uuid NOT NULL,
    share_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    device_id uuid NOT NULL,
    token_hash character varying(255) NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    last_seen_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone NOT NULL,
    "grant" character varying(255) NOT NULL,
    CONSTRAINT share_participant_sessions_grant_check CHECK ((("grant")::text = ANY ((ARRAY['view'::character varying, 'edit'::character varying])::text[])))
);


--
-- Name: share_password_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.share_password_challenges (
    id uuid NOT NULL,
    share_id uuid,
    token_hash character varying(255) NOT NULL,
    challenge bytea NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone NOT NULL,
    CONSTRAINT share_password_challenges_challenge_size CHECK ((octet_length(challenge) = 32))
);


--
-- Name: shared_document_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.shared_document_tokens (
    id uuid NOT NULL,
    share_id uuid NOT NULL,
    document_id uuid NOT NULL,
    token character varying(255) NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: shared_folder_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.shared_folder_tokens (
    id uuid NOT NULL,
    share_id uuid NOT NULL,
    document_id uuid NOT NULL,
    token character varying(255) NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: shares; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.shares (
    id uuid NOT NULL,
    document_id uuid NOT NULL,
    parent_share_id uuid,
    scope character varying(255) NOT NULL,
    token_hash character varying(255) NOT NULL,
    token_prefix character varying(255) NOT NULL,
    slug_ciphertext bytea NOT NULL,
    slug_nonce bytea NOT NULL,
    slug_key_id character varying(255) NOT NULL,
    permission character varying(255) NOT NULL,
    password_protected boolean DEFAULT false NOT NULL,
    access_limit integer,
    access_count integer DEFAULT 0 NOT NULL,
    created_by uuid NOT NULL,
    expires_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    CONSTRAINT shares_access_count_non_negative CHECK ((access_count >= 0)),
    CONSTRAINT shares_access_limit_positive CHECK (((access_limit IS NULL) OR (access_limit >= 0))),
    CONSTRAINT shares_permission_check CHECK (((permission)::text = ANY ((ARRAY['view'::character varying, 'edit'::character varying])::text[]))),
    CONSTRAINT shares_scope_check CHECK (((scope)::text = ANY ((ARRAY['document'::character varying, 'folder'::character varying])::text[]))),
    CONSTRAINT shares_slug_nonce_size CHECK ((octet_length(slug_nonce) = 12))
);


--
-- Name: trust_transfer_nonces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trust_transfer_nonces (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    device_id uuid NOT NULL,
    nonce bytea NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: trust_transfer_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trust_transfer_states (
    device_id uuid NOT NULL,
    user_id uuid NOT NULL,
    sender_device_id uuid NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    signature bytea NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: user_encrypted_identity_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_encrypted_identity_keys (
    user_id uuid NOT NULL,
    encrypted_ecdh_private bytea NOT NULL,
    encrypted_ecdh_private_nonce bytea NOT NULL,
    encrypted_signing_private bytea NOT NULL,
    encrypted_signing_private_nonce bytea NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: user_encrypted_master_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_encrypted_master_keys (
    user_id uuid NOT NULL,
    auth_type text NOT NULL,
    encrypted_umk bytea,
    umk_nonce bytea,
    salt bytea,
    kdf_type text,
    kdf_params jsonb,
    auth_key_hash text,
    recovery_encrypted_umk bytea NOT NULL,
    recovery_nonce bytea NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: user_external_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_external_accounts (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    provider text NOT NULL,
    provider_user_id text NOT NULL,
    email text,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: user_identity_public_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_identity_public_keys (
    user_id uuid NOT NULL,
    ecdh_public_key bytea NOT NULL,
    signing_public_key bytea NOT NULL,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: user_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_settings (
    user_id uuid NOT NULL,
    theme text DEFAULT 'system'::text NOT NULL,
    locale text DEFAULT 'en'::text NOT NULL,
    editor_vim_mode boolean DEFAULT false NOT NULL,
    editor_font_size integer DEFAULT 14 NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    editor_default_mode character varying(255) DEFAULT 'split'::character varying NOT NULL,
    editor_layout_mode character varying(255) DEFAULT 'tiling'::character varying NOT NULL
);


--
-- Name: user_shortcuts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_shortcuts (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    action text NOT NULL,
    keys text NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid NOT NULL,
    email text NOT NULL,
    name text NOT NULL,
    encryption_setup_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    account_type text DEFAULT 'registered'::text NOT NULL,
    CONSTRAINT users_account_type_check CHECK ((account_type = ANY (ARRAY['registered'::text, 'guest'::text])))
);


--
-- Name: workspace_encrypted_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_encrypted_keys (
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    device_id uuid NOT NULL,
    key_version integer NOT NULL,
    sender_device_id uuid NOT NULL,
    encrypted_kek bytea NOT NULL,
    nonce bytea NOT NULL,
    is_active boolean NOT NULL,
    created_at timestamp without time zone NOT NULL,
    CONSTRAINT kek_ciphertext_size CHECK ((octet_length(encrypted_kek) = 48)),
    CONSTRAINT kek_nonce_size CHECK ((octet_length(nonce) = 24))
);


--
-- Name: workspace_guest_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_guest_grants (
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    target_scope text NOT NULL,
    target_document_id uuid,
    permission text NOT NULL,
    invite_id uuid NOT NULL,
    revoked_at timestamp without time zone,
    created_at timestamp without time zone NOT NULL,
    CONSTRAINT workspace_guest_grants_permission_check CHECK ((permission = ANY (ARRAY['view'::text, 'edit'::text]))),
    CONSTRAINT workspace_guest_grants_target_required CHECK ((((target_scope = 'workspace'::text) AND (target_document_id IS NULL)) OR ((target_scope = ANY (ARRAY['document'::text, 'folder'::text])) AND (target_document_id IS NOT NULL)))),
    CONSTRAINT workspace_guest_grants_target_scope_check CHECK ((target_scope = ANY (ARRAY['workspace'::text, 'document'::text, 'folder'::text])))
);


--
-- Name: workspace_invitations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_invitations (
    id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    token_hash text NOT NULL,
    token_prefix text NOT NULL,
    role_id uuid,
    invited_by uuid NOT NULL,
    invited_email text NOT NULL,
    encrypted_kek bytea NOT NULL,
    kek_nonce bytea NOT NULL,
    kek_version integer NOT NULL,
    is_used boolean DEFAULT false NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone NOT NULL,
    revoked_at timestamp without time zone,
    CONSTRAINT invitation_encrypted_kek_length CHECK ((length(encrypted_kek) = 48)),
    CONSTRAINT invitation_kek_nonce_length CHECK ((length(kek_nonce) = 24)),
    CONSTRAINT invitation_kek_version_positive CHECK ((kek_version > 0)),
    CONSTRAINT invitation_token_hash_format CHECK ((token_hash ~ '^[A-Za-z0-9\-_]{43}$'::text)),
    CONSTRAINT invitation_token_hash_length CHECK ((length(token_hash) = 43)),
    CONSTRAINT invitation_token_prefix_format CHECK ((token_prefix ~ '^[A-Za-z0-9\-_]{4}$'::text)),
    CONSTRAINT invitation_token_prefix_length CHECK ((length(token_prefix) = 4))
);


--
-- Name: workspace_kek_backups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_kek_backups (
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    key_version integer NOT NULL,
    encrypted_kek bytea NOT NULL,
    nonce bytea NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp without time zone NOT NULL,
    CONSTRAINT workspace_kek_backups_ciphertext_size CHECK ((octet_length(encrypted_kek) = 48)),
    CONSTRAINT workspace_kek_backups_key_version_positive CHECK ((key_version > 0)),
    CONSTRAINT workspace_kek_backups_nonce_length CHECK ((length(nonce) = 24))
);


--
-- Name: workspace_member_envelopes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_member_envelopes (
    workspace_id uuid NOT NULL,
    target_user_id uuid NOT NULL,
    key_version integer NOT NULL,
    sender_device_id uuid NOT NULL,
    encrypted_kek bytea NOT NULL,
    nonce bytea NOT NULL,
    created_at timestamp without time zone NOT NULL,
    CONSTRAINT member_envelope_ciphertext_size CHECK ((octet_length(encrypted_kek) = 48)),
    CONSTRAINT member_envelope_nonce_size CHECK ((octet_length(nonce) = 24))
);


--
-- Name: workspace_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_members (
    workspace_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    joined_at timestamp without time zone NOT NULL
);


--
-- Name: workspace_role_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_role_permissions (
    role_id uuid NOT NULL,
    permission text NOT NULL,
    granted boolean NOT NULL
);


--
-- Name: workspace_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_roles (
    id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    name text NOT NULL,
    base_role text NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    catalog_version integer,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: workspace_tag_index_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspace_tag_index_keys (
    workspace_id uuid NOT NULL,
    encrypted_key bytea NOT NULL,
    nonce bytea NOT NULL,
    kek_version integer NOT NULL,
    created_at timestamp without time zone NOT NULL
);


--
-- Name: workspaces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workspaces (
    id uuid NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    description text,
    icon text,
    owner_id uuid NOT NULL,
    current_kek_version integer DEFAULT 0 NOT NULL,
    min_kek_version integer DEFAULT 0 NOT NULL,
    needs_kek_rotation boolean DEFAULT false NOT NULL,
    kek_rotation_initiator_user_id uuid,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    guest_invites_enabled boolean DEFAULT false NOT NULL,
    guest_member_limit integer,
    CONSTRAINT workspaces_guest_member_limit_positive CHECK (((guest_member_limit IS NULL) OR (guest_member_limit > 0)))
);


--
-- Name: document_signer_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_signer_keys ALTER COLUMN id SET DEFAULT nextval('public.document_signer_keys_id_seq'::regclass);


--
-- Name: document_updates id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_updates ALTER COLUMN id SET DEFAULT nextval('public.document_updates_id_seq'::regclass);


--
-- Name: oban_jobs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oban_jobs ALTER COLUMN id SET DEFAULT nextval('public.oban_jobs_id_seq'::regclass);


--
-- Name: device_encrypted_umks device_encrypted_umks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_encrypted_umks
    ADD CONSTRAINT device_encrypted_umks_pkey PRIMARY KEY (user_id, device_id);


--
-- Name: device_registrations device_registrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_registrations
    ADD CONSTRAINT device_registrations_pkey PRIMARY KEY (id);


--
-- Name: device_revocation_events device_revocation_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_revocation_events
    ADD CONSTRAINT device_revocation_events_pkey PRIMARY KEY (user_id, device_id);


--
-- Name: devices devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_pkey PRIMARY KEY (id);


--
-- Name: document_encrypted_keys document_encrypted_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_encrypted_keys
    ADD CONSTRAINT document_encrypted_keys_pkey PRIMARY KEY (document_id, key_version);


--
-- Name: document_signer_keys document_signer_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_signer_keys
    ADD CONSTRAINT document_signer_keys_pkey PRIMARY KEY (id);


--
-- Name: document_snapshot_archives document_snapshot_archives_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_snapshot_archives
    ADD CONSTRAINT document_snapshot_archives_pkey PRIMARY KEY (id);


--
-- Name: document_snapshots document_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_snapshots
    ADD CONSTRAINT document_snapshots_pkey PRIMARY KEY (id);


--
-- Name: document_updates document_updates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_updates
    ADD CONSTRAINT document_updates_pkey PRIMARY KEY (id);


--
-- Name: documents documents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.documents
    ADD CONSTRAINT documents_pkey PRIMARY KEY (id);


--
-- Name: guest_invitations guest_invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_invitations
    ADD CONSTRAINT guest_invitations_pkey PRIMARY KEY (id);


--
-- Name: oban_jobs non_negative_priority; Type: CHECK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE public.oban_jobs
    ADD CONSTRAINT non_negative_priority CHECK ((priority >= 0)) NOT VALID;


--
-- Name: oban_jobs oban_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oban_jobs
    ADD CONSTRAINT oban_jobs_pkey PRIMARY KEY (id);


--
-- Name: oban_peers oban_peers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oban_peers
    ADD CONSTRAINT oban_peers_pkey PRIMARY KEY (name);


--
-- Name: password_reset_tokens password_reset_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id);


--
-- Name: pop_challenges pop_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pop_challenges
    ADD CONSTRAINT pop_challenges_pkey PRIMARY KEY (id);


--
-- Name: public_documents public_documents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_documents
    ADD CONSTRAINT public_documents_pkey PRIMARY KEY (document_id);


--
-- Name: public_slug_histories public_slug_histories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_slug_histories
    ADD CONSTRAINT public_slug_histories_pkey PRIMARY KEY (id);


--
-- Name: recovery_challenges recovery_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recovery_challenges
    ADD CONSTRAINT recovery_challenges_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: share_exclusions share_exclusions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_exclusions
    ADD CONSTRAINT share_exclusions_pkey PRIMARY KEY (share_id, document_id);


--
-- Name: share_keys share_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_keys
    ADD CONSTRAINT share_keys_pkey PRIMARY KEY (share_id);


--
-- Name: share_mounts share_mounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_mounts
    ADD CONSTRAINT share_mounts_pkey PRIMARY KEY (id);


--
-- Name: share_participant_devices share_participant_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_participant_devices
    ADD CONSTRAINT share_participant_devices_pkey PRIMARY KEY (id);


--
-- Name: share_participant_pop_challenges share_participant_pop_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_participant_pop_challenges
    ADD CONSTRAINT share_participant_pop_challenges_pkey PRIMARY KEY (id);


--
-- Name: share_participant_principals share_participant_principals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_participant_principals
    ADD CONSTRAINT share_participant_principals_pkey PRIMARY KEY (id);


--
-- Name: share_participant_sessions share_participant_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_participant_sessions
    ADD CONSTRAINT share_participant_sessions_pkey PRIMARY KEY (id);


--
-- Name: share_password_challenges share_password_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_password_challenges
    ADD CONSTRAINT share_password_challenges_pkey PRIMARY KEY (id);


--
-- Name: shared_document_tokens shared_document_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shared_document_tokens
    ADD CONSTRAINT shared_document_tokens_pkey PRIMARY KEY (id);


--
-- Name: shared_folder_tokens shared_folder_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shared_folder_tokens
    ADD CONSTRAINT shared_folder_tokens_pkey PRIMARY KEY (id);


--
-- Name: shares shares_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shares
    ADD CONSTRAINT shares_pkey PRIMARY KEY (id);


--
-- Name: trust_transfer_nonces trust_transfer_nonces_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trust_transfer_nonces
    ADD CONSTRAINT trust_transfer_nonces_pkey PRIMARY KEY (id);


--
-- Name: trust_transfer_states trust_transfer_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trust_transfer_states
    ADD CONSTRAINT trust_transfer_states_pkey PRIMARY KEY (device_id);


--
-- Name: user_encrypted_identity_keys user_encrypted_identity_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_encrypted_identity_keys
    ADD CONSTRAINT user_encrypted_identity_keys_pkey PRIMARY KEY (user_id);


--
-- Name: user_encrypted_master_keys user_encrypted_master_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_encrypted_master_keys
    ADD CONSTRAINT user_encrypted_master_keys_pkey PRIMARY KEY (user_id);


--
-- Name: user_external_accounts user_external_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_external_accounts
    ADD CONSTRAINT user_external_accounts_pkey PRIMARY KEY (id);


--
-- Name: user_identity_public_keys user_identity_public_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_identity_public_keys
    ADD CONSTRAINT user_identity_public_keys_pkey PRIMARY KEY (user_id);


--
-- Name: user_settings user_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_pkey PRIMARY KEY (user_id);


--
-- Name: user_shortcuts user_shortcuts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_shortcuts
    ADD CONSTRAINT user_shortcuts_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: workspace_encrypted_keys workspace_encrypted_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_encrypted_keys
    ADD CONSTRAINT workspace_encrypted_keys_pkey PRIMARY KEY (workspace_id, user_id, device_id, key_version);


--
-- Name: workspace_guest_grants workspace_guest_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_guest_grants
    ADD CONSTRAINT workspace_guest_grants_pkey PRIMARY KEY (workspace_id, user_id);


--
-- Name: workspace_invitations workspace_invitations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_invitations
    ADD CONSTRAINT workspace_invitations_pkey PRIMARY KEY (id);


--
-- Name: workspace_kek_backups workspace_kek_backups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_kek_backups
    ADD CONSTRAINT workspace_kek_backups_pkey PRIMARY KEY (workspace_id, user_id, key_version);


--
-- Name: workspace_member_envelopes workspace_member_envelopes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_member_envelopes
    ADD CONSTRAINT workspace_member_envelopes_pkey PRIMARY KEY (workspace_id, target_user_id, key_version);


--
-- Name: workspace_members workspace_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_members
    ADD CONSTRAINT workspace_members_pkey PRIMARY KEY (workspace_id, user_id);


--
-- Name: workspace_role_permissions workspace_role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_role_permissions
    ADD CONSTRAINT workspace_role_permissions_pkey PRIMARY KEY (role_id, permission);


--
-- Name: workspace_roles workspace_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_roles
    ADD CONSTRAINT workspace_roles_pkey PRIMARY KEY (id);


--
-- Name: workspace_tag_index_keys workspace_tag_index_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_tag_index_keys
    ADD CONSTRAINT workspace_tag_index_keys_pkey PRIMARY KEY (workspace_id);


--
-- Name: workspaces workspaces_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspaces
    ADD CONSTRAINT workspaces_pkey PRIMARY KEY (id);


--
-- Name: device_registrations_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX device_registrations_user_id_index ON public.device_registrations USING btree (user_id);


--
-- Name: devices_ecdh_public_key_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX devices_ecdh_public_key_index ON public.devices USING btree (ecdh_public_key);


--
-- Name: devices_signing_public_key_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX devices_signing_public_key_index ON public.devices USING btree (signing_public_key);


--
-- Name: devices_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX devices_user_id_index ON public.devices USING btree (user_id);


--
-- Name: document_signer_keys_context_unique_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX document_signer_keys_context_unique_index ON public.document_signer_keys USING btree (document_id, signing_public_key, context_key);


--
-- Name: document_signer_keys_document_id_share_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX document_signer_keys_document_id_share_id_index ON public.document_signer_keys USING btree (document_id, share_id);


--
-- Name: document_signer_keys_document_id_signer_kind_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX document_signer_keys_document_id_signer_kind_index ON public.document_signer_keys USING btree (document_id, signer_kind);


--
-- Name: document_snapshot_archives_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX document_snapshot_archives_document_id_index ON public.document_snapshot_archives USING btree (document_id);


--
-- Name: document_snapshots_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX document_snapshots_document_id_index ON public.document_snapshots USING btree (document_id);


--
-- Name: document_updates_document_id_update_hash_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX document_updates_document_id_update_hash_index ON public.document_updates USING btree (document_id, update_hash);


--
-- Name: document_updates_document_id_version_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX document_updates_document_id_version_index ON public.document_updates USING btree (document_id, version);


--
-- Name: document_updates_snapshot_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX document_updates_snapshot_id_index ON public.document_updates USING btree (snapshot_id);


--
-- Name: documents_workspace_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX documents_workspace_id_index ON public.documents USING btree (workspace_id);


--
-- Name: documents_workspace_parent_position; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX documents_workspace_parent_position ON public.documents USING btree (workspace_id, parent_id, "position") NULLS NOT DISTINCT;


--
-- Name: guest_invitations_target_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX guest_invitations_target_document_id_index ON public.guest_invitations USING btree (target_document_id);


--
-- Name: guest_invitations_token_hash_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX guest_invitations_token_hash_index ON public.guest_invitations USING btree (token_hash);


--
-- Name: guest_invitations_workspace_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX guest_invitations_workspace_id_index ON public.guest_invitations USING btree (workspace_id);


--
-- Name: oban_jobs_args_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oban_jobs_args_index ON public.oban_jobs USING gin (args);


--
-- Name: oban_jobs_meta_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oban_jobs_meta_index ON public.oban_jobs USING gin (meta);


--
-- Name: oban_jobs_state_queue_priority_scheduled_at_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oban_jobs_state_queue_priority_scheduled_at_id_index ON public.oban_jobs USING btree (state, queue, priority, scheduled_at, id);


--
-- Name: password_reset_tokens_token_hash_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX password_reset_tokens_token_hash_index ON public.password_reset_tokens USING btree (token_hash);


--
-- Name: password_reset_tokens_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX password_reset_tokens_user_id_index ON public.password_reset_tokens USING btree (user_id);


--
-- Name: pop_challenges_challenge_hash_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX pop_challenges_challenge_hash_index ON public.pop_challenges USING btree (challenge_hash);


--
-- Name: pop_challenges_expires_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX pop_challenges_expires_at_index ON public.pop_challenges USING btree (expires_at);


--
-- Name: pop_challenges_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX pop_challenges_user_id_index ON public.pop_challenges USING btree (user_id);


--
-- Name: public_documents_slug_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX public_documents_slug_index ON public.public_documents USING btree (slug);


--
-- Name: public_documents_workspace_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX public_documents_workspace_id_index ON public.public_documents USING btree (workspace_id);


--
-- Name: public_slug_histories_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX public_slug_histories_document_id_index ON public.public_slug_histories USING btree (document_id);


--
-- Name: public_slug_histories_old_slug_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX public_slug_histories_old_slug_index ON public.public_slug_histories USING btree (old_slug);


--
-- Name: recovery_challenges_challenge_hash_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX recovery_challenges_challenge_hash_index ON public.recovery_challenges USING btree (challenge_hash);


--
-- Name: recovery_challenges_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX recovery_challenges_user_id_index ON public.recovery_challenges USING btree (user_id);


--
-- Name: sessions_token_hash_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX sessions_token_hash_index ON public.sessions USING btree (token_hash);


--
-- Name: sessions_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sessions_user_id_index ON public.sessions USING btree (user_id);


--
-- Name: share_exclusions_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_exclusions_document_id_index ON public.share_exclusions USING btree (document_id);


--
-- Name: share_keys_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_keys_document_id_index ON public.share_keys USING btree (document_id);


--
-- Name: share_keys_manage_token_hash_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX share_keys_manage_token_hash_index ON public.share_keys USING btree (manage_token_hash);


--
-- Name: share_mounts_share_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_mounts_share_id_index ON public.share_mounts USING btree (share_id);


--
-- Name: share_mounts_share_target_user_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX share_mounts_share_target_user_index ON public.share_mounts USING btree (share_id, target_document_id, user_id);


--
-- Name: share_mounts_target_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_mounts_target_document_id_index ON public.share_mounts USING btree (target_document_id);


--
-- Name: share_mounts_user_id_workspace_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_mounts_user_id_workspace_id_index ON public.share_mounts USING btree (user_id, workspace_id);


--
-- Name: share_mounts_workspace_id_parent_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_mounts_workspace_id_parent_id_index ON public.share_mounts USING btree (workspace_id, parent_id);


--
-- Name: share_participant_devices_principal_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_participant_devices_principal_id_index ON public.share_participant_devices USING btree (principal_id);


--
-- Name: share_participant_devices_share_id_signing_public_key_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX share_participant_devices_share_id_signing_public_key_index ON public.share_participant_devices USING btree (share_id, signing_public_key);


--
-- Name: share_participant_pop_challenges_expires_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_participant_pop_challenges_expires_at_index ON public.share_participant_pop_challenges USING btree (expires_at);


--
-- Name: share_participant_pop_challenges_share_id_device_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_participant_pop_challenges_share_id_device_id_index ON public.share_participant_pop_challenges USING btree (share_id, device_id);


--
-- Name: share_participant_principals_share_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_participant_principals_share_id_index ON public.share_participant_principals USING btree (share_id);


--
-- Name: share_participant_sessions_expires_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_participant_sessions_expires_at_index ON public.share_participant_sessions USING btree (expires_at);


--
-- Name: share_participant_sessions_share_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_participant_sessions_share_id_index ON public.share_participant_sessions USING btree (share_id);


--
-- Name: share_participant_sessions_token_hash_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX share_participant_sessions_token_hash_index ON public.share_participant_sessions USING btree (token_hash);


--
-- Name: share_password_challenges_expires_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX share_password_challenges_expires_at_index ON public.share_password_challenges USING btree (expires_at);


--
-- Name: share_password_challenges_token_hash_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX share_password_challenges_token_hash_index ON public.share_password_challenges USING btree (token_hash);


--
-- Name: shared_document_tokens_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX shared_document_tokens_document_id_index ON public.shared_document_tokens USING btree (document_id);


--
-- Name: shared_document_tokens_share_id_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX shared_document_tokens_share_id_document_id_index ON public.shared_document_tokens USING btree (share_id, document_id);


--
-- Name: shared_document_tokens_token_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX shared_document_tokens_token_index ON public.shared_document_tokens USING btree (token);


--
-- Name: shared_folder_tokens_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX shared_folder_tokens_document_id_index ON public.shared_folder_tokens USING btree (document_id);


--
-- Name: shared_folder_tokens_share_id_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX shared_folder_tokens_share_id_document_id_index ON public.shared_folder_tokens USING btree (share_id, document_id);


--
-- Name: shared_folder_tokens_token_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX shared_folder_tokens_token_index ON public.shared_folder_tokens USING btree (token);


--
-- Name: shares_created_by_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX shares_created_by_index ON public.shares USING btree (created_by);


--
-- Name: shares_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX shares_document_id_index ON public.shares USING btree (document_id);


--
-- Name: shares_parent_share_document_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX shares_parent_share_document_id_index ON public.shares USING btree (parent_share_id, document_id) WHERE (parent_share_id IS NOT NULL);


--
-- Name: shares_token_hash_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX shares_token_hash_index ON public.shares USING btree (token_hash);


--
-- Name: trust_transfer_nonces_user_id_device_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX trust_transfer_nonces_user_id_device_id_index ON public.trust_transfer_nonces USING btree (user_id, device_id);


--
-- Name: user_external_accounts_provider_provider_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_external_accounts_provider_provider_user_id_index ON public.user_external_accounts USING btree (provider, provider_user_id);


--
-- Name: user_external_accounts_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_external_accounts_user_id_index ON public.user_external_accounts USING btree (user_id);


--
-- Name: user_shortcuts_user_id_action_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX user_shortcuts_user_id_action_index ON public.user_shortcuts USING btree (user_id, action);


--
-- Name: users_email_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_email_index ON public.users USING btree (email);


--
-- Name: workspace_guest_grants_invite_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workspace_guest_grants_invite_id_index ON public.workspace_guest_grants USING btree (invite_id);


--
-- Name: workspace_guest_grants_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workspace_guest_grants_user_id_index ON public.workspace_guest_grants USING btree (user_id);


--
-- Name: workspace_guest_grants_workspace_id_revoked_at_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workspace_guest_grants_workspace_id_revoked_at_index ON public.workspace_guest_grants USING btree (workspace_id, revoked_at);


--
-- Name: workspace_invitations_token_hash_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX workspace_invitations_token_hash_index ON public.workspace_invitations USING btree (token_hash);


--
-- Name: workspace_kek_backups_one_active_per_user; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX workspace_kek_backups_one_active_per_user ON public.workspace_kek_backups USING btree (workspace_id, user_id) WHERE (is_active = true);


--
-- Name: workspace_members_user_id_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workspace_members_user_id_index ON public.workspace_members USING btree (user_id);


--
-- Name: workspace_roles_composite; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX workspace_roles_composite ON public.workspace_roles USING btree (workspace_id, id);


--
-- Name: workspace_roles_one_default_per_workspace; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX workspace_roles_one_default_per_workspace ON public.workspace_roles USING btree (workspace_id) WHERE (is_default = true);


--
-- Name: workspaces_slug_index; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX workspaces_slug_index ON public.workspaces USING btree (slug);


--
-- Name: device_encrypted_umks device_encrypted_umks_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_encrypted_umks
    ADD CONSTRAINT device_encrypted_umks_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;


--
-- Name: device_encrypted_umks device_encrypted_umks_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_encrypted_umks
    ADD CONSTRAINT device_encrypted_umks_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: device_registrations device_registrations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_registrations
    ADD CONSTRAINT device_registrations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: device_revocation_events device_revocation_events_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_revocation_events
    ADD CONSTRAINT device_revocation_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: devices devices_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.devices
    ADD CONSTRAINT devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: document_encrypted_keys document_encrypted_keys_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_encrypted_keys
    ADD CONSTRAINT document_encrypted_keys_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: document_signer_keys document_signer_keys_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_signer_keys
    ADD CONSTRAINT document_signer_keys_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: document_snapshot_archives document_snapshot_archives_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_snapshot_archives
    ADD CONSTRAINT document_snapshot_archives_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: document_snapshot_archives document_snapshot_archives_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_snapshot_archives
    ADD CONSTRAINT document_snapshot_archives_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: document_snapshot_archives document_snapshot_archives_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_snapshot_archives
    ADD CONSTRAINT document_snapshot_archives_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES public.document_snapshots(id) ON DELETE CASCADE;


--
-- Name: document_snapshots document_snapshots_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_snapshots
    ADD CONSTRAINT document_snapshots_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: document_snapshots document_snapshots_parent_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_snapshots
    ADD CONSTRAINT document_snapshots_parent_snapshot_id_fkey FOREIGN KEY (parent_snapshot_id) REFERENCES public.document_snapshots(id);


--
-- Name: document_updates document_updates_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_updates
    ADD CONSTRAINT document_updates_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: document_updates document_updates_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.document_updates
    ADD CONSTRAINT document_updates_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES public.document_snapshots(id);


--
-- Name: documents documents_active_snapshot_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.documents
    ADD CONSTRAINT documents_active_snapshot_id_fkey FOREIGN KEY (active_snapshot_id) REFERENCES public.document_snapshots(id);


--
-- Name: documents documents_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.documents
    ADD CONSTRAINT documents_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: documents documents_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.documents
    ADD CONSTRAINT documents_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.documents(id);


--
-- Name: documents documents_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.documents
    ADD CONSTRAINT documents_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: guest_invitations guest_invitations_invited_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_invitations
    ADD CONSTRAINT guest_invitations_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES public.users(id);


--
-- Name: guest_invitations guest_invitations_target_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_invitations
    ADD CONSTRAINT guest_invitations_target_document_id_fkey FOREIGN KEY (target_document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: guest_invitations guest_invitations_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.guest_invitations
    ADD CONSTRAINT guest_invitations_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: password_reset_tokens password_reset_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: pop_challenges pop_challenges_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pop_challenges
    ADD CONSTRAINT pop_challenges_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;


--
-- Name: pop_challenges pop_challenges_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pop_challenges
    ADD CONSTRAINT pop_challenges_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: public_documents public_documents_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_documents
    ADD CONSTRAINT public_documents_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: public_documents public_documents_published_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_documents
    ADD CONSTRAINT public_documents_published_by_fkey FOREIGN KEY (published_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: public_documents public_documents_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_documents
    ADD CONSTRAINT public_documents_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: public_slug_histories public_slug_histories_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_slug_histories
    ADD CONSTRAINT public_slug_histories_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE SET NULL;


--
-- Name: recovery_challenges recovery_challenges_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recovery_challenges
    ADD CONSTRAINT recovery_challenges_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE SET NULL;


--
-- Name: sessions sessions_device_registration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_device_registration_id_fkey FOREIGN KEY (device_registration_id) REFERENCES public.device_registrations(id) ON DELETE SET NULL;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: share_exclusions share_exclusions_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_exclusions
    ADD CONSTRAINT share_exclusions_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: share_exclusions share_exclusions_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_exclusions
    ADD CONSTRAINT share_exclusions_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.shares(id) ON DELETE CASCADE;


--
-- Name: share_keys share_keys_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_keys
    ADD CONSTRAINT share_keys_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: share_keys share_keys_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_keys
    ADD CONSTRAINT share_keys_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.shares(id) ON DELETE CASCADE;


--
-- Name: share_mounts share_mounts_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_mounts
    ADD CONSTRAINT share_mounts_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.documents(id) ON DELETE SET NULL;


--
-- Name: share_mounts share_mounts_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_mounts
    ADD CONSTRAINT share_mounts_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.shares(id) ON DELETE CASCADE;


--
-- Name: share_mounts share_mounts_target_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_mounts
    ADD CONSTRAINT share_mounts_target_document_id_fkey FOREIGN KEY (target_document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: share_mounts share_mounts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_mounts
    ADD CONSTRAINT share_mounts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: share_mounts share_mounts_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_mounts
    ADD CONSTRAINT share_mounts_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: share_participant_devices share_participant_devices_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_participant_devices
    ADD CONSTRAINT share_participant_devices_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES public.share_participant_principals(id) ON DELETE CASCADE;


--
-- Name: share_participant_devices share_participant_devices_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_participant_devices
    ADD CONSTRAINT share_participant_devices_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.shares(id) ON DELETE CASCADE;


--
-- Name: share_participant_pop_challenges share_participant_pop_challenges_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_participant_pop_challenges
    ADD CONSTRAINT share_participant_pop_challenges_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.share_participant_devices(id) ON DELETE CASCADE;


--
-- Name: share_participant_pop_challenges share_participant_pop_challenges_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_participant_pop_challenges
    ADD CONSTRAINT share_participant_pop_challenges_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.shares(id) ON DELETE CASCADE;


--
-- Name: share_participant_principals share_participant_principals_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_participant_principals
    ADD CONSTRAINT share_participant_principals_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.shares(id) ON DELETE CASCADE;


--
-- Name: share_participant_sessions share_participant_sessions_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_participant_sessions
    ADD CONSTRAINT share_participant_sessions_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.share_participant_devices(id) ON DELETE CASCADE;


--
-- Name: share_participant_sessions share_participant_sessions_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_participant_sessions
    ADD CONSTRAINT share_participant_sessions_principal_id_fkey FOREIGN KEY (principal_id) REFERENCES public.share_participant_principals(id) ON DELETE CASCADE;


--
-- Name: share_participant_sessions share_participant_sessions_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_participant_sessions
    ADD CONSTRAINT share_participant_sessions_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.shares(id) ON DELETE CASCADE;


--
-- Name: share_password_challenges share_password_challenges_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.share_password_challenges
    ADD CONSTRAINT share_password_challenges_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.shares(id) ON DELETE CASCADE;


--
-- Name: shared_document_tokens shared_document_tokens_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shared_document_tokens
    ADD CONSTRAINT shared_document_tokens_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: shared_document_tokens shared_document_tokens_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shared_document_tokens
    ADD CONSTRAINT shared_document_tokens_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.shares(id) ON DELETE CASCADE;


--
-- Name: shared_folder_tokens shared_folder_tokens_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shared_folder_tokens
    ADD CONSTRAINT shared_folder_tokens_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: shared_folder_tokens shared_folder_tokens_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shared_folder_tokens
    ADD CONSTRAINT shared_folder_tokens_share_id_fkey FOREIGN KEY (share_id) REFERENCES public.shares(id) ON DELETE CASCADE;


--
-- Name: shares shares_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shares
    ADD CONSTRAINT shares_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: shares shares_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shares
    ADD CONSTRAINT shares_document_id_fkey FOREIGN KEY (document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: shares shares_parent_share_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.shares
    ADD CONSTRAINT shares_parent_share_id_fkey FOREIGN KEY (parent_share_id) REFERENCES public.shares(id) ON DELETE CASCADE;


--
-- Name: trust_transfer_nonces trust_transfer_nonces_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trust_transfer_nonces
    ADD CONSTRAINT trust_transfer_nonces_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: trust_transfer_states trust_transfer_states_sender_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trust_transfer_states
    ADD CONSTRAINT trust_transfer_states_sender_device_id_fkey FOREIGN KEY (sender_device_id) REFERENCES public.devices(id) ON DELETE CASCADE;


--
-- Name: trust_transfer_states trust_transfer_states_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trust_transfer_states
    ADD CONSTRAINT trust_transfer_states_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_encrypted_identity_keys user_encrypted_identity_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_encrypted_identity_keys
    ADD CONSTRAINT user_encrypted_identity_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_encrypted_master_keys user_encrypted_master_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_encrypted_master_keys
    ADD CONSTRAINT user_encrypted_master_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_external_accounts user_external_accounts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_external_accounts
    ADD CONSTRAINT user_external_accounts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_identity_public_keys user_identity_public_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_identity_public_keys
    ADD CONSTRAINT user_identity_public_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_settings user_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_settings
    ADD CONSTRAINT user_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_shortcuts user_shortcuts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_shortcuts
    ADD CONSTRAINT user_shortcuts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: workspace_encrypted_keys workspace_encrypted_keys_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_encrypted_keys
    ADD CONSTRAINT workspace_encrypted_keys_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(id) ON DELETE CASCADE;


--
-- Name: workspace_encrypted_keys workspace_encrypted_keys_sender_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_encrypted_keys
    ADD CONSTRAINT workspace_encrypted_keys_sender_device_id_fkey FOREIGN KEY (sender_device_id) REFERENCES public.devices(id) ON DELETE CASCADE;


--
-- Name: workspace_encrypted_keys workspace_encrypted_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_encrypted_keys
    ADD CONSTRAINT workspace_encrypted_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: workspace_encrypted_keys workspace_encrypted_keys_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_encrypted_keys
    ADD CONSTRAINT workspace_encrypted_keys_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: workspace_guest_grants workspace_guest_grants_invite_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_guest_grants
    ADD CONSTRAINT workspace_guest_grants_invite_id_fkey FOREIGN KEY (invite_id) REFERENCES public.guest_invitations(id);


--
-- Name: workspace_guest_grants workspace_guest_grants_target_document_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_guest_grants
    ADD CONSTRAINT workspace_guest_grants_target_document_id_fkey FOREIGN KEY (target_document_id) REFERENCES public.documents(id) ON DELETE CASCADE;


--
-- Name: workspace_guest_grants workspace_guest_grants_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_guest_grants
    ADD CONSTRAINT workspace_guest_grants_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: workspace_guest_grants workspace_guest_grants_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_guest_grants
    ADD CONSTRAINT workspace_guest_grants_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: workspace_invitations workspace_invitations_invited_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_invitations
    ADD CONSTRAINT workspace_invitations_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES public.users(id);


--
-- Name: workspace_invitations workspace_invitations_role_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_invitations
    ADD CONSTRAINT workspace_invitations_role_fk FOREIGN KEY (workspace_id, role_id) REFERENCES public.workspace_roles(workspace_id, id) ON DELETE SET NULL (role_id);


--
-- Name: workspace_invitations workspace_invitations_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_invitations
    ADD CONSTRAINT workspace_invitations_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: workspace_kek_backups workspace_kek_backups_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_kek_backups
    ADD CONSTRAINT workspace_kek_backups_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: workspace_kek_backups workspace_kek_backups_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_kek_backups
    ADD CONSTRAINT workspace_kek_backups_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: workspace_member_envelopes workspace_member_envelopes_member_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_member_envelopes
    ADD CONSTRAINT workspace_member_envelopes_member_fk FOREIGN KEY (workspace_id, target_user_id) REFERENCES public.workspace_members(workspace_id, user_id) ON DELETE CASCADE;


--
-- Name: workspace_member_envelopes workspace_member_envelopes_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_member_envelopes
    ADD CONSTRAINT workspace_member_envelopes_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: workspace_members workspace_members_role_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_members
    ADD CONSTRAINT workspace_members_role_fk FOREIGN KEY (workspace_id, role_id) REFERENCES public.workspace_roles(workspace_id, id);


--
-- Name: workspace_members workspace_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_members
    ADD CONSTRAINT workspace_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: workspace_members workspace_members_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_members
    ADD CONSTRAINT workspace_members_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: workspace_role_permissions workspace_role_permissions_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_role_permissions
    ADD CONSTRAINT workspace_role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.workspace_roles(id) ON DELETE CASCADE;


--
-- Name: workspace_roles workspace_roles_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_roles
    ADD CONSTRAINT workspace_roles_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: workspace_tag_index_keys workspace_tag_index_keys_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspace_tag_index_keys
    ADD CONSTRAINT workspace_tag_index_keys_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspaces(id) ON DELETE CASCADE;


--
-- Name: workspaces workspaces_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workspaces
    ADD CONSTRAINT workspaces_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.users(id);


--
-- PostgreSQL database dump complete
--

\unrestrict MpFqZU2s1B4fsyMI3w4JiEiOKDLsLcsQkO1kCwSHDHBNsZQ5MdoT2iaTA5fMoAA

INSERT INTO public."schema_migrations" (version) VALUES (20260308000001);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000002);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000003);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000004);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000005);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000006);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000007);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000008);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000009);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000010);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000011);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000012);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000013);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000014);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000015);
INSERT INTO public."schema_migrations" (version) VALUES (20260308000016);
INSERT INTO public."schema_migrations" (version) VALUES (20260316081804);
INSERT INTO public."schema_migrations" (version) VALUES (20260316141230);
INSERT INTO public."schema_migrations" (version) VALUES (20260421000100);
INSERT INTO public."schema_migrations" (version) VALUES (20260421000200);
INSERT INTO public."schema_migrations" (version) VALUES (20260421000300);
INSERT INTO public."schema_migrations" (version) VALUES (20260422000100);
INSERT INTO public."schema_migrations" (version) VALUES (20260422000200);
INSERT INTO public."schema_migrations" (version) VALUES (20260422000300);
INSERT INTO public."schema_migrations" (version) VALUES (20260423000100);
INSERT INTO public."schema_migrations" (version) VALUES (20260423000300);
INSERT INTO public."schema_migrations" (version) VALUES (20260423000400);
INSERT INTO public."schema_migrations" (version) VALUES (20260423000500);
INSERT INTO public."schema_migrations" (version) VALUES (20260424000100);
INSERT INTO public."schema_migrations" (version) VALUES (20260501000100);
INSERT INTO public."schema_migrations" (version) VALUES (20260501000200);
