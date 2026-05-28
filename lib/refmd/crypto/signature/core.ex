defmodule RefMD.Crypto.Signature.Core do
  @moduledoc false

  alias RefMD.Crypto.Hash
  alias RefMD.Crypto.JCS
  alias RefMD.Crypto.SigningSurface

  @protocol_version 1
  @suite_rank 1000
  @suite_id "refmd-v2-hybrid-signature-ed25519-mldsa65"

  @transcript_protocol "refmd.hybrid-signature-transcript"
  @transcript_label "RefMD hybrid signature transcript v1"

  @common_transcript_keys [
    "label",
    "owner_id",
    "owner_kind",
    "protocol",
    "signature_suite_id",
    "signature_suite_rank",
    "signing_purpose",
    "surface_id",
    "surface_variant",
    "transcript_owner",
    "version"
  ]
  @owner_exact_payload_keys %{
    {"pq_wrap", "none"} => [
      "actor",
      "authority_boundary",
      "subject_hashes",
      "subject_protocol",
      "subject_suite_id",
      "subject_suite_rank",
      "subject_version"
    ],
    {"key_directory_checkpoint", "device_authorized"} => [
      "authority_boundary",
      "scope",
      "signer",
      "suite_policy",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"key_directory_checkpoint", "identity_initial"} => [
      "authority_boundary",
      "scope",
      "signer",
      "suite_policy",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"key_directory_checkpoint", "identity_active"} => [
      "authority_boundary",
      "scope",
      "signer",
      "suite_policy",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"key_directory_checkpoint", "identity_rotation"} => [
      "authority_boundary",
      "scope",
      "signer",
      "suite_policy",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"key_directory_checkpoint", "workspace_initial"} => [
      "authority_boundary",
      "scope",
      "signer",
      "suite_policy",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"key_directory_checkpoint", "workspace_authorized"} => [
      "authority_boundary",
      "scope",
      "signer",
      "suite_policy",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"key_directory_checkpoint", "invitation_redeem_authority"} => [
      "authority_boundary",
      "scope",
      "signer",
      "suite_policy",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"key_directory_checkpoint", "share_participant_document_operation"} => [
      "authority_boundary",
      "scope",
      "signer",
      "suite_policy",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"workspace_pin_bootstrap", "none"} => [
      "actor",
      "authority_boundary",
      "suite_policy",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"plugin_bundle_approval", "none"} => [
      "actor",
      "approval",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"plugin_consent_event", "none"} => [
      "actor",
      "consent",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"plugin_network_proxy_request", "none"} => [
      "subject",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"device_approval", "none"} => [
      "approval_signature_surface",
      "approved_device_registration_sas_hash",
      "approving_device_key_directory_proof_hash",
      "approving_key_checkpoint_hash",
      "approving_key_checkpoint_sequence",
      "approving_owner_id",
      "approving_owner_kind",
      "approving_signing_key_id",
      "device_approval_kek_initial_delivery_commitments",
      "pending_registration_challenge_hash",
      "pending_registration_id",
      "target_device_client_nonce_hash",
      "target_device_encryption_key_id",
      "target_device_hybrid_encryption_public_key_material_hash",
      "target_device_hybrid_signing_public_key_material_hash",
      "target_device_id",
      "target_device_signing_key_id",
      "target_key_checkpoint_hash",
      "target_key_checkpoint_sequence",
      "trust_transfer_delivery_commitment",
      "umk_distribution_delivery_commitment"
    ],
    {"device_revocation", "none"} => [
      "actor",
      "authority_boundary",
      "revocation",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"genesis_device_bootstrap", "none"} => [
      "bootstrap_authority",
      "client_nonce",
      "device_encryption_key_id",
      "device_hybrid_encryption_public_key_material_hash",
      "device_id",
      "device_signing_key_id",
      "identity_signing_key_id",
      "subject_protocol",
      "subject_version",
      "user_id"
    ],
    {"pop_request", "channel_share_participant_device"} => [
      "actor",
      "challenge",
      "pop_variant",
      "resource",
      "session",
      "transport"
    ],
    {"pop_request", "channel_user_device"} => [
      "actor",
      "challenge",
      "pop_variant",
      "resource",
      "session",
      "transport"
    ],
    {"pop_request", "http_share_participant_device"} => [
      "actor",
      "challenge",
      "pop_variant",
      "request",
      "session",
      "transport"
    ],
    {"pop_request", "http_user_device"} => [
      "actor",
      "challenge",
      "pop_variant",
      "request",
      "session",
      "transport"
    ],
    {"recovery_device_approval", "none"} => [
      "approval_signature_surface",
      "approving_key_checkpoint_hash",
      "approving_key_checkpoint_sequence",
      "approving_owner_id",
      "approving_owner_kind",
      "approving_signing_key_id",
      "pending_registration_binding_hash",
      "pending_registration_challenge_hash",
      "pending_registration_id",
      "recovery_capability_hash",
      "recovery_session_transcript_hash",
      "target_device_client_nonce_hash",
      "target_device_encryption_key_id",
      "target_device_hybrid_encryption_public_key_material_hash",
      "target_device_hybrid_signing_public_key_material_hash",
      "target_device_id",
      "target_device_signing_key_id",
      "target_key_checkpoint_hash",
      "target_key_checkpoint_sequence"
    ],
    {"recovery_session", "none"} => [
      "candidate_user_checkpoint_hash",
      "candidate_user_checkpoint_sequence",
      "candidate_user_event_head_hash",
      "candidate_user_event_head_sequence",
      "owner_user_id",
      "pending_registration_binding_hash",
      "pending_registration_id",
      "recipient_device_id",
      "recovered_identity_signing_key_id",
      "recovery_authorization_key_id",
      "recovery_capability_hash",
      "recovery_session_id",
      "server_challenge_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"recovery_authorization_proof", "none"} => [
      "pending_registration_binding_hash",
      "recipient_device_id",
      "recovery_authorization_key_id",
      "server_challenge_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"recipient_bound_authorization", "none"} => [
      "actor",
      "authority_boundary",
      "freshness",
      "recipient",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"share_capability_authorization", "none"} => [
      "authorization",
      "share_state",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"share_participant_device_authorization", "none"} => [
      "capability_context_hash",
      "latest_bootstrap_event_hash",
      "participant_encryption_key_id",
      "participant_signing_key_id",
      "permission",
      "scope_id",
      "scope_kind",
      "share_created_event_hash",
      "share_id",
      "share_participant_device_id",
      "share_participant_principal_id",
      "share_session_id"
    ],
    {"responder_prekey", "none"} => [
      "freshness",
      "responder",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"initiator_ake_commitment", "none"} => [
      "ake_inputs",
      "binding",
      "initiator",
      "suite",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"initial_key_delivery", "umk_distribution"} => [
      "ake",
      "authority",
      "delivery",
      "recipient",
      "sender",
      "subject_hash",
      "subject_protocol",
      "subject_version",
      "suite"
    ],
    {"initial_key_delivery", "device_approval_kek_initial"} => [
      "ake",
      "authority",
      "delivery",
      "recipient",
      "sender",
      "subject_hash",
      "subject_protocol",
      "subject_version",
      "suite"
    ],
    {"initial_key_delivery", "trust_transfer"} => [
      "ake",
      "authority",
      "delivery",
      "recipient",
      "sender",
      "subject_hash",
      "subject_protocol",
      "subject_version",
      "suite"
    ],
    {"pin_gossip_statement", "none"} => [
      "pin_gossip",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"device_key_deletion_proof", "device_key_deletion_proof"} => [
      "actor",
      "authority_boundary",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ],
    {"device_key_deletion_proof", "identity_key_deletion_proof"} => [
      "actor",
      "authority_boundary",
      "subject_hash",
      "subject_protocol",
      "subject_version"
    ]
  }
  @collaboration_payload_keys %{
    "document_snapshot" => [
      "actor",
      "authority_boundary",
      "ciphertext_hash",
      "document_id",
      "nonce",
      "public_data",
      "snapshot_id"
    ],
    "document_update" => [
      "actor",
      "authority_boundary",
      "ciphertext_hash",
      "document_id",
      "nonce",
      "public_data"
    ],
    "editor_ephemeral" => ["actor", "authority_boundary", "session"],
    "editor_ephemeral_session" => ["actor", "authority_boundary", "session"]
  }
  @nested_owner_exact_keys %{
    {"pq_wrap", "none"} => %{
      "actor" => [
        "device_id",
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "signer_kind",
        "signing_key_id",
        "user_id"
      ],
      "authority_boundary" => [
        "covered_event_head_hash",
        "covered_event_head_sequence",
        "event_hash",
        "operation_checkpoint_hash",
        "operation_checkpoint_sequence",
        "scope_id",
        "scope_kind"
      ],
      "subject_hashes" => [
        "aad_hash",
        "hpke_info_hash",
        "resource_hash",
        "wrap_body_hash",
        "wrap_event_body_hash",
        "wrap_event_hash"
      ]
    },
    {"plugin_bundle_approval", "none"} => %{
      "actor" => [
        "device_id",
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "signer_kind",
        "signing_key_id",
        "user_id"
      ],
      "approval" => [
        "approval_epoch",
        "approver_device_id",
        "approver_user_id",
        "archive_hash",
        "bundle_hash",
        "created_at_ms",
        "document_scope_hash",
        "endpoint_hash",
        "application_scope_kind",
        "main_js_hash",
        "manifest_hash",
        "owner_scope_kind",
        "owner_workspace_id",
        "owner_user_id",
        "package_id",
        "permissions_hash",
        "plugin_id",
        "previous_approval_event_hash",
        "renderer_slots_hash",
        "resource_manifest_hash",
        "source_kind",
        "source_url_hash",
        "styles_css_hash",
        "version",
        "workspace_id"
      ]
    },
    {"plugin_consent_event", "none"} => %{
      "actor" => [
        "device_id",
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "signer_kind",
        "signing_key_id",
        "user_id"
      ],
      "consent" => [
        "bundle_hash",
        "consent_epoch",
        "decision",
        "device_id",
        "document_scope_hash",
        "endpoint_hash",
        "activation_id",
        "application_id",
        "application_scope_kind",
        "manifest_hash",
        "owner_scope_kind",
        "package_id",
        "permissions_hash",
        "plugin_id",
        "previous_event_hash",
        "resource_manifest_hash",
        "signer_device_id",
        "signer_user_id",
        "user_id",
        "version",
        "workspace_id"
      ]
    },
    {"plugin_network_proxy_request", "none"} => %{
      "subject" => [
        "endpoint",
        "protocol",
        "proxy",
        "request_id",
        "runtime",
        "target",
        "version"
      ]
    },
    {"genesis_device_bootstrap", "none"} => %{
      "bootstrap_authority" => [
        "authority_kind",
        "registration_challenge_hash",
        "user_identity_public_key_hash"
      ]
    },
    {"pop_request", "*"} => %{
      "session" => ["is_recovery", "session_id_hash", "session_kind"]
    },
    {"pop_request", "channel_share_participant_device"} => %{
      "actor" => [
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "share_id",
        "share_participant_device_id",
        "share_participant_principal_id",
        "signer_kind",
        "signing_key_id"
      ],
      "resource" => [
        "channel_event",
        "document_id",
        "event_name",
        "join_push_kind",
        "payload_hash",
        "scope_kind",
        "share_id",
        "topic"
      ],
      "session" => ["is_recovery", "session_id_hash", "session_kind", "share_id"]
    },
    {"pop_request", "channel_user_device"} => %{
      "actor" => [
        "device_id",
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "signer_kind",
        "signing_key_id",
        "user_id"
      ],
      "resource" => [
        "channel_event",
        "document_id",
        "event_name",
        "join_push_kind",
        "payload_hash",
        "scope_kind",
        "share_id",
        "topic"
      ],
      "session" => ["is_recovery", "session_id_hash", "session_kind"]
    },
    {"pop_request", "http_share_participant_device"} => %{
      "actor" => [
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "share_id",
        "share_participant_device_id",
        "share_participant_principal_id",
        "signer_kind",
        "signing_key_id"
      ],
      "request" => ["body_hash", "canonical_query", "method", "path", "query_hash"],
      "session" => ["is_recovery", "session_id_hash", "session_kind", "share_id"]
    },
    {"pop_request", "http_user_device"} => %{
      "actor" => [
        "device_id",
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "signer_kind",
        "signing_key_id",
        "user_id"
      ],
      "request" => ["body_hash", "canonical_query", "method", "path", "query_hash"],
      "session" => ["is_recovery", "session_id_hash", "session_kind"]
    },
    {"key_directory_checkpoint", "*"} => %{
      "scope" => [
        "covered_event_head_hash",
        "covered_event_head_sequence",
        "checkpoint_sequence",
        "previous_checkpoint_hash",
        "scope_id",
        "scope_kind"
      ],
      "signer" => [],
      "authority_boundary" => [
        "authorizing_checkpoint_hash",
        "authorizing_checkpoint_sequence",
        "required_authority"
      ],
      "suite_policy" => [
        "allowed_suite_ids_hash",
        "min_suite_rank",
        "suite_policy_version"
      ]
    },
    {"key_directory_event", "*"} => %{
      "event" => [
        "event_body_hash",
        "event_type",
        "previous_event_hash",
        "scope_id",
        "scope_kind",
        "sequence"
      ],
      "actor" => [],
      "authority_boundary" => [
        "checkpoint_hash",
        "checkpoint_sequence",
        "required_authority",
        "scope_id",
        "scope_kind"
      ]
    },
    {"workspace_pin_bootstrap", "none"} => %{
      "actor" => [
        "device_id",
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "signer_kind",
        "signing_key_id",
        "user_id"
      ],
      "authority_boundary" => [
        "checkpoint_hash",
        "checkpoint_sequence",
        "event_head_hash",
        "event_head_sequence",
        "issuing_event_hash",
        "scope_id",
        "scope_kind"
      ],
      "suite_policy" => [
        "allowed_suite_ids_hash",
        "min_suite_rank",
        "suite_policy_version"
      ]
    },
    {"recipient_bound_authorization", "none"} => %{
      "actor" => [
        "device_id",
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "signer_kind",
        "signing_key_id",
        "user_id"
      ],
      "authority_boundary" => [
        "authorization_id",
        "context_id",
        "context_kind",
        "current_checkpoint_hash",
        "current_checkpoint_sequence",
        "current_event_head_hash",
        "current_event_head_sequence",
        "redeem_attempt_id",
        "resource_hash",
        "workspace_id",
        "workspace_pin_bootstrap_hash"
      ],
      "recipient" => [
        "encryption_key_id",
        "recipient_device_id",
        "recipient_kind",
        "recipient_principal_id"
      ],
      "freshness" => [
        "live_redeem_challenge_hash",
        "not_after_event_sequence",
        "recipient_nonce_state_hash",
        "recipient_redeem_nonce",
        "redeem_freshness_proof_hash"
      ]
    },
    {"share_capability_authorization", "none"} => %{
      "authorization" => ["token_hash", "workspace_pin_bootstrap_hash"],
      "share_state" => [
        "capability_context_hash",
        "created_event_hash",
        "latest_bootstrap_event_hash",
        "password_capability_secret_commitment",
        "password_protected",
        "permission",
        "scope_id",
        "scope_kind",
        "share_capability_secret_commitment",
        "share_id"
      ]
    },
    {"document_update", "*"} => %{
      "actor" => [
        "device_id",
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "signer_kind",
        "signing_key_id",
        "user_id"
      ],
      "authority_boundary" => [
        "document_permission_proof_hash",
        "min_dek_version",
        "write_session_counter",
        "write_session_event_hash",
        "write_session_id"
      ],
      "public_data" => [
        "authorityContextKey",
        "authorityId",
        "authorityKind",
        "authorityPermissionVersion",
        "authorityScopeId",
        "clock",
        "docId",
        "keyCheckpointHash",
        "keyCheckpointSequence",
        "keyVersion",
        "minDekVersion",
        "ownerId",
        "ownerKind",
        "refSnapshotId",
        "signingKeyId",
        "timestamp",
        "updateHash",
        "writeSessionCounter",
        "writeSessionEventHash",
        "writeSessionId"
      ]
    },
    {"document_update", "share_participant_device"} => %{
      "actor" => [
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "share_id",
        "share_participant_device_id",
        "share_participant_principal_id",
        "signer_kind",
        "signing_key_id"
      ],
      "authority_boundary" => [
        "document_permission_proof_hash",
        "min_dek_version",
        "write_session_counter",
        "write_session_event_hash",
        "write_session_id"
      ],
      "public_data" => [
        "authorityContextKey",
        "authorityId",
        "authorityKind",
        "authorityPermissionVersion",
        "authorityScopeId",
        "clock",
        "docId",
        "keyCheckpointHash",
        "keyCheckpointSequence",
        "keyVersion",
        "minDekVersion",
        "ownerId",
        "ownerKind",
        "refSnapshotId",
        "signingKeyId",
        "timestamp",
        "updateHash",
        "writeSessionCounter",
        "writeSessionEventHash",
        "writeSessionId"
      ]
    },
    {"document_snapshot", "*"} => %{
      "actor" => [
        "device_id",
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "signer_kind",
        "signing_key_id",
        "user_id"
      ],
      "authority_boundary" => [
        "admission_event_type",
        "admission_nonce",
        "document_permission_proof_hash",
        "min_dek_version",
        "previous_workspace_event_hash",
        "previous_workspace_event_sequence"
      ],
      "public_data" => [
        "authorityContextKey",
        "authorityId",
        "authorityKind",
        "authorityPermissionVersion",
        "authorityScopeId",
        "docId",
        "keyCheckpointHash",
        "keyCheckpointSequence",
        "keyVersion",
        "ownerId",
        "ownerKind",
        "parentProofHash",
        "parentSnapshotId",
        "parentSnapshotUpdateClocks",
        "signingKeyId",
        "snapshotId"
      ]
    },
    {"document_snapshot", "share_participant_device"} => %{
      "actor" => [
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "share_id",
        "share_participant_device_id",
        "share_participant_principal_id",
        "signer_kind",
        "signing_key_id"
      ],
      "authority_boundary" => [
        "admission_event_type",
        "admission_nonce",
        "document_permission_proof_hash",
        "min_dek_version",
        "previous_workspace_event_hash",
        "previous_workspace_event_sequence"
      ],
      "public_data" => [
        "authorityContextKey",
        "authorityId",
        "authorityKind",
        "authorityPermissionVersion",
        "authorityScopeId",
        "docId",
        "keyCheckpointHash",
        "keyCheckpointSequence",
        "keyVersion",
        "ownerId",
        "ownerKind",
        "parentProofHash",
        "parentSnapshotId",
        "parentSnapshotUpdateClocks",
        "signingKeyId",
        "snapshotId"
      ]
    },
    {"editor_ephemeral", "*"} => %{
      "actor" => [
        "device_id",
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "signer_kind",
        "signing_key_id",
        "user_id"
      ],
      "authority_boundary" => [
        "actor_active_proof_hash",
        "document_permission_proof_hash",
        "expires_event_sequence",
        "workspace_event_head_hash",
        "workspace_event_head_sequence"
      ],
      "session" => ["channel_id", "document_id", "message_nonce", "workspace_id"]
    },
    {"editor_ephemeral", "share_participant_device"} => %{
      "actor" => [
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "share_id",
        "share_participant_device_id",
        "share_participant_principal_id",
        "signer_kind",
        "signing_key_id"
      ],
      "authority_boundary" => [
        "actor_active_proof_hash",
        "document_permission_proof_hash",
        "expires_event_sequence",
        "workspace_event_head_hash",
        "workspace_event_head_sequence"
      ],
      "session" => ["channel_id", "document_id", "message_nonce", "workspace_id"]
    },
    {"editor_ephemeral_session", "*"} => %{
      "actor" => [
        "device_id",
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "signer_kind",
        "signing_key_id",
        "user_id"
      ],
      "authority_boundary" => [
        "actor_active_proof_hash",
        "document_permission_proof_hash",
        "workspace_event_head_hash",
        "workspace_event_head_sequence"
      ],
      "session" => [
        "channel_id",
        "counter",
        "document_id",
        "expires_event_sequence",
        "proof_direction",
        "proof_type",
        "session_id",
        "session_nonce",
        "workspace_id"
      ]
    },
    {"editor_ephemeral_session", "share_participant_device"} => %{
      "actor" => [
        "key_checkpoint_hash",
        "key_checkpoint_sequence",
        "key_scope_id",
        "key_scope_kind",
        "share_participant_device_id",
        "share_participant_principal_id",
        "signer_kind",
        "signing_key_id"
      ],
      "authority_boundary" => [
        "actor_active_proof_hash",
        "document_permission_proof_hash",
        "workspace_event_head_hash",
        "workspace_event_head_sequence"
      ],
      "session" => [
        "channel_id",
        "counter",
        "document_id",
        "expires_event_sequence",
        "proof_direction",
        "proof_type",
        "session_id",
        "session_nonce",
        "workspace_id"
      ]
    },
    {"initial_key_delivery", "*"} => %{
      "ake" => [
        "ake_transcript_hash",
        "initiator_commitment_hash",
        "operation_id",
        "purpose"
      ],
      "authority" => ["sender_authority_kind"],
      "delivery" => [
        "ciphertext_hash",
        "context_hash",
        "delivery_id",
        "payload_kind"
      ],
      "recipient" => ["device_id", "encryption_key_id", "user_id"],
      "sender" => ["device_id", "signing_key_id", "user_id"]
    }
  }

  @spec transcript_base(String.t(), map(), String.t(), String.t()) :: map()
  def transcript_base(signing_purpose, surface, owner_kind, owner_id) do
    %{
      "protocol" => @transcript_protocol,
      "label" => @transcript_label,
      "version" => @protocol_version,
      "transcript_owner" => surface.transcript_owner,
      "surface_id" => surface.surface_id,
      "surface_variant" => surface.variant,
      "signing_purpose" => signing_purpose,
      "owner_kind" => owner_kind,
      "owner_id" => owner_id,
      "signature_suite_id" => @suite_id,
      "signature_suite_rank" => @suite_rank
    }
  end

  @spec assert_transcript!(map(), String.t(), String.t(), String.t()) :: :ok
  def assert_transcript!(transcript, signing_purpose, owner_kind, owner_id)
      when is_map(transcript) do
    assert_literal!(transcript["protocol"], @transcript_protocol, "transcript_protocol_invalid")
    assert_literal!(transcript["label"], @transcript_label, "transcript_label_invalid")
    assert_protocol_version!(transcript["version"])

    unless transcript["signing_purpose"] == signing_purpose,
      do: raise(ArgumentError, "signing_purpose_mismatch")

    unless is_binary(transcript["surface_variant"]),
      do: raise(ArgumentError, "surface_variant_invalid")

    surface = SigningSurface.get_active!(signing_purpose, transcript["surface_variant"])
    SigningSurface.assert_owner_kind!(surface, owner_kind)

    unless transcript["transcript_owner"] == surface.transcript_owner,
      do: raise(ArgumentError, "transcript_owner_mismatch")

    unless transcript["surface_id"] == surface.surface_id,
      do: raise(ArgumentError, "surface_id_mismatch")

    unless transcript["surface_variant"] == surface.variant,
      do: raise(ArgumentError, "surface_variant_mismatch")

    unless transcript["owner_kind"] == owner_kind,
      do: raise(ArgumentError, "owner_kind_mismatch")

    unless transcript["owner_id"] == owner_id,
      do: raise(ArgumentError, "owner_id_mismatch")

    assert_canonical_owner_id!(owner_kind, owner_id)
    assert_suite_fields!(transcript["signature_suite_id"], transcript["signature_suite_rank"])
    assert_owner_exact_transcript_payload!(transcript, surface.signing_purpose, surface.variant)
    JCS.canonical_bytes!(transcript)
    :ok
  end

  @spec assert_positive_integer!(term(), String.t()) :: :ok
  def assert_positive_integer!(value, error) do
    unless is_integer(value) and value >= 1 do
      raise ArgumentError, error
    end

    :ok
  end

  @spec assert_non_empty_string!(term(), String.t()) :: :ok
  def assert_non_empty_string!(value, _error) when is_binary(value) and byte_size(value) > 0,
    do: :ok

  def assert_non_empty_string!(_, error), do: raise(ArgumentError, error)

  @spec assert_map!(term(), String.t()) :: :ok
  def assert_map!(value, _error) when is_map(value), do: :ok
  def assert_map!(_, error), do: raise(ArgumentError, error)

  defp assert_owner_exact_transcript_payload!(transcript, signing_purpose, variant) do
    payload_keys = owner_exact_payload_keys!(signing_purpose, variant)
    assert_exact_keys!(transcript, Enum.sort(@common_transcript_keys ++ payload_keys))
    assert_top_level_owner_exact_field_values!(transcript, payload_keys, signing_purpose, variant)

    if Map.has_key?(transcript, "subject_hash"),
      do: Hash.assert_blake3_base64url!(transcript["subject_hash"])

    if Map.has_key?(transcript, "subject_protocol"),
      do: assert_non_empty_string!(transcript["subject_protocol"], "subject_protocol_invalid")

    if Map.has_key?(transcript, "subject_version") and
         transcript["subject_version"] != @protocol_version,
       do: raise(ArgumentError, "subject_version_invalid")

    if signing_purpose == "pop_request" do
      assert_non_empty_string!(transcript["challenge"], "challenge_invalid")
    end

    assert_nested_owner_exact_fields!(transcript, signing_purpose, variant)
    :ok
  end

  defp assert_top_level_owner_exact_field_values!(
         transcript,
         payload_keys,
         signing_purpose,
         variant
       ) do
    nested_fields =
      signing_purpose
      |> nested_owner_exact_fields(variant)
      |> Map.keys()
      |> MapSet.new()

    payload_keys
    |> Enum.reject(&MapSet.member?(nested_fields, &1))
    |> Enum.each(fn key ->
      assert_top_level_owner_exact_field_value!(key, Map.fetch!(transcript, key))
    end)
  end

  defp assert_top_level_owner_exact_field_value!("subject_protocol", value),
    do: assert_non_empty_string!(value, "subject_protocol_invalid")

  defp assert_top_level_owner_exact_field_value!("subject_version", value) do
    unless value == @protocol_version, do: raise(ArgumentError, "subject_version_invalid")
  end

  defp assert_top_level_owner_exact_field_value!(key, value) do
    error = key <> "_invalid"
    assert_top_level_owner_exact_field_kind!(top_level_owner_exact_field_kind(key), value, error)
  end

  defp top_level_owner_exact_field_kind(key) do
    cond do
      key == "password_protected" ->
        :boolean

      String.ends_with?(key, "_hash") ->
        :hash

      String.ends_with?(key, "_sequence") or String.ends_with?(key, "_version") or
          String.ends_with?(key, "_rank") ->
        :positive_integer

      true ->
        :string_or_canonical
    end
  end

  defp assert_top_level_owner_exact_field_kind!(:boolean, value, error) do
    unless is_boolean(value), do: raise(ArgumentError, error)
  end

  defp assert_top_level_owner_exact_field_kind!(:hash, value, error) do
    assert_non_empty_string!(value, error)
    Hash.assert_blake3_base64url!(value)
  end

  defp assert_top_level_owner_exact_field_kind!(:positive_integer, value, error),
    do: assert_positive_integer!(value, error)

  defp assert_top_level_owner_exact_field_kind!(:string_or_canonical, value, _error)
       when is_map(value) do
    JCS.canonical_bytes!(value)
  end

  defp assert_top_level_owner_exact_field_kind!(:string_or_canonical, value, _error)
       when is_list(value) do
    JCS.canonical_bytes!(%{"value" => value})
  end

  defp assert_top_level_owner_exact_field_kind!(:string_or_canonical, value, error),
    do: assert_non_empty_string!(value, error)

  defp owner_exact_payload_keys!(signing_purpose, variant) do
    Map.get(@owner_exact_payload_keys, {signing_purpose, variant}) ||
      dynamic_owner_exact_payload_keys!(signing_purpose)
  end

  defp dynamic_owner_exact_payload_keys!(signing_purpose) do
    if signing_purpose == "key_directory_event" do
      [
        "actor",
        "authority_boundary",
        "event",
        "subject_hash",
        "subject_protocol",
        "subject_version"
      ]
    else
      case Map.fetch(@collaboration_payload_keys, signing_purpose) do
        {:ok, keys} -> keys ++ ["subject_hash", "subject_protocol", "subject_version"]
        :error -> raise(ArgumentError, "owner_exact_schema_missing")
      end
    end
  end

  defp assert_nested_owner_exact_fields!(transcript, signing_purpose, variant) do
    nested = nested_owner_exact_fields(signing_purpose, variant)

    if nested do
      Enum.each(nested, fn {field, keys} ->
        value = transcript[field]
        assert_map!(value, field <> "_invalid")
        assert_exact_keys!(value, Enum.sort(nested_expected_keys(transcript, field, value, keys)))
        assert_nested_field_values!(field, value)
      end)
    end

    :ok
  end

  defp nested_owner_exact_fields(signing_purpose, variant) do
    Map.get(@nested_owner_exact_keys, {signing_purpose, variant}) ||
      Map.get(@nested_owner_exact_keys, {signing_purpose, "*"}) ||
      %{}
  end

  defp nested_expected_keys(
         %{"surface_id" => "key_directory_checkpoint", "scope" => %{"checkpoint_sequence" => 1}},
         "scope",
         _value,
         keys
       ) do
    Enum.reject(keys, &(&1 == "previous_checkpoint_hash"))
  end

  defp nested_expected_keys(
         %{"surface_id" => "key_directory_event", "event" => %{"sequence" => 1}},
         "event",
         _value,
         keys
       ) do
    Enum.reject(keys, &(&1 == "previous_event_hash"))
  end

  defp nested_expected_keys(
         %{"surface_id" => "key_directory_event", "event" => %{"sequence" => 1}},
         "authority_boundary",
         _value,
         _keys
       ),
       do: ["required_authority"]

  defp nested_expected_keys(
         %{"surface_id" => "plugin_bundle_approval"},
         "approval",
         %{"owner_scope_kind" => "workspace"},
         keys
       ) do
    Enum.reject(keys, &(&1 == "owner_user_id"))
  end

  defp nested_expected_keys(
         %{"surface_id" => "plugin_bundle_approval"},
         "approval",
         %{"owner_scope_kind" => "user"},
         keys
       ) do
    Enum.reject(keys, &(&1 in ["application_scope_kind", "owner_workspace_id", "workspace_id"]))
  end

  defp nested_expected_keys(
         %{"surface_id" => "key_directory_checkpoint"},
         "authority_boundary",
         %{"required_authority" => "invitation_redeem_authority"},
         _keys
       ),
       do: ["invitation_id", "required_authority"]

  defp nested_expected_keys(
         %{"surface_id" => "key_directory_event"},
         "authority_boundary",
         %{"required_authority" => "invitation_redeem_authority"},
         _keys
       ),
       do: ["event_type", "invitation_id", "required_authority"]

  defp nested_expected_keys(
         %{"surface_id" => "key_directory_checkpoint", "scope" => %{"checkpoint_sequence" => 1}},
         "authority_boundary",
         _value,
         keys
       ) do
    Enum.reject(keys, &(&1 in ["authorizing_checkpoint_sequence", "authorizing_checkpoint_hash"]))
  end

  defp nested_expected_keys(%{"surface_id" => surface_id}, field, value, _keys)
       when surface_id in ["key_directory_checkpoint", "key_directory_event"] and
              field in ["signer", "actor"] do
    key_directory_signer_keys!(value)
  end

  defp nested_expected_keys(_, _, _value, keys), do: keys

  defp key_directory_signer_keys!(%{"signer_kind" => "identity"} = value),
    do:
      Enum.sort(
        key_directory_checkpoint_keys(value) ++ ["signer_kind", "signing_key_id", "user_id"]
      )

  defp key_directory_signer_keys!(%{"signer_kind" => "device"} = value),
    do:
      Enum.sort(
        key_directory_checkpoint_keys(value) ++
          ["device_id", "signer_kind", "signing_key_id", "user_id"]
      )

  defp key_directory_signer_keys!(%{"signer_kind" => "share_participant_device"} = value) do
    Enum.sort(
      key_directory_checkpoint_keys(value) ++
        [
          "share_id",
          "share_participant_device_id",
          "share_participant_principal_id",
          "signer_kind",
          "signing_key_id"
        ]
    )
  end

  defp key_directory_signer_keys!(%{"signer_kind" => "invitation_redeem_authority"} = value),
    do:
      Enum.sort(
        key_directory_checkpoint_keys(value) ++
          ["invitation_id", "signer_kind", "signing_key_id"]
      )

  defp key_directory_signer_keys!(_), do: raise(ArgumentError, "signer_kind_invalid")

  defp key_directory_checkpoint_keys(value) do
    [
      "key_scope_kind",
      "key_scope_id",
      "key_checkpoint_sequence",
      "key_checkpoint_hash",
      "authorizing_checkpoint_sequence",
      "authorizing_checkpoint_hash",
      "role_at_event"
    ]
    |> Enum.filter(&Map.has_key?(value, &1))
  end

  defp assert_nested_field_values!(field, value) do
    Enum.each(value, fn {key, nested_value} ->
      assert_nested_field_value!(field, key, nested_value)
    end)
  end

  defp assert_nested_field_value!(field, key, nested_value) do
    error = field <> "_" <> key <> "_invalid"
    field_type = nested_field_type(field, key, nested_value)

    assert_nested_field_type!(field_type, nested_value, error)
  end

  defp nested_field_type(field, "canonical_query", _) when field in ["request", "resource"],
    do: :string

  defp nested_field_type("session", "is_recovery", _), do: :boolean
  defp nested_field_type("session", "counter", _), do: :positive_integer
  defp nested_field_type("subject", "version", _), do: :positive_integer

  defp nested_field_type("subject", key, _)
       when key in ["proxy", "target", "endpoint", "runtime"],
       do: :map

  defp nested_field_type(_field, key, _) when key == "password_protected", do: :boolean
  defp nested_field_type(_field, "sequence", _), do: :positive_integer
  defp nested_field_type("public_data", key, _) when key in ["clock"], do: :non_negative_integer

  defp nested_field_type("public_data", key, _) when key in ["parentSnapshotUpdateClocks"],
    do: :map

  defp nested_field_type("public_data", key, _)
       when key in [
              "authorityPermissionVersion",
              "keyCheckpointSequence",
              "keyVersion",
              "minDekVersion",
              "writeSessionCounter",
              "timestamp"
            ],
       do: :positive_integer

  defp nested_field_type("public_data", key, _)
       when key in ["keyCheckpointHash", "updateHash"],
       do: :blake3

  defp nested_field_type(_field, "min_suite_rank", _), do: :positive_integer
  defp nested_field_type("approval", "approval_epoch", _), do: :positive_integer
  defp nested_field_type("approval", "created_at_ms", _), do: :positive_integer
  defp nested_field_type("approval", "source_url_hash", _), do: :source_url_hash
  defp nested_field_type("approval", "previous_approval_event_hash", _), do: :chain_hash
  defp nested_field_type("consent", "consent_epoch", _), do: :positive_integer
  defp nested_field_type("consent", "previous_event_hash", _), do: :chain_hash

  defp nested_field_type(_field, key, _) do
    cond do
      String.ends_with?(key, "_material") -> :map
      String.ends_with?(key, "_hash") -> :blake3
      String.ends_with?(key, "_sequence") -> :positive_integer
      String.ends_with?(key, "_counter") -> :positive_integer
      String.ends_with?(key, "_version") -> :positive_integer
      true -> :non_empty_string
    end
  end

  defp assert_nested_field_type!(:string, value, error),
    do: assert_string!(value, error)

  defp assert_nested_field_type!(:boolean, value, error) do
    unless is_boolean(value), do: raise(ArgumentError, error)
  end

  defp assert_nested_field_type!(:map, value, error) do
    assert_map!(value, error)
    JCS.canonical_bytes!(value)
  end

  defp assert_nested_field_type!(:blake3, value, error) do
    assert_non_empty_string!(value, error)
    Hash.assert_blake3_base64url!(value)
  end

  defp assert_nested_field_type!(:source_url_hash, "NO_SOURCE_URL", _error), do: :ok

  defp assert_nested_field_type!(:source_url_hash, value, error) do
    assert_non_empty_string!(value, error)
    Hash.assert_blake3_base64url!(value)
  end

  defp assert_nested_field_type!(:chain_hash, "GENESIS", _error), do: :ok

  defp assert_nested_field_type!(:chain_hash, value, error) do
    assert_non_empty_string!(value, error)
    Hash.assert_blake3_base64url!(value)
  end

  defp assert_nested_field_type!(:positive_integer, value, error),
    do: assert_positive_integer!(value, error)

  defp assert_nested_field_type!(:non_negative_integer, value, error) do
    unless is_integer(value) and value >= 0 do
      raise ArgumentError, error
    end
  end

  defp assert_nested_field_type!(:non_empty_string, value, error),
    do: assert_non_empty_string!(value, error)

  defp assert_exact_keys!(value, expected_keys) do
    if Enum.sort(Map.keys(value)) != expected_keys,
      do: raise(ArgumentError, "unexpected_keys")

    :ok
  end

  defp assert_protocol_version!(@protocol_version), do: :ok
  defp assert_protocol_version!(_), do: raise(ArgumentError, "signature_protocol_version_invalid")

  defp assert_canonical_owner_id!(owner_kind, owner_id)
       when owner_kind in [
              "identity",
              "device",
              "share_participant_device",
              "invitation_redeem_authority"
            ] do
    case Ecto.UUID.cast(owner_id) do
      {:ok, ^owner_id} -> :ok
      _ -> raise(ArgumentError, "owner_id_invalid")
    end
  end

  defp assert_canonical_owner_id!(_, _), do: :ok

  defp assert_suite_fields!(@suite_id, @suite_rank), do: :ok
  defp assert_suite_fields!(_, _), do: raise(ArgumentError, "signature_suite_invalid")

  defp assert_string!(value, _error) when is_binary(value), do: :ok
  defp assert_string!(_, error), do: raise(ArgumentError, error)

  defp assert_literal!(value, expected, _error) when value == expected, do: :ok
  defp assert_literal!(_, _, error), do: raise(ArgumentError, error)
end
