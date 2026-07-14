defmodule RefMDWeb.Schemas.IdentityRotationPrepareRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "IdentityRotationPrepareRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.IdentityHybridEncryptionPublicKeyMaterial,
      hybrid_signing_public_key_material: RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
      encrypted_identity_hybrid_encryption_private_key_material: RefMDWeb.Schemas.Base64UrlBytes,
      identity_hybrid_encryption_private_key_material_nonce:
        RefMDWeb.Schemas.XChaCha20Poly1305Nonce,
      encrypted_identity_hybrid_signing_private_key_material: RefMDWeb.Schemas.Base64UrlBytes,
      identity_hybrid_signing_private_key_material_nonce: RefMDWeb.Schemas.XChaCha20Poly1305Nonce,
      user_key_directory_events: %Schema{
        type: :array,
        minItems: 1,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      user_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [
      :hybrid_encryption_public_key_material,
      :hybrid_signing_public_key_material,
      :encrypted_identity_hybrid_encryption_private_key_material,
      :identity_hybrid_encryption_private_key_material_nonce,
      :encrypted_identity_hybrid_signing_private_key_material,
      :identity_hybrid_signing_private_key_material_nonce,
      :user_key_directory_events,
      :user_key_directory_checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.IdentityRotationActivateRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "IdentityRotationActivateRequest",
    type: :object,
    additionalProperties: false,
    properties: %{key_version: %Schema{type: :integer, minimum: 2}},
    required: [:key_version]
  })
end

defmodule RefMDWeb.Schemas.IdentityKeyDeletionProofPayload do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "IdentityKeyDeletionProofPayload",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.identity-key-deletion-proof"]},
      version: %Schema{type: :integer, enum: [1]},
      user_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid},
      rotation_kind: %Schema{type: :string, enum: ["identity"]},
      scope_kind: %Schema{type: :string, enum: ["user"]},
      scope_id: %Schema{type: :string, format: :uuid},
      old_identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      old_identity_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      new_identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      new_identity_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      old_user_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      new_user_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      rotation_completed_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_identity_secret_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_storage_classes: %Schema{
        type: :array,
        minItems: 1,
        uniqueItems: true,
        items: %Schema{
          type: :string,
          enum: [
            "local_encrypted_key_store",
            "crypto_worker_state",
            "indexeddb_cache",
            "pending_queue",
            "offline_cache"
          ]
        }
      },
      local_cache_epoch: %Schema{type: :integer, minimum: 0},
      proof_nonce: RefMDWeb.Schemas.Base64UrlBytes
    },
    required: [
      :protocol,
      :version,
      :user_id,
      :device_id,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_identity_signing_key_id,
      :old_identity_encryption_key_id,
      :new_identity_signing_key_id,
      :new_identity_encryption_key_id,
      :old_user_checkpoint_hash,
      :new_user_checkpoint_hash,
      :rotation_completed_event_hash,
      :deleted_identity_secret_ids_hash,
      :deleted_storage_classes,
      :local_cache_epoch,
      :proof_nonce
    ]
  })
end

defmodule RefMDWeb.Schemas.IdentityKeyDeletionProofTranscript do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @actor %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer_kind: %Schema{type: :string, enum: ["device"]},
      user_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid},
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      key_scope_kind: %Schema{type: :string, enum: ["user"]},
      key_scope_id: %Schema{type: :string, format: :uuid},
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :signer_kind,
      :user_id,
      :device_id,
      :signing_key_id,
      :key_scope_kind,
      :key_scope_id,
      :key_checkpoint_sequence,
      :key_checkpoint_hash
    ]
  }

  @authority_boundary %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      scope_kind: %Schema{type: :string, enum: ["user"]},
      scope_id: %Schema{type: :string, format: :uuid},
      rotation_kind: %Schema{type: :string, enum: ["identity"]},
      old_identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      old_identity_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      new_identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      new_identity_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      old_user_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      new_user_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      rotation_completed_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_identity_secret_ids_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :scope_kind,
      :scope_id,
      :rotation_kind,
      :old_identity_signing_key_id,
      :old_identity_encryption_key_id,
      :new_identity_signing_key_id,
      :new_identity_encryption_key_id,
      :old_user_checkpoint_hash,
      :new_user_checkpoint_hash,
      :rotation_completed_event_hash,
      :deleted_identity_secret_ids_hash
    ]
  }

  OpenApiSpex.schema(%{
    title: "IdentityKeyDeletionProofTranscript",
    type: :object,
    additionalProperties: false,
    properties: %{
      label: %Schema{type: :string, enum: ["RefMD hybrid signature transcript v1"]},
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-signature-transcript"]},
      version: %Schema{type: :integer, enum: [1]},
      transcript_owner: %Schema{type: :string, enum: ["refmd.device.key_deletion.identity_key"]},
      surface_id: %Schema{type: :string, enum: ["device_key_deletion_proof"]},
      surface_variant: %Schema{type: :string, enum: ["identity_key_deletion_proof"]},
      signing_purpose: %Schema{type: :string, enum: ["device_key_deletion_proof"]},
      owner_kind: %Schema{type: :string, enum: ["device"]},
      owner_id: %Schema{type: :string, format: :uuid},
      signature_suite_id: %Schema{
        type: :string,
        enum: ["refmd-v2-hybrid-signature-ed25519-mldsa65"]
      },
      signature_suite_rank: %Schema{type: :integer, enum: [1000]},
      subject_protocol: %Schema{type: :string, enum: ["refmd.identity-key-deletion-proof"]},
      subject_version: %Schema{type: :integer, enum: [1]},
      subject_hash: RefMDWeb.Schemas.Blake3Base64Url,
      actor: @actor,
      authority_boundary: @authority_boundary
    },
    required: [
      :label,
      :protocol,
      :version,
      :transcript_owner,
      :surface_id,
      :surface_variant,
      :signing_purpose,
      :owner_kind,
      :owner_id,
      :signature_suite_id,
      :signature_suite_rank,
      :subject_protocol,
      :subject_version,
      :subject_hash,
      :actor,
      :authority_boundary
    ]
  })
end

defmodule RefMDWeb.Schemas.SignedIdentityKeyDeletionProof do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "SignedIdentityKeyDeletionProof",
    type: :object,
    additionalProperties: false,
    properties: %{
      payload: RefMDWeb.Schemas.IdentityKeyDeletionProofPayload,
      transcript: RefMDWeb.Schemas.IdentityKeyDeletionProofTranscript,
      signature: RefMDWeb.Schemas.HybridSignature
    },
    required: [:payload, :transcript, :signature]
  })
end

defmodule RefMDWeb.Schemas.IdentityRotationWorkspaceRewrap do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "IdentityRotationWorkspaceRewrap",
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      workspace_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      member_envelope_manifest_hash: RefMDWeb.Schemas.Blake3Base64Url,
      affected_member_envelope_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      new_identity_recipient_key_id: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :workspace_id,
      :workspace_checkpoint_hash,
      :member_envelope_manifest_hash,
      :affected_member_envelope_ids_hash,
      :new_identity_recipient_key_id
    ]
  })
end

defmodule RefMDWeb.Schemas.IdentityRotationRequiredWorkspaceTarget do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "IdentityRotationRequiredWorkspaceTarget",
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      key_version: %Schema{type: :integer, minimum: 1}
    },
    required: [:workspace_id, :key_version]
  })
end

defmodule RefMDWeb.Schemas.IdentityRotationCompletionManifest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "IdentityRotationCompletionManifest",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.identity-rotation-completion-manifest"]},
      version: %Schema{type: :integer, enum: [1]},
      rotation_kind: %Schema{type: :string, enum: ["identity"]},
      scope_kind: %Schema{type: :string, enum: ["user"]},
      scope_id: %Schema{type: :string, format: :uuid},
      old_identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      old_identity_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      new_identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      new_identity_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      started_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      old_user_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      new_user_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      new_user_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      old_identity_checkpoint_signature_hash: RefMDWeb.Schemas.Blake3Base64Url,
      new_identity_checkpoint_signature_hash: RefMDWeb.Schemas.Blake3Base64Url,
      workspace_rewraps: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.IdentityRotationWorkspaceRewrap
      },
      workspace_rewraps_hash: RefMDWeb.Schemas.Blake3Base64Url,
      revoked_old_identity_public_key_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      semantic_state_proof_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :protocol,
      :version,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_identity_signing_key_id,
      :old_identity_encryption_key_id,
      :new_identity_signing_key_id,
      :new_identity_encryption_key_id,
      :started_event_hash,
      :old_user_checkpoint_hash,
      :new_user_checkpoint_hash,
      :new_user_checkpoint_sequence,
      :old_identity_checkpoint_signature_hash,
      :new_identity_checkpoint_signature_hash,
      :workspace_rewraps,
      :workspace_rewraps_hash,
      :revoked_old_identity_public_key_event_hash,
      :semantic_state_proof_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.IdentityRotationDeletionManifest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "IdentityRotationDeletionManifest",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.identity-old-key-deletion-manifest"]},
      version: %Schema{type: :integer, enum: [1]},
      rotation_kind: %Schema{type: :string, enum: ["identity"]},
      scope_kind: %Schema{type: :string, enum: ["user"]},
      scope_id: %Schema{type: :string, format: :uuid},
      old_identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      old_identity_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      new_identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      rotation_completed_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_identity_secret_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      active_identity_deletion_proofs_hash: RefMDWeb.Schemas.Blake3Base64Url,
      wipe_required_device_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      server_rejects_old_identity_after_sequence: %Schema{type: :integer, minimum: 1}
    },
    required: [
      :protocol,
      :version,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_identity_signing_key_id,
      :old_identity_encryption_key_id,
      :new_identity_signing_key_id,
      :rotation_completed_event_hash,
      :deleted_identity_secret_ids_hash,
      :active_identity_deletion_proofs_hash,
      :wipe_required_device_ids_hash,
      :server_rejects_old_identity_after_sequence
    ]
  })
end

defmodule RefMDWeb.Schemas.IdentityRotationDeletionProof do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "IdentityRotationDeletionProof",
    type: :object,
    additionalProperties: false,
    properties: %{
      old_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      old_private_key_use_blocked: %Schema{type: :boolean, enum: [true]},
      old_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      old_version: %Schema{type: :integer, minimum: 1},
      persistent_identity_deletion_authorized: %Schema{type: :boolean, enum: [true]},
      successor_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      successor_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      successor_version: %Schema{type: :integer, minimum: 2},
      rotation_completed_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      completion_manifest_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deletion_manifest_hash: RefMDWeb.Schemas.Blake3Base64Url,
      completion_manifest: RefMDWeb.Schemas.IdentityRotationCompletionManifest,
      deletion_manifest: RefMDWeb.Schemas.IdentityRotationDeletionManifest,
      device_key_deletion_proofs: %Schema{
        type: :array,
        minItems: 1,
        items: RefMDWeb.Schemas.SignedIdentityKeyDeletionProof
      },
      wipe_required_device_ids: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid}
      }
    },
    required: [
      :old_encryption_key_id,
      :old_private_key_use_blocked,
      :old_signing_key_id,
      :old_version,
      :persistent_identity_deletion_authorized,
      :successor_encryption_key_id,
      :successor_signing_key_id,
      :successor_version,
      :rotation_completed_event_hash,
      :completion_manifest_hash,
      :deletion_manifest_hash,
      :completion_manifest,
      :deletion_manifest,
      :device_key_deletion_proofs,
      :wipe_required_device_ids
    ]
  })
end

defmodule RefMDWeb.Schemas.IdentityRotationFinalizeRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "IdentityRotationFinalizeRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      key_version: %Schema{type: :integer, minimum: 2},
      deletion_proof: RefMDWeb.Schemas.IdentityRotationDeletionProof,
      user_key_directory_events: %Schema{
        type: :array,
        minItems: 4,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      user_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [
      :key_version,
      :deletion_proof,
      :user_key_directory_events,
      :user_key_directory_checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.IdentityRotationStatusResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "IdentityRotationStatusResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      current_key_version: %Schema{type: :integer, nullable: true},
      current_encryption_key_id: %Schema{
        allOf: [RefMDWeb.Schemas.Blake3Base64Url],
        nullable: true
      },
      current_signing_key_id: %Schema{
        allOf: [RefMDWeb.Schemas.Blake3Base64Url],
        nullable: true
      },
      needs_rotation: %Schema{type: :boolean, nullable: true},
      rotation_due_at: %Schema{type: :string, format: :date_time, nullable: true},
      pending_key_version: %Schema{type: :integer, nullable: true},
      pending_encryption_key_id: %Schema{
        allOf: [RefMDWeb.Schemas.Blake3Base64Url],
        nullable: true
      },
      pending_signing_key_id: %Schema{allOf: [RefMDWeb.Schemas.Blake3Base64Url], nullable: true},
      finalization_started: %Schema{type: :boolean},
      pending_encrypted_identity_hybrid_encryption_private_key_material: %Schema{
        allOf: [RefMDWeb.Schemas.Base64UrlBytes],
        nullable: true
      },
      pending_identity_hybrid_encryption_private_key_material_nonce: %Schema{
        allOf: [RefMDWeb.Schemas.XChaCha20Poly1305Nonce],
        nullable: true
      },
      pending_encrypted_identity_hybrid_signing_private_key_material: %Schema{
        allOf: [RefMDWeb.Schemas.Base64UrlBytes],
        nullable: true
      },
      pending_identity_hybrid_signing_private_key_material_nonce: %Schema{
        allOf: [RefMDWeb.Schemas.XChaCha20Poly1305Nonce],
        nullable: true
      },
      required_workspace_count: %Schema{type: :integer, minimum: 0},
      required_workspace_targets: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.IdentityRotationRequiredWorkspaceTarget
      },
      covered_workspace_count: %Schema{type: :integer, minimum: 0},
      envelopes_complete: %Schema{type: :boolean},
      workspace_rewraps: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.IdentityRotationWorkspaceRewrap
      }
    },
    required: [
      :current_key_version,
      :current_encryption_key_id,
      :current_signing_key_id,
      :needs_rotation,
      :rotation_due_at,
      :pending_key_version,
      :pending_encryption_key_id,
      :pending_signing_key_id,
      :finalization_started,
      :pending_encrypted_identity_hybrid_encryption_private_key_material,
      :pending_identity_hybrid_encryption_private_key_material_nonce,
      :pending_encrypted_identity_hybrid_signing_private_key_material,
      :pending_identity_hybrid_signing_private_key_material_nonce,
      :required_workspace_count,
      :required_workspace_targets,
      :covered_workspace_count,
      :envelopes_complete,
      :workspace_rewraps
    ]
  })
end
