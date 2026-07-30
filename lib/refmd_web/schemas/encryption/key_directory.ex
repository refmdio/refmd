defmodule RefMDWeb.Schemas.DeviceKeyDeletionPayload do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceKeyDeletionPayload",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.device-key-deletion-proof"]},
      version: %Schema{type: :integer, enum: [1]},
      workspace_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid},
      rotation_kind: %Schema{type: :string, enum: ["kek", "dek"]},
      scope_kind: %Schema{type: :string, enum: ["workspace", "document"]},
      scope_id: %Schema{type: :string, format: :uuid},
      old_key_version: %Schema{type: :integer, minimum: 1},
      rotation_completed_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_secret_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_storage_classes: %Schema{
        type: :array,
        items: %Schema{
          type: :string,
          enum: [
            "crypto_worker_state",
            "indexeddb_cache",
            "local_encrypted_key_store",
            "offline_cache",
            "pending_queue"
          ]
        }
      },
      local_cache_epoch: %Schema{type: :integer, minimum: 0},
      proof_nonce: %Schema{type: :string}
    },
    required: [
      :protocol,
      :version,
      :workspace_id,
      :device_id,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :rotation_completed_event_hash,
      :deleted_secret_ids_hash,
      :deleted_storage_classes,
      :local_cache_epoch,
      :proof_nonce
    ]
  })
end

defmodule RefMDWeb.Schemas.DeviceKeyDeletionTranscript do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @device_key_deletion_actor %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      signer_kind: %Schema{type: :string, enum: ["workspace_device"]},
      user_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid},
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      key_scope_kind: %Schema{type: :string, enum: ["workspace"]},
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

  @device_key_deletion_authority_boundary %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      rotation_kind: %Schema{type: :string, enum: ["kek", "dek"]},
      scope_kind: %Schema{type: :string, enum: ["workspace", "document"]},
      scope_id: %Schema{type: :string, format: :uuid},
      old_key_version: %Schema{type: :integer, minimum: 1},
      rotation_completed_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_secret_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_storage_classes_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :workspace_id,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :rotation_completed_event_hash,
      :deleted_secret_ids_hash,
      :deleted_storage_classes_hash
    ]
  }

  OpenApiSpex.schema(%{
    title: "DeviceKeyDeletionTranscript",
    type: :object,
    additionalProperties: false,
    properties: %{
      label: %Schema{type: :string, enum: ["RefMD hybrid signature transcript v1"]},
      protocol: %Schema{type: :string, enum: ["refmd.hybrid-signature-transcript"]},
      version: %Schema{type: :integer, enum: [1]},
      transcript_owner: %Schema{type: :string},
      surface_id: %Schema{type: :string, enum: ["device_key_deletion_proof"]},
      surface_variant: %Schema{type: :string, enum: ["device_key_deletion_proof"]},
      signing_purpose: %Schema{type: :string, enum: ["device_key_deletion_proof"]},
      owner_kind: %Schema{type: :string, enum: ["device"]},
      owner_id: %Schema{type: :string, format: :uuid},
      signature_suite_id: %Schema{type: :string},
      signature_suite_rank: %Schema{type: :integer},
      subject_hash: RefMDWeb.Schemas.Blake3Base64Url,
      subject_protocol: %Schema{type: :string, enum: ["refmd.device-key-deletion-proof"]},
      subject_version: %Schema{type: :integer, enum: [1]},
      actor: @device_key_deletion_actor,
      authority_boundary: @device_key_deletion_authority_boundary
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
      :subject_hash,
      :subject_protocol,
      :subject_version,
      :actor,
      :authority_boundary
    ]
  })
end

defmodule RefMDWeb.Schemas.DeviceKeyDeletionProof do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceKeyDeletionProof",
    type: :object,
    additionalProperties: false,
    properties: %{
      payload: RefMDWeb.Schemas.DeviceKeyDeletionPayload,
      transcript: RefMDWeb.Schemas.DeviceKeyDeletionTranscript,
      signature: RefMDWeb.Schemas.HybridSignature
    },
    required: [:payload, :transcript, :signature]
  })
end

defmodule RefMDWeb.Schemas.OldKeyDeletionManifest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "OldKeyDeletionManifest",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.old-key-deletion-manifest"]},
      version: %Schema{type: :integer, enum: [1]},
      rotation_kind: %Schema{type: :string, enum: ["kek"]},
      scope_kind: %Schema{type: :string, enum: ["workspace"]},
      scope_id: %Schema{type: :string, format: :uuid},
      old_key_version: %Schema{type: :integer, minimum: 1},
      rotation_completed_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_secret_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_wrap_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      active_device_deletion_proofs_hash: RefMDWeb.Schemas.Blake3Base64Url,
      wipe_required_device_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      server_rejects_old_key_uploads_after_sequence: %Schema{type: :integer, minimum: 1}
    },
    required: [
      :protocol,
      :version,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :rotation_completed_event_hash,
      :deleted_secret_ids_hash,
      :deleted_wrap_ids_hash,
      :active_device_deletion_proofs_hash,
      :wipe_required_device_ids_hash,
      :server_rejects_old_key_uploads_after_sequence
    ]
  })
end

defmodule RefMDWeb.Schemas.DocumentDekRotationCompletionManifest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @new_key_record %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      recipient_kind: %Schema{type: :string, enum: ["workspace_device"]},
      recipient_id: %Schema{type: :string, format: :uuid},
      wrap_id: %Schema{type: :string},
      key_version: %Schema{type: :integer, minimum: 1},
      wrap_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [:recipient_kind, :recipient_id, :wrap_id, :key_version, :wrap_hash]
  }

  @rewritten_records %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      snapshot_id: %Schema{type: :string, format: :uuid},
      ciphertext_hash: RefMDWeb.Schemas.Blake3Base64Url,
      covered_update_start_clock: %Schema{type: :integer, minimum: 0},
      covered_update_end_clock: %Schema{type: :integer, minimum: 0},
      old_dek_update_hashes_hash: RefMDWeb.Schemas.Blake3Base64Url,
      new_dek_update_hashes_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :snapshot_id,
      :ciphertext_hash,
      :covered_update_start_clock,
      :covered_update_end_clock,
      :old_dek_update_hashes_hash,
      :new_dek_update_hashes_hash
    ]
  }

  OpenApiSpex.schema(%{
    title: "DocumentDekRotationCompletionManifest",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.rotation-completion-manifest"]},
      version: %Schema{type: :integer, enum: [1]},
      rotation_kind: %Schema{type: :string, enum: ["dek"]},
      scope_kind: %Schema{type: :string, enum: ["document"]},
      scope_id: %Schema{type: :string, format: :uuid},
      old_key_version: %Schema{type: :integer, minimum: 1},
      new_key_version: %Schema{type: :integer, minimum: 1},
      started_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      new_key_records: %Schema{type: :array, items: @new_key_record},
      rewritten_records: @rewritten_records,
      deleted_wrap_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      semantic_state_proof_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :protocol,
      :version,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :new_key_version,
      :started_event_hash,
      :new_key_records,
      :rewritten_records,
      :deleted_wrap_ids_hash,
      :semantic_state_proof_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.DocumentDekRotationDeletionManifest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentDekRotationDeletionManifest",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.old-key-deletion-manifest"]},
      version: %Schema{type: :integer, enum: [1]},
      rotation_kind: %Schema{type: :string, enum: ["dek"]},
      scope_kind: %Schema{type: :string, enum: ["document"]},
      scope_id: %Schema{type: :string, format: :uuid},
      old_key_version: %Schema{type: :integer, minimum: 1},
      rotation_completed_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_secret_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_wrap_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      active_device_deletion_proofs_hash: RefMDWeb.Schemas.Blake3Base64Url,
      wipe_required_device_ids_hash: RefMDWeb.Schemas.Blake3Base64Url,
      server_rejects_old_key_uploads_after_sequence: %Schema{type: :integer, minimum: 1}
    },
    required: [
      :protocol,
      :version,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :rotation_completed_event_hash,
      :deleted_secret_ids_hash,
      :deleted_wrap_ids_hash,
      :active_device_deletion_proofs_hash,
      :wipe_required_device_ids_hash,
      :server_rejects_old_key_uploads_after_sequence
    ]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceRotationDeletionEvidence do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceRotationDeletionEvidence",
    type: :object,
    additionalProperties: false,
    properties: %{
      old_key_deleted_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      workspace_id: %Schema{type: :string, format: :uuid},
      rotation_kind: %Schema{type: :string, enum: ["kek"]},
      scope_kind: %Schema{type: :string, enum: ["workspace"]},
      scope_id: %Schema{type: :string, format: :uuid},
      old_key_version: %Schema{type: :integer, minimum: 1},
      deletion_manifest: RefMDWeb.Schemas.OldKeyDeletionManifest,
      device_key_deletion_proofs: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          proofs: %Schema{type: :array, items: RefMDWeb.Schemas.DeviceKeyDeletionProof}
        },
        required: [:proofs]
      },
      wipe_required_device_ids: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid}
      }
    },
    required: [
      :old_key_deleted_event_hash,
      :workspace_id,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :deletion_manifest,
      :device_key_deletion_proofs,
      :wipe_required_device_ids
    ]
  })
end

defmodule RefMDWeb.Schemas.DocumentDekRotationDeletionEvidence do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentDekRotationDeletionEvidence",
    type: :object,
    additionalProperties: false,
    properties: %{
      old_key_deleted_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      document_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      rotation_kind: %Schema{type: :string, enum: ["dek"]},
      scope_kind: %Schema{type: :string, enum: ["document"]},
      scope_id: %Schema{type: :string, format: :uuid},
      old_key_version: %Schema{type: :integer, minimum: 1},
      completion_manifest: RefMDWeb.Schemas.DocumentDekRotationCompletionManifest,
      deletion_manifest: RefMDWeb.Schemas.DocumentDekRotationDeletionManifest,
      device_key_deletion_proofs: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          proofs: %Schema{type: :array, items: RefMDWeb.Schemas.DeviceKeyDeletionProof}
        },
        required: [:proofs]
      },
      wipe_required_device_ids: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid}
      }
    },
    required: [
      :old_key_deleted_event_hash,
      :document_id,
      :workspace_id,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :completion_manifest,
      :deletion_manifest,
      :device_key_deletion_proofs,
      :wipe_required_device_ids
    ]
  })
end

defmodule RefMDWeb.Schemas.IdentityRotationDeletionEvidence do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "IdentityRotationDeletionEvidence",
    type: :object,
    additionalProperties: false,
    properties: %{
      old_key_deleted_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      user_id: %Schema{type: :string, format: :uuid},
      rotation_kind: %Schema{type: :string, enum: ["identity"]},
      scope_kind: %Schema{type: :string, enum: ["user"]},
      scope_id: %Schema{type: :string, format: :uuid},
      old_key_version: %Schema{type: :integer, minimum: 1},
      deletion_manifest: RefMDWeb.Schemas.IdentityRotationDeletionManifest,
      device_key_deletion_proofs: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          proofs: %Schema{
            type: :array,
            items: RefMDWeb.Schemas.SignedIdentityKeyDeletionProof
          }
        },
        required: [:proofs]
      },
      wipe_required_device_ids: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid}
      }
    },
    required: [
      :old_key_deleted_event_hash,
      :user_id,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :deletion_manifest,
      :device_key_deletion_proofs,
      :wipe_required_device_ids
    ]
  })
end

defmodule RefMDWeb.Schemas.RotationDeletionEvidence do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RotationDeletionEvidence",
    oneOf: [
      %Schema{allOf: [RefMDWeb.Schemas.WorkspaceRotationDeletionEvidence]},
      %Schema{allOf: [RefMDWeb.Schemas.DocumentDekRotationDeletionEvidence]},
      %Schema{allOf: [RefMDWeb.Schemas.IdentityRotationDeletionEvidence]}
    ]
  })
end

defmodule RefMDWeb.Schemas.KeyDirectoryPin do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KeyDirectoryPin",
    type: :object,
    additionalProperties: false,
    nullable: true,
    properties: %{
      scope_kind: %Schema{type: :string, enum: ["user", "workspace"]},
      scope_id: %Schema{type: :string, format: :uuid},
      checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      event_head_sequence: %Schema{type: :integer, minimum: 1},
      event_head_hash: RefMDWeb.Schemas.Blake3Base64Url,
      suite_policy_version: %Schema{type: :integer, minimum: 1},
      min_suite_rank: %Schema{type: :integer, minimum: 1},
      allowed_suite_ids_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :scope_kind,
      :scope_id,
      :checkpoint_sequence,
      :checkpoint_hash,
      :event_head_sequence,
      :event_head_hash,
      :suite_policy_version,
      :min_suite_rank,
      :allowed_suite_ids_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.LatestKeyDirectoryResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @key_directory_envelope_schema %Schema{allOf: [RefMDWeb.Schemas.KeyDirectoryEnvelope]}

  OpenApiSpex.schema(%{
    title: "LatestKeyDirectoryResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      checkpoint: @key_directory_envelope_schema,
      checkpoint_ancestry: %Schema{type: :array, items: @key_directory_envelope_schema},
      event_ancestry: %Schema{type: :array, items: @key_directory_envelope_schema},
      authority_event_ancestry: %Schema{type: :array, items: @key_directory_envelope_schema},
      events: %Schema{type: :array, items: @key_directory_envelope_schema},
      rotation_deletion_evidences: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.RotationDeletionEvidence
      },
      pin: RefMDWeb.Schemas.KeyDirectoryPin
    },
    required: [
      :checkpoint,
      :checkpoint_ancestry,
      :event_ancestry,
      :authority_event_ancestry,
      :events,
      :rotation_deletion_evidences,
      :pin
    ]
  })
end
