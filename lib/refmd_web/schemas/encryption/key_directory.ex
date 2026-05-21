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
      rotation_kind: %Schema{type: :string, enum: ["kek"]},
      scope_kind: %Schema{type: :string, enum: ["workspace"]},
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
      rotation_kind: %Schema{type: :string, enum: ["kek"]},
      scope_kind: %Schema{type: :string, enum: ["workspace"]},
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

defmodule RefMDWeb.Schemas.RotationDeletionEvidence do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RotationDeletionEvidence",
    type: :object,
    additionalProperties: false,
    properties: %{
      old_key_deleted_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      workspace_id: %Schema{type: :string, format: :uuid},
      rotation_kind: %Schema{type: :string},
      scope_kind: %Schema{type: :string},
      scope_id: %Schema{type: :string},
      old_key_version: %Schema{type: :integer, minimum: 1},
      deletion_manifest: RefMDWeb.Schemas.OldKeyDeletionManifest,
      device_key_deletion_proofs: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          proofs: %Schema{type: :array, items: RefMDWeb.Schemas.DeviceKeyDeletionProof}
        },
        required: [:proofs]
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
      :device_key_deletion_proofs
    ]
  })
end

defmodule RefMDWeb.Schemas.KeyDirectoryAppendRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @key_directory_envelope_schema %Schema{allOf: [RefMDWeb.Schemas.KeyDirectoryEnvelope]}

  OpenApiSpex.schema(%{
    title: "KeyDirectoryAppendRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      events: %Schema{type: :array, items: @key_directory_envelope_schema},
      checkpoint: @key_directory_envelope_schema
    },
    required: [:events, :checkpoint]
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
      :events,
      :rotation_deletion_evidences,
      :pin
    ]
  })
end
