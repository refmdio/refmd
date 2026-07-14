defmodule RefMDWeb.Schemas.KekRotationStartResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KekRotationStartResponse",
    type: :object,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      needs_kek_rotation: %Schema{type: :boolean}
    },
    required: [:workspace_id, :needs_kek_rotation]
  })
end

defmodule RefMDWeb.Schemas.KekRotationStartRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KekRotationStartRequest",
    type: :object,
    properties: %{
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [
      :workspace_key_directory_events,
      :workspace_key_directory_checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.KekRotationCompleteRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @device_key_deletion_proof_payload %Schema{
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
  }

  @device_key_deletion_proof_actor %Schema{
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

  @device_key_deletion_proof_authority %Schema{
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

  @device_key_deletion_proof_transcript %Schema{
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
      actor: @device_key_deletion_proof_actor,
      authority_boundary: @device_key_deletion_proof_authority
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
  }

  @device_key_deletion_proof %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      payload: @device_key_deletion_proof_payload,
      transcript: @device_key_deletion_proof_transcript,
      signature: RefMDWeb.Schemas.HybridSignature
    },
    required: [:payload, :transcript, :signature]
  }

  OpenApiSpex.schema(%{
    title: "KekRotationCompleteRequest",
    type: :object,
    properties: %{
      new_kek_version: %Schema{type: :integer},
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
      device_key_deletion_proofs: %Schema{
        type: :array,
        items: @device_key_deletion_proof
      },
      wipe_required_device_ids: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid}
      }
    },
    required: [
      :new_kek_version,
      :workspace_key_directory_events,
      :workspace_key_directory_checkpoint,
      :device_key_deletion_proofs,
      :wipe_required_device_ids
    ]
  })
end

defmodule RefMDWeb.Schemas.KekRotationCompletionManifestResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KekRotationCompletionManifestResponse",
    type: :object,
    properties: %{
      old_kek_version: %Schema{type: :integer},
      new_kek_version: %Schema{type: :integer},
      started_event_hash: %Schema{type: :string},
      completed_at_event_sequence: %Schema{type: :integer},
      deleted_at_event_sequence: %Schema{type: :integer},
      server_rejects_old_key_uploads_after_sequence: %Schema{type: :integer},
      completion_manifest_hash: %Schema{type: :string},
      deleted_secret_ids_hash: %Schema{type: :string},
      deleted_wrap_ids_hash: %Schema{type: :string}
    },
    required: [
      :old_kek_version,
      :new_kek_version,
      :started_event_hash,
      :completed_at_event_sequence,
      :deleted_at_event_sequence,
      :server_rejects_old_key_uploads_after_sequence,
      :completion_manifest_hash,
      :deleted_secret_ids_hash,
      :deleted_wrap_ids_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceWipeRequirementResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceWipeRequirementResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      required_kek_version: %Schema{type: :integer, minimum: 2},
      old_key_version: %Schema{type: :integer, minimum: 1},
      rotation_completed_event_hash: RefMDWeb.Schemas.Blake3Base64Url,
      deleted_secret_ids_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :workspace_id,
      :required_kek_version,
      :old_key_version,
      :rotation_completed_event_hash,
      :deleted_secret_ids_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.WorkspaceWipeAcknowledgementRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WorkspaceWipeAcknowledgementRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      device_key_deletion_proof: RefMDWeb.Schemas.DeviceKeyDeletionProof
    },
    required: [:device_key_deletion_proof]
  })
end
