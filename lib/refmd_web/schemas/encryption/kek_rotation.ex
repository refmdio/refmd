defmodule RefMDWeb.Schemas.KekRotationStartIntentRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KekRotationStartIntentRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      old_key_version: %Schema{type: :integer, minimum: 1},
      new_key_version: %Schema{type: :integer, minimum: 2},
      reason: %Schema{type: :string, enum: ["manual"]},
      rotation_id: %Schema{type: :string, format: :uuid},
      events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [
      :old_key_version,
      :new_key_version,
      :reason,
      :rotation_id,
      :events,
      :checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.PqWrapPrecommit do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PqWrapPrecommit",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.signed-pq-hybrid-wrap"]},
      protocol_version: %Schema{type: :integer, enum: [1]},
      suite_id: %Schema{type: :string},
      suite_rank: %Schema{type: :integer},
      purpose: %Schema{type: :string},
      resource: %Schema{type: :object},
      sender: %Schema{type: :object},
      recipient: %Schema{type: :object},
      event_scope: %Schema{type: :object},
      hpke: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          mode: %Schema{type: :string, enum: ["base"]},
          kem_id: %Schema{type: :integer, enum: [25_722]},
          kdf_id: %Schema{type: :integer, enum: [1]},
          aead_id: %Schema{type: :integer, enum: [3]},
          enc: %Schema{type: :string},
          ciphertext: %Schema{type: :string}
        },
        required: [:mode, :kem_id, :kdf_id, :aead_id, :enc, :ciphertext]
      }
    },
    required: [
      :protocol,
      :protocol_version,
      :suite_id,
      :suite_rank,
      :purpose,
      :resource,
      :sender,
      :recipient,
      :event_scope,
      :hpke
    ]
  })
end

defmodule RefMDWeb.Schemas.KekRotationCompletionIntentRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @device_wrap %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      target_user_id: %Schema{type: :string, format: :uuid},
      target_device_id: %Schema{type: :string, format: :uuid},
      sender_device_id: %Schema{type: :string, format: :uuid},
      wrap: RefMDWeb.Schemas.PqWrapPrecommit
    },
    required: [:target_user_id, :target_device_id, :wrap]
  }

  @member_envelope %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.workspace-member-envelope"]},
      version: %Schema{type: :integer, enum: [1]},
      workspace_id: %Schema{type: :string, format: :uuid},
      target_user_id: %Schema{type: :string, format: :uuid},
      kek_version: %Schema{type: :integer, minimum: 1},
      target_identity_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      target_identity_key_material_hash: RefMDWeb.Schemas.Blake3Base64Url,
      authorization_key_directory_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      authorization_key_directory_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      wrap: RefMDWeb.Schemas.PqWrapPrecommit
    },
    required: [
      :protocol,
      :version,
      :workspace_id,
      :target_user_id,
      :kek_version,
      :target_identity_encryption_key_id,
      :target_identity_key_material_hash,
      :authorization_key_directory_checkpoint_sequence,
      :authorization_key_directory_checkpoint_hash,
      :wrap
    ]
  }

  @invitation_update %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      invitation_id: %Schema{type: :string, format: :uuid},
      guest_invitation_id: %Schema{type: :string, format: :uuid},
      kek_version: %Schema{type: :integer, minimum: 1},
      encrypted_bootstrap_package: %Schema{type: :object},
      bootstrap_package_hash: RefMDWeb.Schemas.Blake3Base64Url,
      previous_bootstrap_package_hash: RefMDWeb.Schemas.Blake3Base64Url,
      bootstrap_package_key_maintenance_wrap: %Schema{type: :object},
      bootstrap_package_key_maintenance_wrap_hash: RefMDWeb.Schemas.Blake3Base64Url,
      key_version_context: %Schema{type: :object},
      scope_kind: %Schema{type: :string},
      scope_id: %Schema{type: :string},
      bootstrap_suite_id: %Schema{type: :string}
    },
    required: [
      :kek_version,
      :encrypted_bootstrap_package,
      :bootstrap_package_hash,
      :previous_bootstrap_package_hash,
      :bootstrap_package_key_maintenance_wrap,
      :bootstrap_package_key_maintenance_wrap_hash,
      :key_version_context,
      :bootstrap_suite_id
    ]
  }

  OpenApiSpex.schema(%{
    title: "KekRotationCompletionIntentRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      old_key_version: %Schema{type: :integer, minimum: 1},
      new_key_version: %Schema{type: :integer, minimum: 2},
      device_wrap_precommits: %Schema{type: :array, items: @device_wrap},
      member_envelope_precommits: %Schema{type: :array, items: @member_envelope},
      workspace_invitation_updates: %Schema{type: :array, items: @invitation_update},
      guest_invitation_updates: %Schema{type: :array, items: @invitation_update}
    },
    required: [
      :old_key_version,
      :new_key_version,
      :device_wrap_precommits,
      :member_envelope_precommits,
      :workspace_invitation_updates,
      :guest_invitation_updates
    ]
  })
end

defmodule RefMDWeb.Schemas.KekOldKeyDeletionIntentRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KekOldKeyDeletionIntentRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      old_key_version: %Schema{type: :integer, minimum: 1},
      deletion_manifest: RefMDWeb.Schemas.OldKeyDeletionManifest,
      device_key_deletion_proofs: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.DeviceKeyDeletionProof
      },
      wipe_required_device_ids: %Schema{
        type: :array,
        items: %Schema{type: :string, format: :uuid}
      }
    },
    required: [
      :old_key_version,
      :deletion_manifest,
      :device_key_deletion_proofs,
      :wipe_required_device_ids
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
