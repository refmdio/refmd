defmodule RefMDWeb.Schemas.DeviceApprovalProof do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceApprovalProof",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.device-approval-proof"]},
      version: %Schema{type: :integer, enum: [1]},
      approval_signature_surface: %Schema{
        type: :string,
        enum: ["genesis_device_bootstrap", "device_approval", "recovery_device_approval"]
      },
      approval_transcript_hash: RefMDWeb.Schemas.Blake3Base64Url,
      approval_transcript_owner: %Schema{type: :string},
      approval_surface_id: %Schema{type: :string},
      approval_surface_variant: %Schema{
        type: :string,
        enum: ["none"]
      },
      approving_owner_kind: %Schema{type: :string, enum: ["device", "identity"]},
      approving_owner_id: %Schema{type: :string},
      approving_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      approving_key_checkpoint_sequence: %Schema{type: :integer},
      approving_key_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      target_device_id: %Schema{type: :string},
      target_device_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      target_device_hybrid_signing_public_key_material_hash: RefMDWeb.Schemas.Blake3Base64Url,
      target_device_hybrid_encryption_public_key_material_hash: RefMDWeb.Schemas.Blake3Base64Url,
      target_device_encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      target_device_client_nonce_hash: RefMDWeb.Schemas.Blake3Base64Url,
      target_key_checkpoint_sequence: %Schema{type: :integer},
      target_key_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      surface_details: %Schema{
        oneOf: [
          %Schema{
            type: :object,
            additionalProperties: false,
            properties: %{
              kind: %Schema{type: :string, enum: ["genesis_device_bootstrap"]},
              registration_challenge_hash: RefMDWeb.Schemas.Blake3Base64Url,
              user_identity_public_key_hash: RefMDWeb.Schemas.Blake3Base64Url
            },
            required: [:kind, :registration_challenge_hash, :user_identity_public_key_hash]
          },
          %Schema{
            type: :object,
            additionalProperties: false,
            properties: %{
              kind: %Schema{type: :string, enum: ["device_approval"]},
              pending_registration_id: %Schema{type: :string},
              pending_registration_challenge_hash: RefMDWeb.Schemas.Blake3Base64Url,
              trust_transfer_delivery_commitment:
                RefMDWeb.Schemas.TrustTransferDeliveryCommitment,
              umk_distribution_delivery_commitment:
                RefMDWeb.Schemas.UmkDistributionDeliveryCommitment,
              device_approval_kek_initial_delivery_commitments: %Schema{
                type: :array,
                items: RefMDWeb.Schemas.DeviceApprovalKekInitialDeliveryCommitment
              },
              approving_device_key_directory_proof_hash: RefMDWeb.Schemas.Blake3Base64Url,
              approved_device_registration_sas_hash: RefMDWeb.Schemas.Blake3Base64Url
            },
            required: [
              :kind,
              :pending_registration_id,
              :pending_registration_challenge_hash,
              :trust_transfer_delivery_commitment,
              :umk_distribution_delivery_commitment,
              :device_approval_kek_initial_delivery_commitments,
              :approving_device_key_directory_proof_hash,
              :approved_device_registration_sas_hash
            ]
          },
          %Schema{
            type: :object,
            additionalProperties: false,
            properties: %{
              kind: %Schema{type: :string, enum: ["recovery_device_approval"]},
              pending_registration_id: %Schema{type: :string},
              pending_registration_challenge_hash: RefMDWeb.Schemas.Blake3Base64Url,
              recovery_session_transcript_hash: RefMDWeb.Schemas.Blake3Base64Url,
              recovery_capability_hash: RefMDWeb.Schemas.Blake3Base64Url,
              pending_registration_binding_hash: RefMDWeb.Schemas.Blake3Base64Url
            },
            required: [
              :kind,
              :pending_registration_id,
              :pending_registration_challenge_hash,
              :recovery_session_transcript_hash,
              :recovery_capability_hash,
              :pending_registration_binding_hash
            ]
          }
        ]
      }
    },
    required: [
      :protocol,
      :version,
      :approval_signature_surface,
      :approval_transcript_hash,
      :approval_transcript_owner,
      :approval_surface_id,
      :approval_surface_variant,
      :approving_owner_kind,
      :approving_owner_id,
      :approving_signing_key_id,
      :approving_key_checkpoint_sequence,
      :approving_key_checkpoint_hash,
      :target_device_id,
      :target_device_signing_key_id,
      :target_device_hybrid_signing_public_key_material_hash,
      :target_device_hybrid_encryption_public_key_material_hash,
      :target_device_encryption_key_id,
      :target_device_client_nonce_hash,
      :target_key_checkpoint_sequence,
      :target_key_checkpoint_hash,
      :surface_details
    ]
  })
end

defmodule RefMDWeb.Schemas.InitialKeyDeliveryCommitment do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InitialKeyDeliveryCommitment",
    oneOf: [
      %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          purpose: %Schema{type: :string, enum: ["trust_transfer"]},
          variant: %Schema{type: :string, enum: ["trust_transfer"]},
          ake_session_id: %Schema{type: :string},
          delivery_id: %Schema{type: :string},
          recipient_device_id: %Schema{type: :string},
          sender_device_id: %Schema{type: :string},
          delivery_record_hash: RefMDWeb.Schemas.Blake3Base64Url,
          key_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
          document_rollback_pin_set_hash: RefMDWeb.Schemas.Blake3Base64Url
        },
        required: [
          :purpose,
          :variant,
          :ake_session_id,
          :delivery_id,
          :recipient_device_id,
          :sender_device_id,
          :delivery_record_hash,
          :key_checkpoint_hash,
          :document_rollback_pin_set_hash
        ]
      },
      %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          purpose: %Schema{type: :string, enum: ["umk_distribution"]},
          variant: %Schema{type: :string, enum: ["umk_distribution"]},
          delivery_id: %Schema{type: :string},
          recipient_device_id: %Schema{type: :string},
          sender_device_id: %Schema{type: :string},
          delivery_record_hash: RefMDWeb.Schemas.Blake3Base64Url,
          key_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url
        },
        required: [
          :purpose,
          :variant,
          :delivery_id,
          :recipient_device_id,
          :sender_device_id,
          :delivery_record_hash,
          :key_checkpoint_hash
        ]
      },
      %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          purpose: %Schema{type: :string, enum: ["device_approval_kek_initial"]},
          variant: %Schema{type: :string, enum: ["device_approval_kek_initial"]},
          delivery_id: %Schema{type: :string},
          workspace_id: %Schema{type: :string},
          key_version: %Schema{type: :integer},
          recipient_device_id: %Schema{type: :string},
          sender_device_id: %Schema{type: :string},
          delivery_record_hash: RefMDWeb.Schemas.Blake3Base64Url,
          key_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url
        },
        required: [
          :purpose,
          :variant,
          :delivery_id,
          :workspace_id,
          :key_version,
          :recipient_device_id,
          :sender_device_id,
          :delivery_record_hash,
          :key_checkpoint_hash
        ]
      }
    ]
  })
end

defmodule RefMDWeb.Schemas.TrustTransferDeliveryCommitment do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "TrustTransferDeliveryCommitment",
    type: :object,
    additionalProperties: false,
    properties: %{
      purpose: %Schema{type: :string, enum: ["trust_transfer"]},
      variant: %Schema{type: :string, enum: ["trust_transfer"]},
      ake_session_id: %Schema{type: :string},
      delivery_id: %Schema{type: :string},
      recipient_device_id: %Schema{type: :string},
      sender_device_id: %Schema{type: :string},
      delivery_record_hash: RefMDWeb.Schemas.Blake3Base64Url,
      key_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      document_rollback_pin_set_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :purpose,
      :variant,
      :ake_session_id,
      :delivery_id,
      :recipient_device_id,
      :sender_device_id,
      :delivery_record_hash,
      :key_checkpoint_hash,
      :document_rollback_pin_set_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.UmkDistributionDeliveryCommitment do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UmkDistributionDeliveryCommitment",
    type: :object,
    additionalProperties: false,
    properties: %{
      purpose: %Schema{type: :string, enum: ["umk_distribution"]},
      variant: %Schema{type: :string, enum: ["umk_distribution"]},
      delivery_id: %Schema{type: :string},
      recipient_device_id: %Schema{type: :string},
      sender_device_id: %Schema{type: :string},
      delivery_record_hash: RefMDWeb.Schemas.Blake3Base64Url,
      key_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :purpose,
      :variant,
      :delivery_id,
      :recipient_device_id,
      :sender_device_id,
      :delivery_record_hash,
      :key_checkpoint_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.DeviceApprovalKekInitialDeliveryCommitment do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceApprovalKekInitialDeliveryCommitment",
    type: :object,
    additionalProperties: false,
    properties: %{
      purpose: %Schema{type: :string, enum: ["device_approval_kek_initial"]},
      variant: %Schema{type: :string, enum: ["device_approval_kek_initial"]},
      delivery_id: %Schema{type: :string},
      workspace_id: %Schema{type: :string},
      key_version: %Schema{type: :integer},
      recipient_device_id: %Schema{type: :string},
      sender_device_id: %Schema{type: :string},
      delivery_record_hash: RefMDWeb.Schemas.Blake3Base64Url,
      key_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :purpose,
      :variant,
      :delivery_id,
      :workspace_id,
      :key_version,
      :recipient_device_id,
      :sender_device_id,
      :delivery_record_hash,
      :key_checkpoint_hash
    ]
  })
end

defmodule RefMDWeb.Schemas.InitialKeyDeliveryArtifact do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InitialKeyDeliveryArtifact",
    type: :object,
    additionalProperties: false,
    properties: %{
      initial_ake: RefMDWeb.Schemas.InitialAkeArtifact,
      initial_key_delivery: RefMDWeb.Schemas.InitialKeyDeliveryRecord
    },
    required: [:initial_ake, :initial_key_delivery]
  })
end

defmodule RefMDWeb.Schemas.ApprovalDeliveryCommitments do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ApprovalDeliveryCommitments",
    type: :object,
    additionalProperties: false,
    properties: %{
      umk_distribution_delivery_commitment: RefMDWeb.Schemas.UmkDistributionDeliveryCommitment,
      trust_transfer_delivery_commitment: RefMDWeb.Schemas.TrustTransferDeliveryCommitment,
      device_approval_kek_initial_delivery_commitments: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.DeviceApprovalKekInitialDeliveryCommitment
      }
    },
    required: [
      :umk_distribution_delivery_commitment,
      :trust_transfer_delivery_commitment,
      :device_approval_kek_initial_delivery_commitments
    ]
  })
end

defmodule RefMDWeb.Schemas.ApprovalDeliveryArtifacts do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  @device_approval_kek_initial_delivery_entry %Schema{
    type: :object,
    additionalProperties: false,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      delivery: RefMDWeb.Schemas.InitialKeyDeliveryArtifact
    },
    required: [:workspace_id, :delivery]
  }

  OpenApiSpex.schema(%{
    title: "ApprovalDeliveryArtifacts",
    type: :object,
    additionalProperties: false,
    properties: %{
      umk_distribution_initial_delivery: RefMDWeb.Schemas.InitialKeyDeliveryArtifact,
      trust_transfer_initial_delivery: RefMDWeb.Schemas.InitialKeyDeliveryArtifact,
      device_approval_kek_initial_deliveries: %Schema{
        type: :array,
        items: @device_approval_kek_initial_delivery_entry
      }
    },
    required: [
      :umk_distribution_initial_delivery,
      :trust_transfer_initial_delivery,
      :device_approval_kek_initial_deliveries
    ]
  })
end
