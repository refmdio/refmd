defmodule RefMDWeb.Schemas.DeviceInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceInfo",
    type: :object,
    additionalProperties: false,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      name: %Schema{type: :string},
      device_type: %Schema{type: :string}
    },
    required: [:id, :name, :device_type]
  })
end

defmodule RefMDWeb.Schemas.DeviceFullInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DeviceFullInfo",
    type: :object,
    additionalProperties: false,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      name: %Schema{type: :string},
      device_type: %Schema{type: :string},
      hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.DeviceHybridEncryptionPublicKeyMaterial,
      encryption_key_id: %Schema{type: :string},
      hybrid_signing_public_key_material: RefMDWeb.Schemas.DeviceHybridSigningPublicKeyMaterial,
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      client_nonce: %Schema{type: :string},
      approval_signature: RefMDWeb.Schemas.HybridSignature,
      approval_signature_surface: %Schema{
        type: :string,
        enum: ["genesis_device_bootstrap", "device_approval", "recovery_device_approval"]
      },
      approval_proof: RefMDWeb.Schemas.DeviceApprovalProof,
      approval_delivery_commitments: %Schema{
        allOf: [RefMDWeb.Schemas.ApprovalDeliveryCommitments],
        nullable: true
      },
      approval_delivery_artifacts: %Schema{
        allOf: [RefMDWeb.Schemas.ApprovalDeliveryArtifacts],
        nullable: true
      },
      key_checkpoint_sequence: %Schema{type: :integer, minimum: 1},
      key_checkpoint_hash: RefMDWeb.Schemas.Blake3Base64Url,
      last_seen_at: %Schema{type: :string, format: :"date-time"},
      created_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :id,
      :name,
      :device_type,
      :hybrid_encryption_public_key_material,
      :encryption_key_id,
      :hybrid_signing_public_key_material,
      :signing_key_id,
      :approval_signature,
      :approval_signature_surface,
      :approval_proof,
      :key_checkpoint_sequence,
      :key_checkpoint_hash,
      :client_nonce
    ]
  })
end

defmodule RefMDWeb.Schemas.DevicesResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DevicesResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      devices: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.DeviceFullInfo}
    },
    required: [:devices]
  })
end

defmodule RefMDWeb.Schemas.RenameDeviceRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RenameDeviceRequest",
    type: :object,
    properties: %{
      name: %Schema{type: :string}
    },
    required: [:name]
  })
end
