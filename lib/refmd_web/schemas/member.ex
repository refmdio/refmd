defmodule RefMDWeb.Schemas.MemberInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberInfo",
    type: :object,
    properties: %{
      user_id: %Schema{type: :string, format: :uuid},
      email: %Schema{type: :string, format: :email},
      name: %Schema{type: :string},
      role_id: %Schema{type: :string, format: :uuid},
      role_name: %Schema{type: :string},
      base_role: %Schema{type: :string, enum: ["owner", "admin", "editor", "viewer", "guest"]},
      is_default: %Schema{type: :boolean},
      joined_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [:user_id, :email, :name, :role_id, :role_name, :base_role, :joined_at]
  })
end

defmodule RefMDWeb.Schemas.MembersListResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MembersListResponse",
    type: :object,
    properties: %{
      members: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.MemberInfo}
    },
    required: [:members]
  })
end

defmodule RefMDWeb.Schemas.MemberDeviceInfo do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberDeviceInfo",
    type: :object,
    properties: %{
      device_id: %Schema{type: :string, format: :uuid},
      hybrid_signing_public_key_material: RefMDWeb.Schemas.HybridSigningPublicKeyMaterial,
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      hybrid_encryption_public_key_material: RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial,
      encryption_key_id: %Schema{type: :string},
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
      client_nonce: %Schema{type: :string},
      revoked_at: %Schema{type: :string, format: :"date-time", nullable: true},
      created_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :device_id,
      :hybrid_signing_public_key_material,
      :signing_key_id,
      :hybrid_encryption_public_key_material,
      :encryption_key_id,
      :approval_signature,
      :approval_signature_surface,
      :approval_proof,
      :client_nonce,
      :created_at
    ]
  })
end

defmodule RefMDWeb.Schemas.MemberDevicesResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MemberDevicesResponse",
    type: :object,
    properties: %{
      devices: %OpenApiSpex.Schema{type: :array, items: RefMDWeb.Schemas.MemberDeviceInfo}
    },
    required: [:devices]
  })
end

defmodule RefMDWeb.Schemas.ChangeMemberRoleRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ChangeMemberRoleRequest",
    type: :object,
    properties: %{
      role_id: %Schema{type: :string, format: :uuid}
    },
    required: [:role_id]
  })
end

defmodule RefMDWeb.Schemas.RemoveMemberRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RemoveMemberRequest",
    type: :object,
    properties: %{
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [:workspace_key_directory_events, :workspace_key_directory_checkpoint]
  })
end
