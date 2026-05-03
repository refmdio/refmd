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
      signing_public_key: %Schema{type: :string},
      ecdh_public_key: %Schema{type: :string},
      identity_signature: %Schema{type: :string},
      client_nonce: %Schema{type: :string},
      revoked_at: %Schema{type: :string, format: :"date-time", nullable: true},
      created_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :device_id,
      :signing_public_key,
      :ecdh_public_key,
      :identity_signature,
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
