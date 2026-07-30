defmodule RefMDWeb.Schemas.RegisterRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RegisterRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      protocol: %Schema{type: :string, enum: ["refmd.password-account-registration"]},
      version: %Schema{type: :integer, enum: [1]},
      reserved_user_id: %Schema{type: :string, format: :uuid},
      email: %Schema{type: :string, format: :email},
      display_name: %Schema{type: :string},
      auth_key_b64u: %Schema{type: :string},
      salt_b64u: %Schema{type: :string},
      kdf_type: %Schema{type: :string, enum: ["argon2id"]},
      kdf_params: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          memory_kib: %Schema{type: :integer, minimum: 1},
          iterations: %Schema{type: :integer, minimum: 1},
          parallelism: %Schema{type: :integer, minimum: 1}
        },
        required: [:memory_kib, :iterations, :parallelism]
      }
    },
    required: [
      :protocol,
      :version,
      :reserved_user_id,
      :email,
      :display_name,
      :auth_key_b64u,
      :salt_b64u,
      :kdf_type,
      :kdf_params
    ]
  })
end

defmodule RefMDWeb.Schemas.RegisterResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RegisterResponse",
    type: :object,
    additionalProperties: false,
    properties: %{
      bootstrap_required: %Schema{type: :boolean, enum: [true]},
      registration_id: %Schema{type: :string, format: :uuid},
      reserved_user_id: %Schema{type: :string, format: :uuid},
      reserved_workspace_id: %Schema{type: :string, format: :uuid},
      reserved_workspace_role_ids: %Schema{
        type: :object,
        additionalProperties: false,
        properties: %{
          owner: %Schema{type: :string, format: :uuid},
          admin: %Schema{type: :string, format: :uuid},
          editor: %Schema{type: :string, format: :uuid},
          viewer: %Schema{type: :string, format: :uuid}
        },
        required: [:owner, :admin, :editor, :viewer]
      },
      expires_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :bootstrap_required,
      :registration_id,
      :reserved_user_id,
      :reserved_workspace_id,
      :reserved_workspace_role_ids,
      :expires_at
    ]
  })
end
