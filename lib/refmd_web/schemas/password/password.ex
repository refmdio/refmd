defmodule RefMDWeb.Schemas.PasswordSetResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PasswordSetResponse",
    type: :object,
    properties: %{
      ok: %Schema{type: :boolean},
      session_id: %Schema{type: :string, format: :uuid}
    },
    required: [:ok, :session_id]
  })
end

defmodule RefMDWeb.Schemas.PasswordSetRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PasswordSetRequest",
    type: :object,
    properties: %{
      new_auth_key: %Schema{type: :string},
      new_salt: %Schema{type: :string},
      new_encrypted_umk: %Schema{type: :string},
      new_umk_nonce: %Schema{type: :string}
    },
    required: [:new_auth_key, :new_salt, :new_encrypted_umk, :new_umk_nonce]
  })
end

defmodule RefMDWeb.Schemas.ChangePasswordRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ChangePasswordRequest",
    type: :object,
    properties: %{
      current_auth_key: %Schema{type: :string},
      new_auth_key: %Schema{type: :string},
      new_salt: %Schema{type: :string},
      new_encrypted_umk: %Schema{type: :string},
      new_umk_nonce: %Schema{type: :string}
    },
    required: [:current_auth_key, :new_auth_key, :new_salt, :new_encrypted_umk, :new_umk_nonce]
  })
end

defmodule RefMDWeb.Schemas.RegenerateRecoveryKeyRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RegenerateRecoveryKeyRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      new_recovery_encrypted_umk: %Schema{type: :string},
      new_recovery_nonce: %Schema{type: :string},
      new_recovery_authorization_public_material:
        RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
      new_recovery_authorization_key_id: %Schema{type: :string}
    },
    required: [
      :new_recovery_encrypted_umk,
      :new_recovery_nonce,
      :new_recovery_authorization_public_material,
      :new_recovery_authorization_key_id
    ]
  })
end
