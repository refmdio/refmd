defmodule RefMDWeb.Schemas.VerifyKeyRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "VerifyKeyRequest",
    type: :object,
    properties: %{
      auth_key: %Schema{type: :string}
    },
    required: [:auth_key]
  })
end

defmodule RefMDWeb.Schemas.SaltResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "SaltResponse",
    type: :object,
    properties: %{
      salt: %Schema{type: :string},
      kdf_params: RefMDWeb.Schemas.KdfParams
    },
    required: [:salt, :kdf_params]
  })
end

defmodule RefMDWeb.Schemas.RegisterRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RegisterRequest",
    type: :object,
    properties: %{
      user_id: %Schema{
        type: :string,
        format: :uuid,
        description: "Client-generated UUID for AAD binding"
      },
      email: %Schema{type: :string, format: :email},
      name: %Schema{type: :string},
      auth_key: %Schema{type: :string},
      salt: %Schema{type: :string},
      encrypted_umk: %Schema{type: :string},
      umk_nonce: %Schema{type: :string},
      kdf_params: RefMDWeb.Schemas.KdfParams,
      recovery_encrypted_umk: %Schema{type: :string},
      recovery_nonce: %Schema{type: :string},
      ecdh_public_key: %Schema{type: :string},
      signing_public_key: %Schema{type: :string},
      encrypted_ecdh_private: %Schema{type: :string},
      encrypted_ecdh_private_nonce: %Schema{type: :string},
      encrypted_signing_private: %Schema{type: :string},
      encrypted_signing_private_nonce: %Schema{type: :string}
    },
    required: [
      :user_id,
      :email,
      :name,
      :auth_key,
      :salt,
      :encrypted_umk,
      :umk_nonce,
      :kdf_params,
      :recovery_encrypted_umk,
      :recovery_nonce,
      :ecdh_public_key,
      :signing_public_key,
      :encrypted_ecdh_private,
      :encrypted_ecdh_private_nonce,
      :encrypted_signing_private,
      :encrypted_signing_private_nonce
    ]
  })
end

defmodule RefMDWeb.Schemas.RegisterResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RegisterResponse",
    type: :object,
    properties: %{
      user: RefMDWeb.Schemas.UserInfo,
      workspace_id: %Schema{type: :string, format: :uuid},
      session_id: %Schema{type: :string, format: :uuid}
    },
    required: [:user, :workspace_id, :session_id]
  })
end

defmodule RefMDWeb.Schemas.LoginRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "LoginRequest",
    type: :object,
    properties: %{
      email: %Schema{type: :string, format: :email},
      auth_key: %Schema{type: :string},
      device_id: %Schema{type: :string, format: :uuid},
      remember_me: %Schema{type: :boolean}
    },
    required: [:email, :auth_key]
  })
end

defmodule RefMDWeb.Schemas.LoginKeys do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "LoginKeys",
    type: :object,
    nullable: true,
    properties: %{
      encrypted_umk: %Schema{type: :string},
      umk_nonce: %Schema{type: :string},
      encrypted_ecdh_private: %Schema{type: :string},
      encrypted_ecdh_private_nonce: %Schema{type: :string},
      encrypted_signing_private: %Schema{type: :string},
      encrypted_signing_private_nonce: %Schema{type: :string}
    },
    required: [
      :encrypted_ecdh_private,
      :encrypted_ecdh_private_nonce,
      :encrypted_signing_private,
      :encrypted_signing_private_nonce
    ]
  })
end

defmodule RefMDWeb.Schemas.LoginResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "LoginResponse",
    type: :object,
    properties: %{
      user: RefMDWeb.Schemas.UserInfo,
      session_id: %Schema{type: :string, format: :uuid},
      device_verified: %Schema{type: :boolean},
      keys: RefMDWeb.Schemas.LoginKeys,
      kdf_migration_required: %Schema{type: :boolean},
      target_kdf_params: RefMDWeb.Schemas.KdfParams,
      encrypted_umk: %Schema{type: :string},
      umk_nonce: %Schema{type: :string}
    },
    required: [:user, :session_id, :device_verified]
  })
end

defmodule RefMDWeb.Schemas.MeResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "MeResponse",
    type: :object,
    properties: %{
      user_id: %Schema{type: :string, format: :uuid},
      email: %Schema{type: :string, format: :email},
      name: %Schema{type: :string},
      encryption_setup_at: %Schema{type: :string, format: :"date-time", nullable: true},
      session_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid, nullable: true},
      device_verified: %Schema{type: :boolean},
      is_recovery: %Schema{type: :boolean},
      expires_at: %Schema{type: :string, format: :"date-time"},
      auth_type: %Schema{type: :string, nullable: true},
      remember_me: %Schema{type: :boolean},
      identity_signing_public_key: %Schema{type: :string, nullable: true},
      keys: RefMDWeb.Schemas.LoginKeys
    },
    required: [:user_id, :email, :name, :session_id, :device_verified, :expires_at]
  })
end

defmodule RefMDWeb.Schemas.KdfMigrationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "KdfMigrationRequest",
    type: :object,
    properties: %{
      new_auth_key: %Schema{type: :string},
      new_encrypted_umk: %Schema{type: :string},
      new_nonce: %Schema{type: :string},
      new_kdf_params: RefMDWeb.Schemas.KdfParams
    },
    required: [:new_auth_key, :new_encrypted_umk, :new_nonce, :new_kdf_params]
  })
end

defmodule RefMDWeb.Schemas.PopChallengeResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PopChallengeResponse",
    type: :object,
    properties: %{
      challenge: %Schema{type: :string}
    },
    required: [:challenge]
  })
end

defmodule RefMDWeb.Schemas.WsTokenResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "WsTokenResponse",
    type: :object,
    properties: %{
      token: %Schema{type: :string}
    },
    required: [:token]
  })
end
