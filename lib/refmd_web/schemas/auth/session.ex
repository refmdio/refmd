defmodule RefMDWeb.Schemas.LoginRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "LoginRequest",
    type: :object,
    additionalProperties: false,
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
      encrypted_identity_hybrid_encryption_private_key_material:
        RefMDWeb.Schemas.EncryptedIdentityHybridPrivateKeyMaterial,
      identity_hybrid_encryption_private_key_material_nonce:
        RefMDWeb.Schemas.EncryptedMaterialNonce,
      identity_encryption_key_id: %Schema{type: :string},
      encrypted_identity_hybrid_signing_private_key_material:
        RefMDWeb.Schemas.EncryptedIdentityHybridPrivateKeyMaterial,
      identity_hybrid_signing_private_key_material_nonce: RefMDWeb.Schemas.EncryptedMaterialNonce,
      identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url
    },
    required: [
      :encrypted_identity_hybrid_encryption_private_key_material,
      :identity_hybrid_encryption_private_key_material_nonce,
      :identity_encryption_key_id,
      :encrypted_identity_hybrid_signing_private_key_material,
      :identity_hybrid_signing_private_key_material_nonce,
      :identity_signing_key_id
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
      target_kdf_params: RefMDWeb.Schemas.KdfParams
    },
    required: [:user, :session_id, :device_verified]
  })
end

defmodule RefMDWeb.Schemas.OAuthStartRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "OAuthStartRequest",
    type: :object,
    properties: %{
      return_to: %Schema{type: :string}
    },
    additionalProperties: false
  })
end

defmodule RefMDWeb.Schemas.OAuthStartResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "OAuthStartResponse",
    type: :object,
    properties: %{
      authorization_url: %Schema{type: :string, format: :uri}
    },
    required: [:authorization_url],
    additionalProperties: false
  })
end

defmodule RefMDWeb.Schemas.OAuthProvidersResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "OAuthProvidersResponse",
    type: :object,
    properties: %{
      providers: %Schema{
        type: :array,
        items: %Schema{type: :string, enum: ["google", "github"]},
        uniqueItems: true
      }
    },
    required: [:providers],
    additionalProperties: false
  })
end

defmodule RefMDWeb.Schemas.DbscSessionScopeRule do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DbscSessionScopeRule",
    type: :object,
    properties: %{
      type: %Schema{type: :string, enum: ["include", "exclude"]},
      domain: %Schema{type: :string},
      path: %Schema{type: :string}
    },
    required: [:type]
  })
end

defmodule RefMDWeb.Schemas.DbscSessionScope do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DbscSessionScope",
    type: :object,
    properties: %{
      origin: %Schema{type: :string, format: :uri},
      include_site: %Schema{type: :boolean},
      scope_specification: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.DbscSessionScopeRule
      }
    },
    required: [:include_site]
  })
end

defmodule RefMDWeb.Schemas.DbscSessionCredential do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DbscSessionCredential",
    type: :object,
    properties: %{
      type: %Schema{type: :string, enum: ["cookie"]},
      name: %Schema{type: :string},
      attributes: %Schema{type: :string}
    },
    required: [:type, :name]
  })
end

defmodule RefMDWeb.Schemas.DbscSessionInstructions do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DbscSessionInstructions",
    type: :object,
    properties: %{
      session_identifier: %Schema{type: :string},
      refresh_url: %Schema{type: :string},
      continue: %Schema{type: :boolean},
      scope: RefMDWeb.Schemas.DbscSessionScope,
      credentials: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.DbscSessionCredential
      },
      allowed_refresh_initiators: %Schema{type: :array, items: %Schema{type: :string}}
    },
    required: [:session_identifier, :refresh_url, :scope, :credentials]
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
      account_type: %Schema{type: :string, nullable: true},
      encryption_setup_at: %Schema{type: :string, format: :"date-time", nullable: true},
      session_id: %Schema{type: :string, format: :uuid},
      device_id: %Schema{type: :string, format: :uuid, nullable: true},
      device_verified: %Schema{type: :boolean},
      device_key_checkpoint_sequence: %Schema{type: :integer, minimum: 1, nullable: true},
      device_key_checkpoint_hash: %Schema{
        allOf: [RefMDWeb.Schemas.Blake3Base64Url],
        nullable: true
      },
      is_recovery: %Schema{type: :boolean},
      expires_at: %Schema{type: :string, format: :"date-time"},
      auth_type: %Schema{type: :string, nullable: true},
      remember_me: %Schema{type: :boolean},
      key_restore_available: %Schema{type: :boolean},
      key_restore_endpoint_ref: %Schema{type: :string, nullable: true},
      candidate_user_event_head_sequence: %Schema{type: :integer, nullable: true},
      identity_hybrid_encryption_public_key_material: %Schema{
        allOf: [RefMDWeb.Schemas.HybridEncryptionPublicKeyMaterial],
        nullable: true
      },
      identity_hybrid_signing_public_key_material: %Schema{
        allOf: [RefMDWeb.Schemas.HybridSigningPublicKeyMaterial],
        nullable: true
      }
    },
    required: [
      :user_id,
      :email,
      :name,
      :session_id,
      :device_verified,
      :expires_at,
      :key_restore_available
    ]
  })
end

defmodule RefMDWeb.Schemas.LogoutRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "LogoutRequest",
    type: :object,
    properties: %{
      clear_mount_session: %Schema{type: :boolean}
    },
    additionalProperties: false
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
