defmodule RefMDWeb.Schemas.RegisterRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RegisterRequest",
    type: :object,
    additionalProperties: false,
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
      recovery_authorization_public_material:
        RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
      recovery_authorization_key_id: %Schema{type: :string},
      hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.IdentityHybridEncryptionPublicKeyMaterial,
      hybrid_signing_public_key_material: RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
      encrypted_identity_hybrid_encryption_private_key_material:
        RefMDWeb.Schemas.EncryptedIdentityHybridPrivateKeyMaterial,
      identity_hybrid_encryption_private_key_material_nonce:
        RefMDWeb.Schemas.EncryptedMaterialNonce,
      encrypted_identity_hybrid_signing_private_key_material:
        RefMDWeb.Schemas.EncryptedIdentityHybridPrivateKeyMaterial,
      identity_hybrid_signing_private_key_material_nonce: RefMDWeb.Schemas.EncryptedMaterialNonce
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
      :recovery_authorization_public_material,
      :recovery_authorization_key_id,
      :hybrid_encryption_public_key_material,
      :hybrid_signing_public_key_material,
      :encrypted_identity_hybrid_encryption_private_key_material,
      :identity_hybrid_encryption_private_key_material_nonce,
      :encrypted_identity_hybrid_signing_private_key_material,
      :identity_hybrid_signing_private_key_material_nonce
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
      workspace_owner_role_id: %Schema{type: :string, format: :uuid},
      session_id: %Schema{type: :string, format: :uuid}
    },
    required: [
      :user,
      :workspace_id,
      :workspace_owner_role_id,
      :session_id
    ]
  })
end

defmodule RefMDWeb.Schemas.OAuthCryptoSetupRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "OAuthCryptoSetupRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      recovery_encrypted_umk: %Schema{type: :string},
      recovery_nonce: %Schema{type: :string},
      recovery_authorization_public_material:
        RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
      recovery_authorization_key_id: %Schema{type: :string},
      hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.IdentityHybridEncryptionPublicKeyMaterial,
      hybrid_signing_public_key_material: RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
      encrypted_identity_hybrid_encryption_private_key_material:
        RefMDWeb.Schemas.EncryptedIdentityHybridPrivateKeyMaterial,
      identity_hybrid_encryption_private_key_material_nonce:
        RefMDWeb.Schemas.EncryptedMaterialNonce,
      encrypted_identity_hybrid_signing_private_key_material:
        RefMDWeb.Schemas.EncryptedIdentityHybridPrivateKeyMaterial,
      identity_hybrid_signing_private_key_material_nonce: RefMDWeb.Schemas.EncryptedMaterialNonce
    },
    required: [
      :recovery_encrypted_umk,
      :recovery_nonce,
      :recovery_authorization_public_material,
      :recovery_authorization_key_id,
      :hybrid_encryption_public_key_material,
      :hybrid_signing_public_key_material,
      :encrypted_identity_hybrid_encryption_private_key_material,
      :identity_hybrid_encryption_private_key_material_nonce,
      :encrypted_identity_hybrid_signing_private_key_material,
      :identity_hybrid_signing_private_key_material_nonce
    ]
  })
end

defmodule RefMDWeb.Schemas.OAuthCryptoSetupResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "OAuthCryptoSetupResponse",
    type: :object,
    properties: %{
      user: RefMDWeb.Schemas.UserInfo,
      workspace_id: %Schema{type: :string, format: :uuid},
      workspace_owner_role_id: %Schema{type: :string, format: :uuid},
      session_id: %Schema{type: :string, format: :uuid}
    },
    required: [
      :user,
      :workspace_id,
      :workspace_owner_role_id,
      :session_id
    ]
  })
end
