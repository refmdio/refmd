defmodule RefMDWeb.Schemas.RecoverableIdentitySecretRecord do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RecoverableIdentitySecretRecord",
    type: :object,
    additionalProperties: false,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      user_id: %Schema{type: :string, format: :uuid},
      identity_key_epoch: %Schema{type: :integer, minimum: 1},
      previous_record_hash: %Schema{type: :string},
      encrypted_identity_hybrid_signing_private_key_material: RefMDWeb.Schemas.Base64UrlBytes,
      identity_hybrid_signing_private_key_material_nonce: RefMDWeb.Schemas.Base64UrlBytes,
      encrypted_identity_hybrid_encryption_private_key_material: RefMDWeb.Schemas.Base64UrlBytes,
      identity_hybrid_encryption_private_key_material_nonce: RefMDWeb.Schemas.Base64UrlBytes,
      signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      encryption_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      signing_material_aad_hash: RefMDWeb.Schemas.Blake3Base64Url,
      encryption_material_aad_hash: RefMDWeb.Schemas.Blake3Base64Url,
      record_hash: RefMDWeb.Schemas.Blake3Base64Url,
      is_current: %Schema{type: :boolean}
    },
    required: [
      :id,
      :user_id,
      :identity_key_epoch,
      :previous_record_hash,
      :encrypted_identity_hybrid_signing_private_key_material,
      :identity_hybrid_signing_private_key_material_nonce,
      :encrypted_identity_hybrid_encryption_private_key_material,
      :identity_hybrid_encryption_private_key_material_nonce,
      :signing_key_id,
      :encryption_key_id,
      :signing_material_aad_hash,
      :encryption_material_aad_hash,
      :record_hash,
      :is_current
    ]
  })
end
