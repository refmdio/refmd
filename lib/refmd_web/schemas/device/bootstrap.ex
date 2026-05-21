defmodule RefMDWeb.Schemas.BootstrapDeviceRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "BootstrapDeviceRequest",
    type: :object,
    additionalProperties: false,
    properties: %{
      device_id: %Schema{type: :string, format: :uuid},
      name: %Schema{type: :string},
      device_type: %Schema{type: :string},
      identity_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      identity_hybrid_signing_public_key_material:
        RefMDWeb.Schemas.IdentityHybridSigningPublicKeyMaterial,
      device_hybrid_signing_public_key_material:
        RefMDWeb.Schemas.DeviceHybridSigningPublicKeyMaterial,
      device_signing_key_id: RefMDWeb.Schemas.Blake3Base64Url,
      device_hybrid_encryption_public_key_material:
        RefMDWeb.Schemas.DeviceHybridEncryptionPublicKeyMaterial,
      device_encryption_key_id: %Schema{type: :string},
      client_nonce: %Schema{type: :string},
      registration_challenge: %Schema{type: :string},
      identity_signature: RefMDWeb.Schemas.HybridSignature,
      user_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      user_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope,
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [
      :name,
      :device_id,
      :device_type,
      :identity_signing_key_id,
      :identity_hybrid_signing_public_key_material,
      :device_hybrid_signing_public_key_material,
      :device_signing_key_id,
      :device_hybrid_encryption_public_key_material,
      :device_encryption_key_id,
      :client_nonce,
      :registration_challenge,
      :identity_signature,
      :user_key_directory_events,
      :user_key_directory_checkpoint,
      :workspace_key_directory_events,
      :workspace_key_directory_checkpoint
    ]
  })
end

defmodule RefMDWeb.Schemas.RegistrationChallengeResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "RegistrationChallengeResponse",
    type: :object,
    properties: %{
      registration_challenge: %Schema{type: :string},
      expires_in_seconds: %Schema{type: :integer}
    },
    required: [:registration_challenge, :expires_in_seconds]
  })
end

defmodule RefMDWeb.Schemas.BootstrapDeviceResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "BootstrapDeviceResponse",
    type: :object,
    properties: %{
      status: %Schema{type: :string}
    },
    required: [:status]
  })
end
