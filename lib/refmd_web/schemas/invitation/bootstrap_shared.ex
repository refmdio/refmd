defmodule RefMDWeb.Schemas.InvitationBootstrapCiphertext do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationBootstrapCiphertext",
    type: :object,
    additionalProperties: false,
    properties: %{
      nonce: %Schema{type: :string},
      ciphertext: %Schema{type: :string}
    },
    required: [:nonce, :ciphertext]
  })
end

defmodule RefMDWeb.Schemas.InvitationKnownRecipientWrap do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationKnownRecipientWrap",
    type: :object,
    additionalProperties: false,
    properties: %{
      delivery_mode: %Schema{type: :string, enum: ["known_recipient"]},
      recipient_user_id: %Schema{type: :string, format: :uuid},
      sender_signing_public_key_material: RefMDWeb.Schemas.HybridSigningPublicKeyMaterial,
      wraps: %Schema{type: :array, maxItems: 0, items: RefMDWeb.Schemas.HybridKeyWrapFields}
    },
    required: [
      :delivery_mode,
      :recipient_user_id,
      :sender_signing_public_key_material,
      :wraps
    ]
  })
end

defmodule RefMDWeb.Schemas.InvitationPackageKeyRecipientWrap do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationPackageKeyRecipientWrap",
    oneOf: [
      RefMDWeb.Schemas.InvitationBootstrapCiphertext,
      RefMDWeb.Schemas.InvitationKnownRecipientWrap
    ]
  })
end

defmodule RefMDWeb.Schemas.InvitationBootstrapMaintenanceWrap do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "InvitationBootstrapMaintenanceWrap",
    type: :object,
    additionalProperties: false,
    properties: %{
      key_version: %Schema{type: :integer, minimum: 1},
      nonce: %Schema{type: :string},
      ciphertext: %Schema{type: :string}
    },
    required: [:key_version, :nonce, :ciphertext]
  })
end
