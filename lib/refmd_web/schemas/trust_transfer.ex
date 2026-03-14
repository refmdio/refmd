defmodule RefMDWeb.Schemas.TrustTransferNonceRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "TrustTransferNonceRequest",
    type: :object,
    properties: %{
      device_id: %Schema{type: :string, format: :uuid}
    },
    required: [:device_id]
  })
end

defmodule RefMDWeb.Schemas.TrustTransferNonceResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "TrustTransferNonceResponse",
    type: :object,
    properties: %{
      nonce: %Schema{type: :string},
      expires_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [:nonce, :expires_at]
  })
end

defmodule RefMDWeb.Schemas.TrustTransferSendRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "TrustTransferSendRequest",
    type: :object,
    properties: %{
      target_device_id: %Schema{type: :string, format: :uuid},
      transfer_nonce: %Schema{type: :string},
      ciphertext: %Schema{type: :string},
      nonce: %Schema{type: :string},
      signature: %Schema{type: :string}
    },
    required: [:target_device_id, :transfer_nonce, :ciphertext, :nonce, :signature]
  })
end

defmodule RefMDWeb.Schemas.TrustTransferRetrieveRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "TrustTransferRetrieveRequest",
    type: :object,
    properties: %{
      device_id: %Schema{type: :string, format: :uuid}
    },
    required: [:device_id]
  })
end

defmodule RefMDWeb.Schemas.TrustTransferGetResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "TrustTransferGetResponse",
    type: :object,
    properties: %{
      sender_device_id: %Schema{type: :string, format: :uuid},
      sender_ecdh_public_key: %Schema{type: :string},
      sender_signing_public_key: %Schema{type: :string},
      ciphertext: %Schema{type: :string},
      nonce: %Schema{type: :string},
      signature: %Schema{type: :string}
    },
    required: [
      :sender_device_id,
      :sender_ecdh_public_key,
      :sender_signing_public_key,
      :ciphertext,
      :nonce,
      :signature
    ]
  })
end
