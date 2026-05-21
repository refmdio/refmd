defmodule RefMDWeb.Schemas.CreateDocumentKeyRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateDocumentKeyRequest",
    type: :object,
    properties: %{
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string},
      key_version: %Schema{type: :integer, minimum: 1},
      kek_version: %Schema{type: :integer, minimum: 1}
    },
    required: [:encrypted_dek, :nonce, :key_version, :kek_version]
  })
end

defmodule RefMDWeb.Schemas.DocumentKeyResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentKeyResponse",
    type: :object,
    properties: %{
      document_id: %Schema{type: :string, format: :uuid},
      key_version: %Schema{type: :integer},
      encrypted_dek: %Schema{type: :string},
      nonce: %Schema{type: :string},
      kek_version: %Schema{type: :integer},
      is_active: %Schema{type: :boolean},
      created_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :document_id,
      :key_version,
      :encrypted_dek,
      :nonce,
      :kek_version,
      :is_active,
      :created_at
    ]
  })
end

defmodule RefMDWeb.Schemas.DocumentKeysResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentKeysResponse",
    type: :object,
    properties: %{
      keys: %OpenApiSpex.Schema{
        type: :array,
        items: RefMDWeb.Schemas.DocumentKeyResponse
      }
    },
    required: [:keys]
  })
end
