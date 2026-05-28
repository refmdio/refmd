defmodule RefMDWeb.Schemas.PluginStorageWriteRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PluginStorageWriteRequest",
    type: :object,
    properties: %{
      plugin_id: %Schema{type: :string, minLength: 1},
      ciphertext: %Schema{type: :string, minLength: 1},
      nonce: %Schema{type: :string, minLength: 1},
      key_version: %Schema{type: :integer, minimum: 1}
    },
    required: [:plugin_id, :ciphertext, :nonce, :key_version]
  })
end

defmodule RefMDWeb.Schemas.PluginStorageEntryResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PluginStorageEntryResponse",
    type: :object,
    properties: %{
      plugin_id: %Schema{type: :string},
      application_id: %Schema{type: :string, format: :uuid},
      activation_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      surface: %Schema{type: :string, enum: ["workspace", "document"]},
      scope_id: %Schema{type: :string},
      key: %Schema{type: :string},
      ciphertext: %Schema{type: :string},
      nonce: %Schema{type: :string},
      key_version: %Schema{type: :integer}
    },
    required: [
      :plugin_id,
      :application_id,
      :activation_id,
      :workspace_id,
      :surface,
      :scope_id,
      :key,
      :ciphertext,
      :nonce,
      :key_version
    ]
  })
end

defmodule RefMDWeb.Schemas.PluginRecordWriteRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PluginRecordWriteRequest",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      plugin_id: %Schema{type: :string, minLength: 1},
      kind: %Schema{type: :string, minLength: 1},
      encrypted_data: %Schema{type: :string, minLength: 1},
      nonce: %Schema{type: :string, minLength: 1},
      key_version: %Schema{type: :integer, minimum: 1}
    },
    required: [:id, :plugin_id, :kind, :encrypted_data, :nonce, :key_version]
  })
end

defmodule RefMDWeb.Schemas.PluginRecordResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PluginRecordResponse",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      plugin_id: %Schema{type: :string},
      application_id: %Schema{type: :string, format: :uuid},
      activation_id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      surface: %Schema{type: :string, enum: ["workspace", "document"]},
      scope_id: %Schema{type: :string},
      kind: %Schema{type: :string},
      encrypted_data: %Schema{type: :string},
      nonce: %Schema{type: :string},
      key_version: %Schema{type: :integer}
    },
    required: [
      :id,
      :plugin_id,
      :application_id,
      :activation_id,
      :workspace_id,
      :surface,
      :scope_id,
      :kind,
      :encrypted_data,
      :nonce,
      :key_version
    ]
  })
end
