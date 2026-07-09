defmodule RefMDWeb.Schemas.DocumentResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentResponse",
    type: :object,
    properties: %{
      id: %Schema{type: :string, format: :uuid},
      workspace_id: %Schema{type: :string, format: :uuid},
      parent_id: %Schema{type: :string, format: :uuid, nullable: true},
      active_snapshot_id: %Schema{type: :string, format: :uuid, nullable: true},
      position: %Schema{type: :integer},
      title: %Schema{type: :string},
      encrypted_title: %Schema{type: :string, nullable: true},
      encrypted_title_nonce: %Schema{type: :string, nullable: true},
      encrypted_title_key_version: %Schema{type: :integer, nullable: true},
      slug: %Schema{type: :string},
      path: %Schema{type: :string, nullable: true},
      doc_type: %Schema{type: :string, enum: ["document", "folder"]},
      is_encrypted: %Schema{type: :boolean},
      needs_dek_rotation: %Schema{type: :boolean},
      needs_rotation_snapshot: %Schema{type: :boolean},
      min_dek_version: %Schema{type: :integer},
      is_published: %Schema{type: :boolean},
      can_sync_publication: %Schema{type: :boolean},
      created_by: %Schema{type: :string, format: :uuid, nullable: true},
      write_state: %Schema{
        type: :string,
        enum: ["writable", "read_only", "archived", "write_disabled"]
      },
      archived_at: %Schema{type: :string, format: :"date-time", nullable: true},
      created_at: %Schema{type: :string, format: :"date-time"},
      updated_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :id,
      :workspace_id,
      :active_snapshot_id,
      :position,
      :title,
      :slug,
      :doc_type,
      :is_encrypted,
      :needs_dek_rotation,
      :min_dek_version,
      :is_published,
      :can_sync_publication,
      :write_state,
      :created_at,
      :updated_at
    ]
  })
end

defmodule RefMDWeb.Schemas.DocumentsListResponse do
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentsListResponse",
    type: :object,
    properties: %{
      documents: %OpenApiSpex.Schema{
        type: :array,
        items: RefMDWeb.Schemas.DocumentResponse
      }
    },
    required: [:documents]
  })
end

defmodule RefMDWeb.Schemas.CreateDocumentRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreateDocumentRequest",
    type: :object,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      id: %Schema{type: :string, format: :uuid},
      doc_type: %Schema{type: :string, enum: ["document", "folder"]},
      parent_id: %Schema{type: :string, format: :uuid, nullable: true},
      encrypted_title: %Schema{type: :string, minLength: 1},
      encrypted_title_nonce: %Schema{type: :string, minLength: 32, maxLength: 32},
      encrypted_title_key_version: %Schema{type: :integer, minimum: 1}
    },
    required: [
      :workspace_id,
      :doc_type,
      :encrypted_title,
      :encrypted_title_nonce,
      :encrypted_title_key_version
    ]
  })
end

defmodule RefMDWeb.Schemas.UpdateDocumentRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdateDocumentRequest",
    type: :object,
    properties: %{
      parent_id: %Schema{type: :string, format: :uuid, nullable: true},
      encrypted_title: %Schema{type: :string, minLength: 1},
      encrypted_title_nonce: %Schema{type: :string, minLength: 32, maxLength: 32},
      encrypted_title_key_version: %Schema{type: :integer, minimum: 1}
    }
  })
end

defmodule RefMDWeb.Schemas.ReorderDocumentRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "ReorderDocumentRequest",
    type: :object,
    properties: %{
      workspace_id: %Schema{type: :string, format: :uuid},
      document_id: %Schema{type: :string, format: :uuid},
      parent_id: %Schema{type: :string, format: :uuid, nullable: true},
      position: %Schema{type: :integer, minimum: 0}
    },
    required: [:workspace_id, :document_id, :position]
  })
end

defmodule RefMDWeb.Schemas.DocumentWriteStateRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "DocumentWriteStateRequest",
    type: :object,
    properties: %{
      workspace_key_directory_events: %Schema{
        type: :array,
        items: RefMDWeb.Schemas.KeyDirectoryEnvelope
      },
      workspace_key_directory_checkpoint: RefMDWeb.Schemas.KeyDirectoryEnvelope
    },
    required: [:workspace_key_directory_events, :workspace_key_directory_checkpoint]
  })
end
