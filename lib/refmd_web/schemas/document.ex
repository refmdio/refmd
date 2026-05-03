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
      archived_at: %Schema{type: :string, format: :"date-time", nullable: true},
      created_at: %Schema{type: :string, format: :"date-time"},
      updated_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :id,
      :workspace_id,
      :position,
      :title,
      :slug,
      :doc_type,
      :is_encrypted,
      :needs_dek_rotation,
      :min_dek_version,
      :is_published,
      :can_sync_publication,
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
      title: %Schema{type: :string},
      encrypted_title: %Schema{type: :string},
      encrypted_title_nonce: %Schema{type: :string},
      encrypted_title_key_version: %Schema{type: :integer}
    },
    required: [:workspace_id, :doc_type]
  })
end

defmodule RefMDWeb.Schemas.UpdateDocumentRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdateDocumentRequest",
    type: :object,
    properties: %{
      title: %Schema{type: :string},
      parent_id: %Schema{type: :string, format: :uuid, nullable: true},
      encrypted_title: %Schema{type: :string},
      encrypted_title_nonce: %Schema{type: :string},
      encrypted_title_key_version: %Schema{type: :integer}
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
    required: [:workspace_id, :document_id, :parent_id, :position]
  })
end
