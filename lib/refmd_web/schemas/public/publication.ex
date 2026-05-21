defmodule RefMDWeb.Schemas.CreatePublicationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "CreatePublicationRequest",
    type: :object,
    properties: %{
      slug: %Schema{type: :string, nullable: true},
      title: %Schema{type: :string},
      content: %Schema{type: :string},
      content_hash: %Schema{type: :string},
      noindex: %Schema{type: :boolean}
    },
    required: [:title, :content, :content_hash]
  })
end

defmodule RefMDWeb.Schemas.UpdatePublicationRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdatePublicationRequest",
    type: :object,
    properties: %{
      slug: %Schema{type: :string},
      noindex: %Schema{type: :boolean}
    }
  })
end

defmodule RefMDWeb.Schemas.UpdatePublicationContentRequest do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "UpdatePublicationContentRequest",
    type: :object,
    properties: %{
      title: %Schema{type: :string},
      content: %Schema{type: :string},
      content_hash: %Schema{type: :string}
    },
    required: [:title, :content, :content_hash]
  })
end

defmodule RefMDWeb.Schemas.PublicationResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PublicationResponse",
    type: :object,
    properties: %{
      document_id: %Schema{type: :string, format: :uuid},
      slug: %Schema{type: :string},
      url: %Schema{type: :string},
      noindex: %Schema{type: :boolean},
      published_at: %Schema{type: :string, format: :"date-time"},
      updated_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [:document_id, :slug, :url, :noindex, :published_at, :updated_at]
  })
end

defmodule RefMDWeb.Schemas.PublicationConflictResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PublicationConflictResponse",
    type: :object,
    properties: %{
      error: %Schema{type: :string},
      suggested_slug: %Schema{type: :string, nullable: true}
    },
    required: [:error]
  })
end

defmodule RefMDWeb.Schemas.PublicationContentResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PublicationContentResponse",
    type: :object,
    properties: %{
      updated_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [:updated_at]
  })
end

defmodule RefMDWeb.Schemas.PublicDocumentResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PublicDocumentResponse",
    type: :object,
    properties: %{
      title: %Schema{type: :string},
      content: %Schema{type: :string},
      author_slug: %Schema{type: :string},
      author_name: %Schema{type: :string},
      author_description: %Schema{type: :string, nullable: true},
      noindex: %Schema{type: :boolean},
      published_at: %Schema{type: :string, format: :"date-time"},
      updated_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [
      :title,
      :content,
      :author_slug,
      :author_name,
      :author_description,
      :noindex,
      :published_at,
      :updated_at
    ]
  })
end
