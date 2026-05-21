defmodule RefMDWeb.Schemas.PublicAuthorProfile do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PublicAuthorProfile",
    type: :object,
    properties: %{
      slug: %Schema{type: :string},
      display_name: %Schema{type: :string},
      bio: %Schema{type: :string, nullable: true}
    },
    required: [:slug, :display_name]
  })
end

defmodule RefMDWeb.Schemas.PublicAuthorDocument do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PublicAuthorDocument",
    type: :object,
    properties: %{
      slug: %Schema{type: :string},
      title: %Schema{type: :string},
      excerpt: %Schema{type: :string},
      noindex: %Schema{type: :boolean},
      published_at: %Schema{type: :string, format: :"date-time"},
      updated_at: %Schema{type: :string, format: :"date-time"}
    },
    required: [:slug, :title, :excerpt, :noindex, :published_at, :updated_at]
  })
end

defmodule RefMDWeb.Schemas.PublicAuthorResponse do
  alias OpenApiSpex.Schema
  require OpenApiSpex

  OpenApiSpex.schema(%{
    title: "PublicAuthorResponse",
    type: :object,
    properties: %{
      author_slug: %Schema{type: :string},
      author_name: %Schema{type: :string},
      author_description: %Schema{type: :string, nullable: true},
      documents: %Schema{type: :array, items: RefMDWeb.Schemas.PublicAuthorDocument}
    },
    required: [:author_slug, :author_name, :author_description, :documents]
  })
end
