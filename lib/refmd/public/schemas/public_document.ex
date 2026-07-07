defmodule RefMD.Public.PublicDocument do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:document_id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "public_documents" do
    belongs_to :document, RefMD.Documents.Document,
      define_field: false,
      foreign_key: :document_id

    belongs_to :workspace, RefMD.Workspaces.Workspace

    belongs_to :author_profile, RefMD.Public.PublicAuthorProfile,
      foreign_key: :author_profile_id,
      references: :workspace_id

    belongs_to :published_by_user, RefMD.Users.User, foreign_key: :published_by

    field :slug, :string
    field :title, :string
    field :content, :string
    field :content_hash, :string
    field :noindex, :boolean, default: false
    field :published_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec, inserted_at: false)
  end

  def changeset(public_document, attrs) do
    public_document
    |> cast(attrs, [
      :document_id,
      :workspace_id,
      :author_profile_id,
      :slug,
      :title,
      :content,
      :content_hash,
      :noindex,
      :published_by,
      :published_at
    ])
    |> validate_required([
      :document_id,
      :workspace_id,
      :author_profile_id,
      :slug,
      :title,
      :content,
      :content_hash,
      :published_by,
      :published_at
    ])
    |> validate_length(:title, min: 1, max: 300)
    |> validate_length(:slug, min: 1, max: 128)
    |> validate_slug()
    |> unique_constraint(:slug, name: :public_documents_author_profile_id_slug_index)
    |> unique_constraint(:document_id)
    |> foreign_key_constraint(:document_id)
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:author_profile_id)
    |> foreign_key_constraint(:published_by)
  end

  def settings_changeset(public_document, attrs) do
    public_document
    |> cast(attrs, [:slug, :noindex])
    |> validate_length(:slug, min: 1, max: 128)
    |> validate_slug()
    |> unique_constraint(:slug, name: :public_documents_author_profile_id_slug_index)
  end

  def content_changeset(public_document, attrs) do
    public_document
    |> cast(attrs, [:title, :content, :content_hash])
    |> validate_required([:title, :content, :content_hash])
    |> validate_length(:title, min: 1, max: 300)
  end

  defp validate_slug(changeset) do
    validate_change(changeset, :slug, fn :slug, slug ->
      if Regex.match?(~r/\A[a-z0-9]([a-z0-9-]*[a-z0-9])?\z/, slug) do
        []
      else
        [slug: "must contain only lowercase letters, numbers, and hyphens"]
      end
    end)
  end
end
