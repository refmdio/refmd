defmodule RefMD.Public.PublicAuthorProfile do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:workspace_id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "public_author_profiles" do
    belongs_to :workspace, RefMD.Workspaces.Workspace,
      define_field: false,
      foreign_key: :workspace_id

    field :slug, :string
    field :display_name, :string
    field :bio, :string

    timestamps(type: :utc_datetime_usec)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(profile, attrs) do
    profile
    |> cast(attrs, [:workspace_id, :slug, :display_name, :bio])
    |> validate_required([:workspace_id, :slug, :display_name])
    |> validate_length(:slug, min: 1, max: 64)
    |> validate_length(:display_name, min: 1, max: 100)
    |> validate_length(:bio, max: 500)
    |> validate_slug()
    |> unique_constraint(:slug)
    |> foreign_key_constraint(:workspace_id)
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
