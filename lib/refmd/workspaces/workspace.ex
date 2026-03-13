defmodule RefMD.Workspaces.Workspace do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "workspaces" do
    field :name, :string
    field :slug, :string
    field :description, :string
    field :icon, :string
    belongs_to :owner, RefMD.Users.User
    field :current_kek_version, :integer, default: 0
    field :min_kek_version, :integer, default: 0
    field :needs_kek_rotation, :boolean, default: false
    field :kek_rotation_initiator_user_id, :binary_id

    has_many :roles, RefMD.Workspaces.WorkspaceRole
    has_many :members, RefMD.Workspaces.WorkspaceMember

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(workspace, attrs) do
    workspace
    |> cast(attrs, [:name, :slug, :description, :icon, :owner_id])
    |> validate_required([:name, :slug, :owner_id])
    |> validate_slug()
    |> unique_constraint(:slug)
  end

  @spec update_changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def update_changeset(workspace, attrs) do
    workspace
    |> cast(attrs, [:name, :slug, :description, :icon])
    |> validate_length(:name, min: 1, max: 100)
    |> validate_length(:description, max: 500)
    |> validate_slug()
    |> unique_constraint(:slug)
  end

  defp validate_slug(changeset) do
    case get_change(changeset, :slug) do
      nil ->
        changeset

      slug ->
        if Regex.match?(~r/\A[a-z0-9]([a-z0-9-]*[a-z0-9])?\z/, slug) do
          changeset
        else
          add_error(changeset, :slug, "must contain only lowercase letters, numbers, and hyphens")
        end
    end
  end
end
