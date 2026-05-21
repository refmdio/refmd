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
    field :encrypted_name, :binary
    field :encrypted_name_nonce, :binary
    field :encrypted_name_key_version, :integer
    field :encrypted_description, :binary
    field :encrypted_description_nonce, :binary
    field :encrypted_description_key_version, :integer
    field :encrypted_icon, :binary
    field :encrypted_icon_nonce, :binary
    field :encrypted_icon_key_version, :integer
    belongs_to :owner, RefMD.Users.User
    field :share_links_enabled, :boolean, default: true
    field :public_publishing_enabled, :boolean, default: false
    field :guest_invites_enabled, :boolean, default: false
    field :guest_member_limit, :integer
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
    |> cast(attrs, [
      :name,
      :slug,
      :description,
      :icon,
      :encrypted_name,
      :encrypted_name_nonce,
      :encrypted_name_key_version,
      :encrypted_description,
      :encrypted_description_nonce,
      :encrypted_description_key_version,
      :encrypted_icon,
      :encrypted_icon_nonce,
      :encrypted_icon_key_version,
      :owner_id,
      :share_links_enabled,
      :public_publishing_enabled,
      :guest_invites_enabled,
      :guest_member_limit
    ])
    |> validate_required([:name, :slug, :owner_id])
    |> validate_number(:guest_member_limit, greater_than: 0)
    |> validate_slug()
    |> unique_constraint(:slug)
  end

  @spec update_changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def update_changeset(workspace, attrs) do
    workspace
    |> cast(attrs, [
      :name,
      :slug,
      :description,
      :icon,
      :encrypted_name,
      :encrypted_name_nonce,
      :encrypted_name_key_version,
      :encrypted_description,
      :encrypted_description_nonce,
      :encrypted_description_key_version,
      :encrypted_icon,
      :encrypted_icon_nonce,
      :encrypted_icon_key_version,
      :share_links_enabled,
      :public_publishing_enabled,
      :guest_invites_enabled,
      :guest_member_limit
    ])
    |> validate_length(:name, min: 1, max: 100)
    |> validate_length(:description, max: 500)
    |> validate_number(:guest_member_limit, greater_than: 0)
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
