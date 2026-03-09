defmodule RefMD.Encryption.WorkspaceKekBackup do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_kek_backups" do
    belongs_to :workspace, RefMD.Workspaces.Workspace
    belongs_to :user, RefMD.Accounts.User
    field :key_version, :integer, primary_key: true
    field :encrypted_kek, :binary
    field :nonce, :binary
    field :is_active, :boolean
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(backup, attrs) do
    backup
    |> cast(attrs, [
      :workspace_id,
      :user_id,
      :key_version,
      :encrypted_kek,
      :nonce,
      :is_active
    ])
    |> validate_required([
      :workspace_id,
      :user_id,
      :key_version,
      :encrypted_kek,
      :nonce,
      :is_active
    ])
  end
end
