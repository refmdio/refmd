defmodule RefMD.Encryption.WorkspaceKekBackup do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_kek_backups" do
    belongs_to :workspace, RefMD.Workspaces.Workspace, primary_key: true
    belongs_to :user, RefMD.Users.User, primary_key: true
    field :key_version, :integer, primary_key: true
    field :encrypted_kek, :binary
    field :nonce, :binary
    field :is_active, :boolean
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  alias RefMD.Crypto.Validate

  @kek_bytes 32

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
    |> Validate.validate_nonce()
    |> Validate.validate_wrapped_key(:encrypted_kek, @kek_bytes)
  end
end
