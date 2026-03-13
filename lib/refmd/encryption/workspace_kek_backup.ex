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

  @xchacha20_nonce_bytes 24
  @encrypted_kek_bytes 48

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
    |> validate_binary_size(:nonce, @xchacha20_nonce_bytes)
    |> validate_binary_size(:encrypted_kek, @encrypted_kek_bytes)
  end

  defp validate_binary_size(changeset, field, expected) do
    validate_change(changeset, field, fn _, value ->
      if byte_size(value) == expected,
        do: [],
        else: [{field, "must be exactly #{expected} bytes"}]
    end)
  end
end
