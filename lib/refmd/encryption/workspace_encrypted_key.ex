defmodule RefMD.Encryption.WorkspaceEncryptedKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_encrypted_keys" do
    belongs_to :workspace, RefMD.Workspaces.Workspace
    belongs_to :user, RefMD.Accounts.User
    belongs_to :device, RefMD.Accounts.Device
    field :key_version, :integer, primary_key: true
    field :sender_device_id, :binary_id
    field :encrypted_kek, :binary
    field :nonce, :binary
    field :is_active, :boolean
    field :created_at, :utc_datetime_usec
  end

  def changeset(key, attrs) do
    key
    |> cast(attrs, [
      :workspace_id,
      :user_id,
      :device_id,
      :key_version,
      :sender_device_id,
      :encrypted_kek,
      :nonce,
      :is_active
    ])
    |> validate_required([
      :workspace_id,
      :user_id,
      :device_id,
      :key_version,
      :sender_device_id,
      :encrypted_kek,
      :nonce,
      :is_active
    ])
  end
end
