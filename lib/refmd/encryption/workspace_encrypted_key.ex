defmodule RefMD.Encryption.WorkspaceEncryptedKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_encrypted_keys" do
    belongs_to :workspace, RefMD.Workspaces.Workspace, primary_key: true
    belongs_to :user, RefMD.Users.User, primary_key: true
    belongs_to :device, RefMD.Devices.Device, primary_key: true
    field :key_version, :integer, primary_key: true
    field :sender_device_id, :binary_id
    field :encrypted_kek, :binary
    field :nonce, :binary
    field :is_active, :boolean
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @xchacha20_nonce_bytes 24
  @encrypted_kek_bytes 48

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
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
    |> validate_binary_size(:nonce, @xchacha20_nonce_bytes)
    |> validate_binary_size(:encrypted_kek, @encrypted_kek_bytes)
    |> unique_constraint([:workspace_id, :user_id, :device_id, :key_version],
      name: :workspace_encrypted_keys_pkey,
      message: "key version already exists for this device"
    )
  end

  defp validate_binary_size(changeset, field, expected) do
    validate_change(changeset, field, fn _, value ->
      if byte_size(value) == expected,
        do: [],
        else: [{field, "must be exactly #{expected} bytes"}]
    end)
  end
end
