defmodule RefMD.Encryption.WorkspaceMemberEnvelope do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_member_envelopes" do
    field :workspace_id, :binary_id, primary_key: true
    field :target_user_id, :binary_id, primary_key: true
    field :key_version, :integer, primary_key: true
    field :sender_device_id, :binary_id
    field :encrypted_kek, :binary
    field :nonce, :binary
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @xchacha20_nonce_bytes 24
  @encrypted_kek_bytes 48

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :workspace_id,
      :target_user_id,
      :key_version,
      :sender_device_id,
      :encrypted_kek,
      :nonce
    ])
    |> validate_required([
      :workspace_id,
      :target_user_id,
      :key_version,
      :sender_device_id,
      :encrypted_kek,
      :nonce
    ])
    |> validate_binary_size(:nonce, @xchacha20_nonce_bytes)
    |> validate_binary_size(:encrypted_kek, @encrypted_kek_bytes)
    |> unique_constraint([:workspace_id, :target_user_id, :key_version],
      name: :workspace_member_envelopes_pk
    )
    |> foreign_key_constraint(:target_user_id,
      name: :workspace_member_envelopes_member_fk
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
