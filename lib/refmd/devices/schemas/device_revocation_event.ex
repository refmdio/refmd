defmodule RefMD.Devices.DeviceRevocationEvent do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.Signature

  @primary_key false
  @foreign_key_type :binary_id

  schema "device_revocation_events" do
    belongs_to :user, RefMD.Users.User, primary_key: true
    field :device_id, :binary_id, primary_key: true
    field :revoked_by_device_id, :binary_id
    field :revocation_mode, :string
    field :signature, :map
    field :revoked_at, :integer
    field :created_at, :utc_datetime_usec
  end

  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :user_id,
      :device_id,
      :revoked_by_device_id,
      :revocation_mode,
      :signature,
      :revoked_at
    ])
    |> validate_required([
      :user_id,
      :device_id,
      :revoked_by_device_id,
      :revocation_mode,
      :signature,
      :revoked_at
    ])
    |> validate_inclusion(:revocation_mode, ~w(security retire))
    |> validate_hybrid_signature_shape(:signature)
  end

  defp validate_hybrid_signature_shape(changeset, field) do
    validate_change(changeset, field, fn ^field, signature ->
      try do
        Signature.assert_hybrid_signature_shape!(signature)
        []
      rescue
        ArgumentError -> [{field, "must be an exact hybrid signature object"}]
      end
    end)
  end
end
