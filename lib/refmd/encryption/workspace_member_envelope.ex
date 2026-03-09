defmodule RefMD.Encryption.WorkspaceMemberEnvelope do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_member_envelopes" do
    field :workspace_id, :binary_id
    field :target_user_id, :binary_id
    field :key_version, :integer
    field :sender_device_id, :binary_id
    field :encrypted_kek, :binary
    field :nonce, :binary
    field :created_at, :utc_datetime_usec
  end

  def changeset(record, attrs) do
    record
    |> cast(attrs, [:workspace_id, :target_user_id, :key_version, :sender_device_id, :encrypted_kek, :nonce])
    |> validate_required([:workspace_id, :target_user_id, :key_version, :sender_device_id, :encrypted_kek, :nonce])
    |> unique_constraint([:workspace_id, :target_user_id, :key_version],
      name: :workspace_member_envelopes_pk
    )
  end
end
