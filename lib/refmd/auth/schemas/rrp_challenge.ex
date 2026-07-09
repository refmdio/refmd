defmodule RefMD.Auth.RrpChallenge do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "rrp_challenges" do
    belongs_to :device, RefMD.Devices.Device
    field :challenge_hash, :binary
    field :session_id_hash, :string
    field :session_kind, :string
    field :subject_id, :binary_id
    field :expires_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  def changeset(challenge, attrs) do
    challenge
    |> cast(attrs, [
      :device_id,
      :challenge_hash,
      :session_id_hash,
      :session_kind,
      :subject_id,
      :expires_at
    ])
    |> validate_required([
      :device_id,
      :challenge_hash,
      :session_id_hash,
      :session_kind,
      :subject_id,
      :expires_at
    ])
    |> validate_inclusion(:session_kind, ["user"])
    |> unique_constraint(:challenge_hash)
  end
end
