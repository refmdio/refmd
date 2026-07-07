defmodule RefMD.Sharing.ShareParticipantPopChallenge do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "share_participant_pop_challenges" do
    belongs_to :share, RefMD.Sharing.Share
    belongs_to :device, RefMD.Sharing.ShareParticipantDevice

    field :challenge_hash, :binary
    field :session_id_hash, :string
    field :session_kind, :string
    field :subject_id, :binary_id
    field :share_participant_principal_id, :binary_id
    field :share_participant_device_id, :binary_id
    field :expires_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  def changeset(challenge, attrs) do
    challenge
    |> cast(attrs, [
      :share_id,
      :device_id,
      :challenge_hash,
      :session_id_hash,
      :session_kind,
      :subject_id,
      :share_participant_principal_id,
      :share_participant_device_id,
      :expires_at
    ])
    |> validate_required([
      :share_id,
      :device_id,
      :challenge_hash,
      :session_id_hash,
      :session_kind,
      :subject_id,
      :share_participant_principal_id,
      :share_participant_device_id,
      :expires_at
    ])
    |> validate_inclusion(:session_kind, ["share_participant"])
    |> foreign_key_constraint(:share_id)
    |> foreign_key_constraint(:device_id)
  end
end
