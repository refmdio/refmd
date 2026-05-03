defmodule RefMD.Sharing.ShareParticipantPopChallenge do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "share_participant_pop_challenges" do
    belongs_to :share, RefMD.Sharing.Share
    belongs_to :device, RefMD.Sharing.ShareParticipantDevice

    field :challenge_hash, :binary
    field :expires_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(challenge, attrs) do
    challenge
    |> cast(attrs, [:share_id, :device_id, :challenge_hash, :expires_at])
    |> validate_required([:share_id, :device_id, :challenge_hash, :expires_at])
    |> foreign_key_constraint(:share_id)
    |> foreign_key_constraint(:device_id)
  end
end
