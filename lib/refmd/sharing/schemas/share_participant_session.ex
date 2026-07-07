defmodule RefMD.Sharing.ShareParticipantSession do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "share_participant_sessions" do
    belongs_to :share, RefMD.Sharing.Share
    belongs_to :principal, RefMD.Sharing.ShareParticipantPrincipal
    belongs_to :device, RefMD.Sharing.ShareParticipantDevice

    field :grant, :string
    field :token_hash, :string
    field :expires_at, :utc_datetime_usec
    field :last_seen_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  def changeset(session, attrs) do
    session
    |> cast(attrs, [
      :share_id,
      :principal_id,
      :device_id,
      :grant,
      :token_hash,
      :expires_at,
      :last_seen_at
    ])
    |> validate_required([
      :share_id,
      :principal_id,
      :device_id,
      :grant,
      :token_hash,
      :expires_at,
      :last_seen_at
    ])
    |> validate_inclusion(:grant, ~w(view edit))
    |> validate_length(:token_hash, is: 43)
    |> validate_format(:token_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> unique_constraint(:token_hash)
    |> foreign_key_constraint(:share_id)
    |> foreign_key_constraint(:principal_id)
    |> foreign_key_constraint(:device_id)
  end
end
