defmodule RefMD.Auth.PendingGenesisChallenge do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:registration_id, :binary_id, autogenerate: false}

  schema "pending_genesis_challenges" do
    field :pending_genesis_session_token_hash, :string
    field :challenge_hash, :string
    field :expires_at, :utc_datetime_usec
    field :consumed_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  def changeset(challenge, attrs) do
    challenge
    |> cast(attrs, [
      :registration_id,
      :pending_genesis_session_token_hash,
      :challenge_hash,
      :expires_at,
      :consumed_at,
      :created_at
    ])
    |> validate_required([
      :registration_id,
      :pending_genesis_session_token_hash,
      :challenge_hash,
      :expires_at,
      :created_at
    ])
    |> validate_format(:pending_genesis_session_token_hash, ~r/^[A-Za-z0-9_-]{43}$/)
    |> validate_format(:challenge_hash, ~r/^[A-Za-z0-9_-]{43}$/)
    |> unique_constraint(:challenge_hash)
  end
end
