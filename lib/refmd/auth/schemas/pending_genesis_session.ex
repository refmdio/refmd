defmodule RefMD.Auth.PendingGenesisSession do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:registration_id, :binary_id, autogenerate: false}

  schema "pending_genesis_sessions" do
    field :token_hash, :string
    field :expires_at, :utc_datetime_usec
    field :consumed_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  def changeset(session, attrs) do
    session
    |> cast(attrs, [:registration_id, :token_hash, :expires_at, :consumed_at, :created_at])
    |> validate_required([:registration_id, :token_hash, :expires_at, :created_at])
    |> unique_constraint(:token_hash)
  end
end
