defmodule RefMD.Auth.OAuthState do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}

  schema "oauth_states" do
    field :provider, :string
    field :state_hash, :binary
    field :nonce, :string
    field :code_verifier, :string
    field :redirect_uri, :string
    field :return_to, :string
    field :expires_at, :utc_datetime_usec
    field :consumed_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  def changeset(state, attrs) do
    state
    |> cast(attrs, [
      :provider,
      :state_hash,
      :nonce,
      :code_verifier,
      :redirect_uri,
      :return_to,
      :expires_at,
      :consumed_at
    ])
    |> validate_required([
      :provider,
      :state_hash,
      :nonce,
      :code_verifier,
      :redirect_uri,
      :return_to,
      :expires_at
    ])
    |> validate_inclusion(:provider, ["google", "github"])
    |> unique_constraint(:state_hash)
  end
end
