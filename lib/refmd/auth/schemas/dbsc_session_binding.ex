defmodule RefMD.Auth.DBSCSessionBinding do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "dbsc_session_bindings" do
    field :session_kind, :string
    field :session_id, :binary_id
    field :session_identifier, :string
    field :public_key_jwk, :map
    field :current_token_hash, :string
    field :current_challenge, :string
    field :previous_challenge, :string
    field :previous_challenge_expires_at, :utc_datetime_usec
    field :binding_expires_at, :utc_datetime_usec
    field :credential_expires_at, :utc_datetime_usec
    field :last_verified_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
    field :updated_at, :utc_datetime_usec
  end

  def changeset(binding, attrs) do
    binding
    |> cast(attrs, [
      :session_kind,
      :session_id,
      :session_identifier,
      :public_key_jwk,
      :current_token_hash,
      :current_challenge,
      :previous_challenge,
      :previous_challenge_expires_at,
      :binding_expires_at,
      :credential_expires_at,
      :last_verified_at,
      :created_at,
      :updated_at
    ])
    |> validate_required([
      :session_kind,
      :session_id,
      :session_identifier,
      :public_key_jwk,
      :current_challenge,
      :binding_expires_at,
      :created_at,
      :updated_at
    ])
    |> validate_inclusion(:session_kind, ["user", "share_participant", "mount"])
    |> validate_length(:session_identifier, min: 32, max: 128)
    |> validate_length(:current_token_hash, is: 43)
    |> validate_format(:current_token_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> unique_constraint([:session_kind, :session_id])
    |> unique_constraint(:session_identifier)
  end
end
