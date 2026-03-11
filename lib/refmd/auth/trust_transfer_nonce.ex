defmodule RefMD.Auth.TrustTransferNonce do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "trust_transfer_nonces" do
    belongs_to :user, RefMD.Users.User
    field :device_id, :binary_id
    field :nonce, :binary
    field :expires_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(record, attrs) do
    record
    |> cast(attrs, [:user_id, :device_id, :nonce, :expires_at])
    |> validate_required([:user_id, :device_id, :nonce, :expires_at])
    |> unique_constraint([:user_id, :device_id])
  end
end
