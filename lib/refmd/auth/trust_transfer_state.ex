defmodule RefMD.Auth.TrustTransferState do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "trust_transfer_states" do
    field :device_id, :binary_id, primary_key: true
    belongs_to :user, RefMD.Users.User
    field :sender_device_id, :binary_id
    field :ciphertext, :binary
    field :nonce, :binary
    field :signature, :binary
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :device_id,
      :user_id,
      :sender_device_id,
      :ciphertext,
      :nonce,
      :signature
    ])
    |> validate_required([
      :device_id,
      :user_id,
      :sender_device_id,
      :ciphertext,
      :nonce,
      :signature
    ])
  end
end
