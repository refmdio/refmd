defmodule RefMD.Accounts.TrustTransferState do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "trust_transfer_states" do
    belongs_to :user, RefMD.Accounts.User
    field :target_device_id, :binary_id
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
      :user_id,
      :target_device_id,
      :sender_device_id,
      :ciphertext,
      :nonce,
      :signature
    ])
    |> validate_required([
      :user_id,
      :target_device_id,
      :sender_device_id,
      :ciphertext,
      :nonce,
      :signature
    ])
    |> unique_constraint([:user_id, :target_device_id])
  end
end
