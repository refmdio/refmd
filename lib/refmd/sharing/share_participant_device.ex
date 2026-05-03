defmodule RefMD.Sharing.ShareParticipantDevice do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "share_participant_devices" do
    belongs_to :share, RefMD.Sharing.Share
    belongs_to :principal, RefMD.Sharing.ShareParticipantPrincipal

    field :signing_public_key, :binary
    field :encryption_public_key, :binary
    field :last_seen_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(device, attrs) do
    device
    |> cast(attrs, [
      :share_id,
      :principal_id,
      :signing_public_key,
      :encryption_public_key,
      :last_seen_at
    ])
    |> validate_required([
      :share_id,
      :principal_id,
      :signing_public_key,
      :encryption_public_key,
      :last_seen_at
    ])
    |> validate_change(:signing_public_key, fn :signing_public_key, key ->
      cond do
        byte_size(key) != 32 ->
          [signing_public_key: "must be 32 bytes"]

        not Crypto.valid_ed25519_public_key?(key) ->
          [signing_public_key: "must be a valid Ed25519 public key"]

        true ->
          []
      end
    end)
    |> validate_change(:encryption_public_key, fn :encryption_public_key, key ->
      cond do
        byte_size(key) != 32 ->
          [encryption_public_key: "must be 32 bytes"]

        not Crypto.valid_x25519_public_key?(key) ->
          [encryption_public_key: "must be a valid X25519 public key"]

        true ->
          []
      end
    end)
    |> unique_constraint([:share_id, :signing_public_key])
    |> foreign_key_constraint(:share_id)
    |> foreign_key_constraint(:principal_id)
  end
end
