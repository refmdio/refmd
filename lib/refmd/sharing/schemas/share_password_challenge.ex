defmodule RefMD.Sharing.SharePasswordChallenge do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "share_password_challenges" do
    belongs_to :share, RefMD.Sharing.Share

    field :token_hash, :string
    field :challenge, :binary
    field :expires_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  def changeset(challenge, attrs) do
    challenge
    |> cast(attrs, [:share_id, :token_hash, :challenge, :expires_at])
    |> validate_required([:token_hash, :challenge, :expires_at])
    |> validate_length(:token_hash, is: 43)
    |> validate_format(:token_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_change(:challenge, fn :challenge, value ->
      if byte_size(value) == 32, do: [], else: [challenge: "must be 32 bytes"]
    end)
    |> unique_constraint(:token_hash)
    |> foreign_key_constraint(:share_id)
  end
end
