defmodule RefMD.Sharing.ShareKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:share_id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "share_keys" do
    belongs_to :share, RefMD.Sharing.Share, define_field: false
    belongs_to :document, RefMD.Documents.Document

    field :encrypted_dek, :binary
    field :nonce, :binary
    field :salt, :binary
    field :kdf_params, :map
    field :encrypted_auth_key, :binary
    field :auth_key_nonce, :binary
    field :dek_server_nonce, :binary
    field :server_key_id, :string
    field :manage_token_hash, :string

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(share_key, attrs) do
    share_key
    |> cast(attrs, [
      :share_id,
      :document_id,
      :encrypted_dek,
      :nonce,
      :salt,
      :kdf_params,
      :encrypted_auth_key,
      :auth_key_nonce,
      :dek_server_nonce,
      :server_key_id,
      :manage_token_hash
    ])
    |> validate_required([
      :share_id,
      :document_id,
      :encrypted_dek,
      :dek_server_nonce,
      :server_key_id,
      :manage_token_hash
    ])
    |> validate_length(:manage_token_hash, is: 43)
    |> validate_format(:manage_token_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_change(:nonce, fn :nonce, nonce ->
      if is_nil(nonce) or byte_size(nonce) == 24, do: [], else: [nonce: "must be 24 bytes"]
    end)
    |> validate_change(:salt, fn :salt, salt ->
      if is_nil(salt) or byte_size(salt) == 16, do: [], else: [salt: "must be 16 bytes"]
    end)
    |> validate_change(:auth_key_nonce, fn :auth_key_nonce, nonce ->
      if is_nil(nonce) or byte_size(nonce) == 12,
        do: [],
        else: [auth_key_nonce: "must be 12 bytes"]
    end)
    |> validate_change(:dek_server_nonce, fn :dek_server_nonce, nonce ->
      if byte_size(nonce) == 12, do: [], else: [dek_server_nonce: "must be 12 bytes"]
    end)
    |> unique_constraint(:manage_token_hash)
    |> foreign_key_constraint(:share_id)
    |> foreign_key_constraint(:document_id)
  end
end
