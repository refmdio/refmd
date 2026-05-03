defmodule RefMD.Sharing.Share do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "shares" do
    belongs_to :document, RefMD.Documents.Document
    belongs_to :parent_share, __MODULE__
    belongs_to :created_by_user, RefMD.Users.User, foreign_key: :created_by

    field :scope, :string
    field :token_hash, :string
    field :token_prefix, :string
    field :slug_ciphertext, :binary
    field :slug_nonce, :binary
    field :slug_key_id, :string
    field :permission, :string
    field :password_protected, :boolean, default: false
    field :access_limit, :integer
    field :access_count, :integer, default: 0
    field :expires_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(share, attrs) do
    share
    |> cast(attrs, [
      :id,
      :document_id,
      :parent_share_id,
      :scope,
      :token_hash,
      :token_prefix,
      :slug_ciphertext,
      :slug_nonce,
      :slug_key_id,
      :permission,
      :password_protected,
      :access_limit,
      :access_count,
      :created_by,
      :expires_at
    ])
    |> validate_required([
      :id,
      :document_id,
      :scope,
      :token_hash,
      :token_prefix,
      :slug_ciphertext,
      :slug_nonce,
      :slug_key_id,
      :permission,
      :password_protected,
      :created_by
    ])
    |> validate_inclusion(:scope, ~w(document folder))
    |> validate_inclusion(:permission, ~w(view edit))
    |> validate_length(:token_hash, is: 43)
    |> validate_format(:token_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_length(:token_prefix, is: 4)
    |> validate_format(:token_prefix, ~r/^[A-Za-z0-9\-_]{4}$/)
    |> validate_required([:slug_ciphertext, :slug_nonce, :slug_key_id])
    |> validate_number(:access_count, greater_than_or_equal_to: 0)
    |> validate_number(:access_limit, greater_than_or_equal_to: 0)
    |> check_constraint(:access_limit, name: :shares_access_limit_positive)
    |> unique_constraint(:token_hash)
    |> unique_constraint([:parent_share_id, :document_id],
      name: :shares_parent_share_document_id_index
    )
    |> unique_constraint(:id, name: :shares_pkey)
    |> foreign_key_constraint(:document_id)
    |> foreign_key_constraint(:created_by)
    |> foreign_key_constraint(:parent_share_id)
  end

  @spec update_settings_changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def update_settings_changeset(share, attrs) do
    share
    |> cast(attrs, [:expires_at, :access_limit])
    |> validate_number(:access_limit, greater_than_or_equal_to: 0)
    |> check_constraint(:access_limit, name: :shares_access_limit_positive)
  end
end
