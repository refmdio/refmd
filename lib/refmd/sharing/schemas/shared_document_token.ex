defmodule RefMD.Sharing.SharedDocumentToken do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "shared_document_tokens" do
    belongs_to :share, RefMD.Sharing.Share
    belongs_to :document, RefMD.Documents.Document

    field :token, :string

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
  end

  def changeset(shared_token, attrs) do
    shared_token
    |> cast(attrs, [:share_id, :document_id, :token])
    |> validate_required([:share_id, :document_id, :token])
    |> validate_length(:token, min: 20, max: 512)
    |> unique_constraint(:token)
    |> unique_constraint([:share_id, :document_id])
    |> foreign_key_constraint(:share_id)
    |> foreign_key_constraint(:document_id)
  end
end
