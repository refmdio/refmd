defmodule RefMD.Documents.DocumentSignerKey do
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "document_signer_keys" do
    belongs_to :document, RefMD.Documents.Document

    field :signer_kind, :string
    field :share_id, Ecto.UUID
    field :principal_id, Ecto.UUID
    field :user_id, Ecto.UUID
    field :device_id, Ecto.UUID
    field :context_key, :string
    field :signing_public_key, :binary
    field :encryption_public_key, :binary
    field :first_seen_at, :utc_datetime_usec
    field :last_seen_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}
end
