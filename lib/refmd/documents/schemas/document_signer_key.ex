defmodule RefMD.Documents.DocumentSignerKey do
  use Ecto.Schema

  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "document_signer_keys" do
    belongs_to :document, RefMD.Documents.Document

    field :authority_kind, :string
    field :authority_id, :string
    field :authority_context_key, :string
    field :authority_scope_id, :string
    field :authority_permission_version, :integer
    field :key_checkpoint_sequence, :integer
    field :key_checkpoint_hash, :string
    field :owner_kind, :string
    field :owner_id, :string
    field :hybrid_signing_public_key_material, :map
    field :signing_key_id, :string
    field :first_seen_at, :utc_datetime_usec
    field :last_seen_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}
end
