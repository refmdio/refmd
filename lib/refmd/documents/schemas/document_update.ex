defmodule RefMD.Documents.DocumentUpdate do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.Signature

  @primary_key {:id, :id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "document_updates" do
    belongs_to :document, RefMD.Documents.Document
    belongs_to :snapshot, RefMD.Documents.DocumentSnapshot

    field :clock, :integer
    field :version, :integer
    field :signing_key_id, :string
    field :update_data, :binary
    field :nonce, :binary
    field :key_version, :integer
    field :update_hash, :string
    field :hybrid_signature, :map
    field :owner_kind, :string
    field :owner_id, :string
    field :authority_kind, :string
    field :authority_id, :string
    field :authority_context_key, :string
    field :authority_scope_id, :string
    field :authority_permission_version, :integer
    field :key_checkpoint_sequence, :integer
    field :key_checkpoint_hash, :string
    field :admission_event_hash, :string
    field :write_session_counter, :integer
    field :timestamp, :integer
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(update, attrs) do
    update
    |> cast(attrs, [
      :document_id,
      :snapshot_id,
      :clock,
      :version,
      :signing_key_id,
      :update_data,
      :nonce,
      :key_version,
      :update_hash,
      :hybrid_signature,
      :owner_kind,
      :owner_id,
      :authority_kind,
      :authority_id,
      :authority_context_key,
      :authority_scope_id,
      :authority_permission_version,
      :key_checkpoint_sequence,
      :key_checkpoint_hash,
      :admission_event_hash,
      :write_session_counter,
      :timestamp
    ])
    |> validate_required([
      :document_id,
      :snapshot_id,
      :version,
      :update_data,
      :nonce,
      :key_version,
      :update_hash,
      :timestamp
    ])
    |> validate_update_auth_fields()
    |> validate_hybrid_signature_shape()
    |> unique_constraint([:document_id, :version],
      name: :document_updates_document_id_version_index
    )
    |> unique_constraint([:document_id, :update_hash],
      name: :document_updates_document_id_update_hash_index
    )
    |> unique_constraint([:admission_event_hash, :signing_key_id, :write_session_counter],
      name: :document_updates_admission_event_hash_signing_key_id_write_session_counter_index
    )
  end

  defp validate_update_auth_fields(changeset) do
    changeset
    |> validate_required([
      :hybrid_signature,
      :clock,
      :signing_key_id,
      :owner_kind,
      :owner_id,
      :authority_kind,
      :authority_id,
      :authority_context_key,
      :authority_scope_id,
      :authority_permission_version,
      :key_checkpoint_sequence,
      :key_checkpoint_hash,
      :admission_event_hash,
      :write_session_counter
    ])
  end

  defp validate_hybrid_signature_shape(changeset) do
    validate_change(changeset, :hybrid_signature, fn field, signature ->
      try do
        Signature.assert_hybrid_signature_shape!(signature)
        []
      rescue
        ArgumentError -> [{field, "must be an exact hybrid signature object"}]
      end
    end)
  end
end
