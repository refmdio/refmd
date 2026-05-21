defmodule RefMD.Documents.DocumentSnapshot do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.Signature

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "document_snapshots" do
    belongs_to :document, RefMD.Documents.Document
    belongs_to :parent_snapshot, RefMD.Documents.DocumentSnapshot

    field :latest_version, :integer
    field :data, :binary
    field :nonce, :binary
    field :key_version, :integer
    field :hybrid_signature, :map
    field :ciphertext_hash, :string
    field :snapshot_signature_hash, :string
    field :snapshot_admission_event_hash, :string
    field :proof_chain_hash, :string
    field :clocks, :map
    field :parent_snapshot_update_clocks, :map
    field :parent_proof_hash, :string
    field :created_by_signing_key_id, :string
    field :owner_kind, :string
    field :owner_id, :string
    field :authority_kind, :string
    field :authority_id, :string
    field :authority_context_key, :string
    field :authority_scope_id, :string
    field :authority_permission_version, :integer
    field :key_checkpoint_sequence, :integer
    field :key_checkpoint_hash, :string
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(snapshot, attrs) do
    snapshot
    |> cast(attrs, [
      :id,
      :document_id,
      :parent_snapshot_id,
      :latest_version,
      :data,
      :nonce,
      :key_version,
      :hybrid_signature,
      :ciphertext_hash,
      :snapshot_signature_hash,
      :snapshot_admission_event_hash,
      :proof_chain_hash,
      :clocks,
      :parent_snapshot_update_clocks,
      :parent_proof_hash,
      :created_by_signing_key_id,
      :owner_kind,
      :owner_id,
      :authority_kind,
      :authority_id,
      :authority_context_key,
      :authority_scope_id,
      :authority_permission_version,
      :key_checkpoint_sequence,
      :key_checkpoint_hash
    ])
    |> validate_required([
      :document_id,
      :latest_version,
      :data,
      :nonce,
      :key_version,
      :hybrid_signature,
      :ciphertext_hash,
      :snapshot_signature_hash,
      :snapshot_admission_event_hash,
      :proof_chain_hash,
      :clocks,
      :parent_snapshot_update_clocks,
      :created_by_signing_key_id,
      :owner_kind,
      :owner_id,
      :authority_kind,
      :authority_id,
      :authority_context_key,
      :authority_scope_id,
      :authority_permission_version,
      :key_checkpoint_sequence,
      :key_checkpoint_hash
    ])
    |> validate_hybrid_signature_shape()
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
