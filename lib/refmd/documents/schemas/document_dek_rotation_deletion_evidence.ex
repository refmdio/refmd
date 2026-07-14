defmodule RefMD.Documents.DocumentDekRotationDeletionEvidence do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "document_dek_rotation_deletion_evidences" do
    field :old_key_deleted_event_hash, :string, primary_key: true
    belongs_to :document, RefMD.Documents.Document
    belongs_to :workspace, RefMD.Workspaces.Workspace
    field :rotation_kind, :string
    field :scope_kind, :string
    field :scope_id, :string
    field :old_key_version, :integer
    field :completion_manifest, :map
    field :deletion_manifest, :map
    field :device_key_deletion_proofs, :map
    field :wipe_required_device_ids, {:array, :binary_id}, default: []

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :old_key_deleted_event_hash,
      :document_id,
      :workspace_id,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :completion_manifest,
      :deletion_manifest,
      :device_key_deletion_proofs,
      :wipe_required_device_ids
    ])
    |> validate_required([
      :old_key_deleted_event_hash,
      :document_id,
      :workspace_id,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :completion_manifest,
      :deletion_manifest,
      :device_key_deletion_proofs,
      :wipe_required_device_ids
    ])
    |> validate_number(:old_key_version, greater_than: 0)
    |> validate_inclusion(:rotation_kind, ["dek"])
    |> validate_inclusion(:scope_kind, ["document"])
    |> validate_scope_matches_document()
    |> foreign_key_constraint(:document_id)
    |> foreign_key_constraint(:workspace_id)
    |> unique_constraint(:old_key_deleted_event_hash,
      name: :document_dek_rotation_deletion_evidences_pkey
    )
  end

  defp validate_scope_matches_document(changeset) do
    if get_field(changeset, :scope_id) == get_field(changeset, :document_id) do
      changeset
    else
      add_error(changeset, :scope_id, "must match document_id")
    end
  end
end
