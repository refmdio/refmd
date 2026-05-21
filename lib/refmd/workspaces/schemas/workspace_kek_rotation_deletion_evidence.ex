defmodule RefMD.Workspaces.WorkspaceKekRotationDeletionEvidence do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_kek_rotation_deletion_evidences" do
    field :old_key_deleted_event_hash, :string, primary_key: true
    belongs_to :workspace, RefMD.Workspaces.Workspace
    field :rotation_kind, :string
    field :scope_kind, :string
    field :scope_id, :string
    field :old_key_version, :integer
    field :deletion_manifest, :map
    field :device_key_deletion_proofs, :map

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :old_key_deleted_event_hash,
      :workspace_id,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :deletion_manifest,
      :device_key_deletion_proofs
    ])
    |> validate_required([
      :old_key_deleted_event_hash,
      :workspace_id,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :deletion_manifest,
      :device_key_deletion_proofs
    ])
    |> validate_number(:old_key_version, greater_than: 0)
    |> validate_inclusion(:rotation_kind, ["kek"])
    |> validate_inclusion(:scope_kind, ["workspace"])
    |> validate_scope_matches_workspace()
    |> foreign_key_constraint(:workspace_id)
    |> unique_constraint(:old_key_deleted_event_hash,
      name: :workspace_kek_rotation_deletion_evidences_pkey
    )
  end

  defp validate_scope_matches_workspace(changeset) do
    workspace_id = get_field(changeset, :workspace_id)
    scope_id = get_field(changeset, :scope_id)

    if is_binary(workspace_id) and is_binary(scope_id) and scope_id != workspace_id do
      add_error(changeset, :scope_id, "must match workspace_id")
    else
      changeset
    end
  end
end
