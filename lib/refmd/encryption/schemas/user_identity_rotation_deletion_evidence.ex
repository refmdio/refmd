defmodule RefMD.Encryption.UserIdentityRotationDeletionEvidence do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "user_identity_rotation_deletion_evidences" do
    field :old_key_deleted_event_hash, :string, primary_key: true
    belongs_to :user, RefMD.Users.User
    field :rotation_kind, :string
    field :scope_kind, :string
    field :scope_id, :string
    field :old_key_version, :integer
    field :deletion_manifest, :map
    field :device_key_deletion_proofs, :map
    field :wipe_required_device_ids, {:array, :binary_id}

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(record, attrs) do
    record
    |> cast(attrs, [
      :old_key_deleted_event_hash,
      :user_id,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :deletion_manifest,
      :device_key_deletion_proofs,
      :wipe_required_device_ids
    ])
    |> validate_required([
      :old_key_deleted_event_hash,
      :user_id,
      :rotation_kind,
      :scope_kind,
      :scope_id,
      :old_key_version,
      :deletion_manifest,
      :device_key_deletion_proofs,
      :wipe_required_device_ids
    ])
    |> validate_number(:old_key_version, greater_than: 0)
    |> validate_inclusion(:rotation_kind, ["identity"])
    |> validate_inclusion(:scope_kind, ["user"])
    |> validate_scope_matches_user()
    |> foreign_key_constraint(:user_id)
    |> unique_constraint(:old_key_deleted_event_hash,
      name: :user_identity_rotation_deletion_evidences_pkey
    )
  end

  defp validate_scope_matches_user(changeset) do
    user_id = get_field(changeset, :user_id)
    scope_id = get_field(changeset, :scope_id)

    if is_binary(user_id) and is_binary(scope_id) and scope_id != user_id do
      add_error(changeset, :scope_id, "must match user_id")
    else
      changeset
    end
  end
end
