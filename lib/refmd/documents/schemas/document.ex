defmodule RefMD.Documents.Document do
  use Ecto.Schema
  import Ecto.Changeset

  @encrypted_title_nonce_bytes 24

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "documents" do
    belongs_to :workspace, RefMD.Workspaces.Workspace
    belongs_to :parent, RefMD.Documents.Document
    belongs_to :created_by_user, RefMD.Users.User, foreign_key: :created_by
    belongs_to :active_snapshot, RefMD.Documents.DocumentSnapshot

    field :position, :integer, default: 0
    field :title, :string
    field :encrypted_title, :binary
    field :encrypted_title_nonce, :binary
    field :encrypted_title_key_version, :integer
    field :slug, :string
    field :path, :string
    field :doc_type, :string, default: "document"
    field :is_encrypted, :boolean, default: true
    field :needs_dek_rotation, :boolean, default: false
    field :dek_rotation_reason, :string
    field :dek_rotation_due_at, :utc_datetime_usec
    field :needs_rotation_snapshot, :boolean, default: false
    field :min_dek_version, :integer, default: 1
    field :archived_at, :utc_datetime_usec
    field :write_state, :string, default: "writable"

    has_many :children, RefMD.Documents.Document, foreign_key: :parent_id

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  def changeset(document, attrs) do
    document
    |> cast(attrs, [
      :workspace_id,
      :parent_id,
      :position,
      :title,
      :encrypted_title,
      :encrypted_title_nonce,
      :encrypted_title_key_version,
      :slug,
      :path,
      :doc_type,
      :is_encrypted,
      :created_by,
      :active_snapshot_id,
      :archived_at
    ])
    |> validate_required([:workspace_id, :slug, :doc_type, :is_encrypted])
    |> validate_inclusion(:doc_type, ~w(document folder))
    |> validate_inclusion(:write_state, ~w(writable read_only archived write_disabled))
    |> validate_number(:position, greater_than_or_equal_to: 0)
    |> validate_title_encryption()
    |> validate_encrypted_title_metadata_shape()
    |> validate_encrypted_title_update_consistency()
    |> unique_constraint(:id, name: :documents_pkey)
    |> unique_constraint([:workspace_id, :parent_id, :position],
      name: :documents_workspace_parent_position
    )
  end

  defp validate_title_encryption(changeset) do
    case get_field(changeset, :is_encrypted) do
      true ->
        changeset
        |> validate_required([
          :encrypted_title,
          :encrypted_title_nonce,
          :encrypted_title_key_version
        ])
        |> force_change(:title, "Untitled")

      false ->
        changeset
        |> validate_required([:title])
        |> validate_length(:title, min: 1)
        |> validate_no_encrypted_title()

      _ ->
        changeset
    end
  end

  defp validate_encrypted_title_update_consistency(changeset) do
    supplied_fields =
      [:encrypted_title, :encrypted_title_nonce, :encrypted_title_key_version]
      |> Enum.filter(&metadata_field_supplied?(changeset, &1))

    case supplied_fields do
      [] ->
        changeset

      [:encrypted_title, :encrypted_title_nonce, :encrypted_title_key_version] ->
        changeset

      _partial ->
        changeset
        |> validate_change_present(:encrypted_title)
        |> validate_change_present(:encrypted_title_nonce)
        |> validate_change_present(:encrypted_title_key_version)
    end
  end

  defp validate_encrypted_title_metadata_shape(changeset) do
    changeset
    |> validate_change(:encrypted_title, fn :encrypted_title, value ->
      if is_binary(value) and byte_size(value) > 0 do
        []
      else
        [encrypted_title: "must be non-empty encrypted title ciphertext"]
      end
    end)
    |> validate_change(:encrypted_title_nonce, fn :encrypted_title_nonce, value ->
      if is_binary(value) and byte_size(value) == @encrypted_title_nonce_bytes do
        []
      else
        [encrypted_title_nonce: "must be 24 bytes"]
      end
    end)
    |> validate_number(:encrypted_title_key_version, greater_than: 0)
  end

  defp metadata_field_supplied?(changeset, field) do
    params = changeset.params || %{}
    Map.has_key?(params, Atom.to_string(field)) || Map.has_key?(params, field)
  end

  defp validate_change_present(changeset, field) do
    if metadata_field_supplied?(changeset, field) do
      changeset
    else
      add_error(changeset, field, "must be provided with encrypted title metadata updates")
    end
  end

  defp validate_no_encrypted_title(changeset) do
    changeset
    |> reject_field(:encrypted_title)
    |> reject_field(:encrypted_title_nonce)
    |> reject_field(:encrypted_title_key_version)
  end

  defp reject_field(changeset, field) do
    if get_field(changeset, field) do
      add_error(changeset, field, "must not be set when is_encrypted is false")
    else
      changeset
    end
  end
end
