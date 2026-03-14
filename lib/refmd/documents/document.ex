defmodule RefMD.Documents.Document do
  use Ecto.Schema
  import Ecto.Changeset

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
    field :min_dek_version, :integer, default: 1
    field :archived_at, :utc_datetime_usec

    has_many :children, RefMD.Documents.Document, foreign_key: :parent_id

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
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
    |> validate_number(:position, greater_than_or_equal_to: 0)
    |> validate_folder_not_encrypted()
    |> validate_title_encryption()
    |> validate_encrypted_title_update_consistency()
    |> unique_constraint([:workspace_id, :parent_id, :position],
      name: :documents_workspace_parent_position
    )
  end

  defp validate_folder_not_encrypted(changeset) do
    if get_field(changeset, :doc_type) == "folder" and get_field(changeset, :is_encrypted) == true do
      add_error(changeset, :is_encrypted, "folders cannot be encrypted")
    else
      changeset
    end
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

  # On update: if encrypted_title is changed, nonce and key_version must also be provided
  defp validate_encrypted_title_update_consistency(changeset) do
    if get_change(changeset, :encrypted_title) do
      changeset
      |> validate_required([:encrypted_title_nonce, :encrypted_title_key_version])
      |> validate_change_present(:encrypted_title_nonce)
      |> validate_change_present(:encrypted_title_key_version)
    else
      changeset
    end
  end

  defp validate_change_present(changeset, field) do
    if get_change(changeset, field) do
      changeset
    else
      add_error(changeset, field, "must be provided when encrypted_title is updated")
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
