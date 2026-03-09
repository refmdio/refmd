defmodule RefMD.Documents.Document do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "documents" do
    belongs_to :workspace, RefMD.Workspaces.Workspace
    belongs_to :parent, RefMD.Documents.Document
    belongs_to :created_by_user, RefMD.Accounts.User, foreign_key: :created_by
    belongs_to :active_snapshot, RefMD.Documents.DocumentSnapshot

    field :position, :integer, default: 0
    field :title, :string, default: "Untitled"
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

    timestamps(type: :utc_datetime_usec)
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
    |> validate_required([:workspace_id, :slug, :doc_type])
    |> validate_inclusion(:doc_type, ~w(document folder))
    |> unique_constraint([:workspace_id, :parent_id, :position],
      name: :documents_workspace_parent_position
    )
  end
end
