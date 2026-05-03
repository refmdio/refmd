defmodule RefMD.Sharing.ShareMount do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "share_mounts" do
    belongs_to :share, RefMD.Sharing.Share
    belongs_to :target_document, RefMD.Documents.Document
    belongs_to :user, RefMD.Users.User
    belongs_to :workspace, RefMD.Workspaces.Workspace
    belongs_to :parent, RefMD.Documents.Document

    field :target_kind, :string
    field :position, :integer, default: 0

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(mount, attrs) do
    mount
    |> cast(attrs, [
      :share_id,
      :target_document_id,
      :target_kind,
      :user_id,
      :workspace_id,
      :parent_id,
      :position
    ])
    |> validate_required([
      :share_id,
      :target_document_id,
      :target_kind,
      :user_id,
      :workspace_id,
      :position
    ])
    |> validate_inclusion(:target_kind, ~w(document folder))
    |> validate_number(:position, greater_than_or_equal_to: 0)
    |> unique_constraint([:share_id, :target_document_id, :user_id],
      name: :share_mounts_share_target_user_index
    )
    |> foreign_key_constraint(:share_id)
    |> foreign_key_constraint(:target_document_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:parent_id)
  end

  @spec position_changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def position_changeset(mount, attrs) do
    mount
    |> cast(attrs, [:parent_id, :position])
    |> validate_required([:position])
    |> validate_number(:position, greater_than_or_equal_to: 0)
    |> foreign_key_constraint(:parent_id)
  end
end
