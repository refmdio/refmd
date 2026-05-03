defmodule RefMD.Workspaces.WorkspaceGuestGrant do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_guest_grants" do
    belongs_to :workspace, RefMD.Workspaces.Workspace, primary_key: true
    belongs_to :user, RefMD.Users.User, primary_key: true
    field :target_scope, :string
    belongs_to :target_document, RefMD.Documents.Document
    field :permission, :string
    belongs_to :invite, RefMD.Workspaces.GuestInvitation
    field :revoked_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(grant, attrs) do
    grant
    |> cast(attrs, [
      :workspace_id,
      :user_id,
      :target_scope,
      :target_document_id,
      :permission,
      :invite_id,
      :revoked_at
    ])
    |> validate_required([:workspace_id, :user_id, :target_scope, :permission, :invite_id])
    |> validate_inclusion(:target_scope, ~w(workspace document folder))
    |> validate_inclusion(:permission, ~w(view edit))
    |> validate_target_scope()
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:target_document_id)
    |> foreign_key_constraint(:invite_id)
  end

  defp validate_target_scope(changeset) do
    scope = get_field(changeset, :target_scope)
    target_document_id = get_field(changeset, :target_document_id)

    cond do
      scope == "workspace" and not is_nil(target_document_id) ->
        add_error(changeset, :target_document_id, "must be nil for workspace scope")

      scope in ["document", "folder"] and is_nil(target_document_id) ->
        add_error(changeset, :target_document_id, "is required for document or folder scope")

      true ->
        changeset
    end
  end
end
