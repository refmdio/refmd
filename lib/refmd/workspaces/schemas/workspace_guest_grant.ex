defmodule RefMD.Workspaces.WorkspaceGuestGrant do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_guest_grants" do
    field :id, :binary_id
    belongs_to :workspace, RefMD.Workspaces.Workspace, primary_key: true
    belongs_to :user, RefMD.Users.User, primary_key: true
    field :scope_kind, :string
    field :scope_id, :binary_id
    field :permission, :string

    belongs_to :invite, RefMD.Workspaces.GuestInvitation,
      foreign_key: :invite_id,
      type: :binary_id

    field :revoked_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  def changeset(grant, attrs) do
    grant
    |> cast(attrs, [
      :workspace_id,
      :user_id,
      :id,
      :scope_kind,
      :scope_id,
      :permission,
      :invite_id,
      :revoked_at
    ])
    |> validate_required([:workspace_id, :user_id, :id, :scope_kind, :permission, :invite_id])
    |> validate_inclusion(:scope_kind, ~w(workspace document folder share))
    |> validate_inclusion(:permission, ~w(view edit))
    |> validate_target_scope()
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:invite_id)
  end

  defp validate_target_scope(changeset) do
    scope = get_field(changeset, :scope_kind)
    scope_id = get_field(changeset, :scope_id)

    cond do
      scope == "workspace" and not is_nil(scope_id) ->
        add_error(changeset, :scope_id, "must be nil for workspace scope")

      scope in ["document", "folder", "share"] and is_nil(scope_id) ->
        add_error(changeset, :scope_id, "is required for document, folder, or share scope")

      true ->
        changeset
    end
  end
end
