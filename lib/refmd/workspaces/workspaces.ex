defmodule RefMD.Workspaces do
  @moduledoc """
  The Workspaces context. Manages workspaces, members, roles, and permissions.
  """

  import Ecto.Query

  alias RefMD.Repo

  alias RefMD.Workspaces.{
    GuestInvitation,
    Workspace,
    WorkspaceDeviceWipeRequirement,
    WorkspaceGuestGrant,
    WorkspaceInvitation,
    WorkspaceMember,
    WorkspaceRole
  }

  alias RefMD.Workspaces.Roles, as: WRoles

  # ── Members (delegated to RefMD.Workspaces.Members) ──

  defdelegate list_workspace_member_user_ids(workspace_id), to: RefMD.Workspaces.Members
  defdelegate get_workspace_member(workspace_id, user_id), to: RefMD.Workspaces.Members
  defdelegate get_member_role(workspace_id, user_id), to: RefMD.Workspaces.Members
  defdelegate get_member_with_role(workspace_id, user_id), to: RefMD.Workspaces.Members
  defdelegate list_workspace_members(workspace_id), to: RefMD.Workspaces.Members

  @spec get_member_permission_version(Ecto.UUID.t(), Ecto.UUID.t()) :: pos_integer()
  def get_member_permission_version(workspace_id, user_id) do
    from(m in WorkspaceMember,
      where: m.workspace_id == ^workspace_id and m.user_id == ^user_id,
      select: m.permission_version,
      limit: 1
    )
    |> Repo.one()
    |> case do
      version when is_integer(version) and version > 0 -> version
      _ -> 1
    end
  end

  @spec workspace_device_wipe_required?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def workspace_device_wipe_required?(workspace_id, device_id) do
    from(r in WorkspaceDeviceWipeRequirement,
      where: r.workspace_id == ^workspace_id and r.device_id == ^device_id
    )
    |> Repo.exists?()
  end

  defdelegate change_member_role(
                workspace_id,
                target_user_id,
                new_role_id,
                actor_user_id,
                key_directory
              ),
              to: RefMD.Workspaces.Members

  defdelegate remove_member(workspace_id, target_user_id, actor_user_id, key_directory),
    to: RefMD.Workspaces.Members

  # ── Roles (delegated to RefMD.Workspaces.Roles) ──

  @spec permission_defined?(String.t()) :: boolean()
  defdelegate permission_defined?(permission), to: RefMD.Workspaces.Roles.Authorization

  @spec effective_permissions(WorkspaceRole.t() | map()) :: MapSet.t(String.t())
  defdelegate effective_permissions(role), to: RefMD.Workspaces.Roles.Authorization

  @spec permission_granted?(WorkspaceRole.t() | map(), String.t()) :: boolean()
  defdelegate permission_granted?(role, permission), to: RefMD.Workspaces.Roles.Authorization

  @spec validate_role_assignment(WorkspaceRole.t() | map(), WorkspaceRole.t() | map()) ::
          :ok | {:error, :role_escalation | :permission_escalation}
  defdelegate validate_role_assignment(actor_role, target_role),
    to: RefMD.Workspaces.Roles.Authorization

  defdelegate list_workspace_roles(workspace_id), to: RefMD.Workspaces.Roles

  @spec create_custom_role(Ecto.UUID.t(), String.t(), String.t(), list() | nil) ::
          {:ok, WorkspaceRole.t()} | {:error, term()}
  def create_custom_role(workspace_id, name, base_role, permissions \\ nil),
    do: WRoles.create_custom_role(workspace_id, name, base_role, permissions)

  @spec update_role(WorkspaceRole.t(), map(), keyword()) ::
          {:ok, WorkspaceRole.t()} | {:error, term()}
  def update_role(role, attrs, opts \\ []),
    do: WRoles.update_role(role, attrs, opts)

  defdelegate delete_role(role), to: RefMD.Workspaces.Roles
  defdelegate get_default_role_with_permissions(workspace_id), to: RefMD.Workspaces.Roles
  defdelegate get_role_with_permissions(workspace_id, role_id), to: RefMD.Workspaces.Roles
  defdelegate get_default_role(workspace_id), to: RefMD.Workspaces.Roles

  # ── Invitations (delegated to RefMD.Workspaces.Invitations) ──

  defdelegate create_invitation(attrs), to: RefMD.Workspaces.Invitations

  defdelegate invitation_lookup_ancestry(
                workspace_id,
                created_event_type,
                invitation_body_key,
                invitation_id,
                current_checkpoint
              ),
              to: RefMD.Workspaces.Invitations,
              as: :lookup_ancestry

  defdelegate validate_invitation_encrypted_bootstrap_package(package, workspace_id, key_version),
    to: RefMD.Workspaces.Invitations,
    as: :validate_encrypted_bootstrap_package

  defdelegate accept_invitation(
                token_hash,
                user_id,
                user_email,
                requester_device_id,
                admission \\ nil
              ),
              to: RefMD.Workspaces.Invitations

  defdelegate list_active_invitations(workspace_id), to: RefMD.Workspaces.Invitations
  defdelegate revoke_invitation(workspace_id, invitation_id), to: RefMD.Workspaces.Invitations

  defdelegate revoke_invitation(workspace_id, invitation_id, actor_user_id, key_directory),
    to: RefMD.Workspaces.Invitations

  defdelegate revoke_invitations_for_email(workspace_id, email),
    to: RefMD.Workspaces.Invitations

  defdelegate revoke_all_active_invitations(workspace_ids), to: RefMD.Workspaces.Invitations
  defdelegate revoke_all_active_guest_invitations(workspace_ids), to: RefMD.Workspaces.Guests

  @spec lookup_invitation_kind(String.t()) :: {:ok, :workspace | :guest} | {:error, :not_found}
  def lookup_invitation_kind(token_hash) when is_binary(token_hash) do
    cond do
      Repo.exists?(from(i in WorkspaceInvitation, where: i.token_hash == ^token_hash)) ->
        {:ok, :workspace}

      Repo.exists?(from(i in GuestInvitation, where: i.token_hash == ^token_hash)) ->
        {:ok, :guest}

      true ->
        {:error, :not_found}
    end
  end

  @spec lookup_invitation(String.t()) ::
          {:ok, WorkspaceInvitation.t() | GuestInvitation.t()} | {:error, :not_found}
  def lookup_invitation(token_hash) when is_binary(token_hash) do
    case Repo.one(from(i in WorkspaceInvitation, where: i.token_hash == ^token_hash, limit: 1)) do
      %WorkspaceInvitation{} = invitation ->
        {:ok, invitation}

      nil ->
        case Repo.one(from(i in GuestInvitation, where: i.token_hash == ^token_hash, limit: 1)) do
          %GuestInvitation{} = invitation -> {:ok, invitation}
          nil -> {:error, :not_found}
        end
    end
  end

  @spec get_guest_invitation_redeem_context(String.t()) ::
          {:ok, GuestInvitation.t()} | {:error, :not_found}
  def get_guest_invitation_redeem_context(token_hash) when is_binary(token_hash) do
    case Repo.one(from(i in GuestInvitation, where: i.token_hash == ^token_hash, limit: 1)) do
      %GuestInvitation{} = invitation -> {:ok, invitation}
      nil -> {:error, :not_found}
    end
  end

  @spec revoke_all_active_access_invitations([Ecto.UUID.t()]) :: %{
          member_invitations: non_neg_integer(),
          guest_invitations: non_neg_integer()
        }
  def revoke_all_active_access_invitations(workspace_ids) do
    %{
      member_invitations: revoke_all_active_invitations(workspace_ids),
      guest_invitations: revoke_all_active_guest_invitations(workspace_ids)
    }
  end

  # ── Guest Invitations (delegated to RefMD.Workspaces.Guests) ──

  defdelegate guest_user?(user_id), to: RefMD.Workspaces.Guests

  defdelegate guest_role_for_active_grants(workspace_id, user_id), to: RefMD.Workspaces.Guests

  defdelegate active_guest_device_workspace_id(user_id, device_id), to: RefMD.Workspaces.Guests

  defdelegate authorize_guest_permission(workspace_id, user_id, permission, document \\ nil),
    to: RefMD.Workspaces.Guests,
    as: :authorize_permission

  defdelegate authorize_guest_document_create(workspace_id, user_id, doc_type, parent_id),
    to: RefMD.Workspaces.Guests,
    as: :authorize_document_create

  defdelegate authorize_guest_document_reorder(workspace_id, user_id, document_id, parent_id),
    to: RefMD.Workspaces.Guests,
    as: :authorize_document_reorder

  defdelegate filter_guest_documents(workspace_id, user_id, documents),
    to: RefMD.Workspaces.Guests,
    as: :filter_documents

  defdelegate create_guest_invitation(attrs), to: RefMD.Workspaces.Guests
  defdelegate list_guest_invitations(workspace_id), to: RefMD.Workspaces.Guests

  defdelegate revoke_guest_invitation(workspace_id, invitation_id, actor_user_id),
    to: RefMD.Workspaces.Guests

  defdelegate revoke_guest_invitation(workspace_id, invitation_id, actor_user_id, key_directory),
    to: RefMD.Workspaces.Guests

  defdelegate redeem_guest_invitation(token_hash, device_attrs, session_attrs),
    to: RefMD.Workspaces.Guests

  defdelegate redeem_guest_invitation(token_hash, device_attrs, session_attrs, key_directory),
    to: RefMD.Workspaces.Guests

  defdelegate revoke_guest_grants(workspace_id, user_id), to: RefMD.Workspaces.Guests
  defdelegate guest_invites_enabled?(workspace_id), to: RefMD.Workspaces.Guests

  @spec share_links_enabled?(Ecto.UUID.t()) :: boolean()
  def share_links_enabled?(workspace_id) when is_binary(workspace_id) do
    from(w in Workspace, where: w.id == ^workspace_id, select: w.share_links_enabled)
    |> Repo.one()
    |> Kernel.==(true)
  end

  @spec public_publishing_enabled?(Ecto.UUID.t()) :: boolean()
  def public_publishing_enabled?(workspace_id) when is_binary(workspace_id) do
    from(w in Workspace, where: w.id == ^workspace_id, select: w.public_publishing_enabled)
    |> Repo.one()
    |> Kernel.==(true)
  end

  # ── Workspace CRUD ──────────────────────────────

  defdelegate create_default_workspace(user_id, name), to: RefMD.Workspaces.Creation
  defdelegate create_workspace(user_id, name, opts \\ %{}), to: RefMD.Workspaces.Creation

  @spec get_workspace(Ecto.UUID.t()) :: Workspace.t() | nil
  def get_workspace(id), do: Repo.get(Workspace, id)

  @spec update_workspace(Workspace.t(), map()) ::
          {:ok, Workspace.t()} | {:error, Ecto.Changeset.t()}
  def update_workspace(%Workspace{} = workspace, attrs) do
    workspace
    |> Workspace.update_changeset(attrs)
    |> Repo.update()
    |> maybe_recompute_plugin_user_policy(attrs)
  end

  defp maybe_recompute_plugin_user_policy({:ok, workspace}, attrs) do
    if Map.has_key?(attrs, :plugin_user_policy) do
      case RefMD.Plugins.recompute_workspace_user_plugin_policy(workspace.id) do
        :ok -> {:ok, workspace}
        {:error, reason} -> {:error, reason}
      end
    else
      {:ok, workspace}
    end
  end

  defp maybe_recompute_plugin_user_policy(result, _attrs), do: result

  @spec delete_workspace(Workspace.t()) :: {:ok, Workspace.t()} | {:error, Ecto.Changeset.t()}
  def delete_workspace(%Workspace{} = workspace) do
    Repo.delete(workspace)
  end

  # ── KEK Version ─────────────────────────────────

  @spec update_current_kek_version(Ecto.UUID.t(), integer()) ::
          {non_neg_integer(), nil | [term()]}
  def update_current_kek_version(workspace_id, version) do
    from(w in Workspace, where: w.id == ^workspace_id)
    |> Repo.update_all(set: [current_kek_version: version])
  end

  @spec initialize_kek_version(Ecto.UUID.t()) :: {non_neg_integer(), nil | [term()]}
  def initialize_kek_version(workspace_id) do
    from(w in Workspace, where: w.id == ^workspace_id and w.current_kek_version == 0)
    |> Repo.update_all(set: [current_kek_version: 1])
  end

  # ── User Workspace Queries ──────────────────────

  @spec get_user_default_workspace(Ecto.UUID.t()) :: Workspace.t() | nil
  def get_user_default_workspace(user_id) do
    from(wm in WorkspaceMember,
      join: w in Workspace,
      on: w.id == wm.workspace_id,
      where: wm.user_id == ^user_id and wm.is_default == true,
      select: w,
      limit: 1
    )
    |> Repo.one()
  end

  @spec list_user_workspaces(Ecto.UUID.t()) :: [
          %{
            workspace: Workspace.t(),
            is_default: boolean(),
            role_id: Ecto.UUID.t(),
            base_role: String.t()
          }
        ]
  def list_user_workspaces(user_id) do
    from(wm in WorkspaceMember,
      join: w in Workspace,
      on: w.id == wm.workspace_id,
      join: r in WorkspaceRole,
      on: r.id == wm.role_id,
      where: wm.user_id == ^user_id,
      select: %{
        workspace: w,
        is_default: wm.is_default,
        role_id: wm.role_id,
        base_role: r.base_role
      },
      order_by: [asc: w.name]
    )
    |> Repo.all()
  end

  @spec list_discoverable_workspaces(Ecto.UUID.t()) :: [
          %{
            workspace: Workspace.t(),
            is_default: boolean(),
            role_id: Ecto.UUID.t(),
            base_role: String.t()
          }
        ]
  def list_discoverable_workspaces(user_id) do
    if guest_user?(user_id) do
      from(g in WorkspaceGuestGrant,
        join: w in Workspace,
        on: w.id == g.workspace_id,
        join: r in WorkspaceRole,
        on:
          r.workspace_id == g.workspace_id and r.base_role == "guest" and
            is_nil(r.catalog_version),
        where: g.user_id == ^user_id and is_nil(g.revoked_at),
        select: %{
          workspace: w,
          is_default: false,
          role_id: r.id,
          base_role: r.base_role
        },
        distinct: w.id,
        order_by: [asc: w.name]
      )
      |> Repo.all()
    else
      list_user_workspaces(user_id)
    end
  end

  @spec get_user_workspace_ids(Ecto.UUID.t()) :: [Ecto.UUID.t()]
  def get_user_workspace_ids(user_id) do
    from(wm in WorkspaceMember,
      where: wm.user_id == ^user_id,
      select: wm.workspace_id
    )
    |> Repo.all()
  end

  @spec get_discoverable_workspace_ids(Ecto.UUID.t()) :: [Ecto.UUID.t()]
  def get_discoverable_workspace_ids(user_id) do
    if guest_user?(user_id) do
      from(g in WorkspaceGuestGrant,
        where: g.user_id == ^user_id and is_nil(g.revoked_at),
        select: g.workspace_id,
        distinct: true
      )
      |> Repo.all()
    else
      get_user_workspace_ids(user_id)
    end
  end

  @spec get_user_workspace_ids_with_kek_version(Ecto.UUID.t()) :: [{Ecto.UUID.t(), integer()}]
  def get_user_workspace_ids_with_kek_version(user_id) do
    from(wm in WorkspaceMember,
      join: w in Workspace,
      on: w.id == wm.workspace_id,
      where: wm.user_id == ^user_id,
      select: {wm.workspace_id, w.current_kek_version}
    )
    |> Repo.all()
  end

  # ── KEK Rotation ────────────────────────────────

  defdelegate mark_kek_rotation_needed(workspace_ids, initiator_user_id),
    to: RefMD.Workspaces.KekRotation

  defdelegate mark_dek_rotation_needed(workspace_ids), to: RefMD.Workspaces.KekRotation

  defdelegate start_kek_rotation(workspace_id, initiator_user_id, opts \\ []),
    to: RefMD.Workspaces.KekRotation

  defdelegate prepare_kek_rotation_completion(workspace_id, new_kek_version, opts \\ []),
    to: RefMD.Workspaces.KekRotation

  defdelegate complete_kek_rotation(workspace_id, new_kek_version, opts \\ []),
    to: RefMD.Workspaces.KekRotation

  defdelegate list_workspaces_needing_kek_rotation, to: RefMD.Workspaces.KekRotation

  defdelegate rotation_deletion_evidences_by_event_hash(event_hashes),
    to: RefMD.Workspaces.KekRotation
end
