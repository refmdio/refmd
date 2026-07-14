defmodule RefMD.Workers.MarkOverdueKeyRotations do
  @moduledoc false

  use Oban.Worker, queue: :default, unique: [period: 300]

  import Ecto.Query

  alias RefMD.Devices.Device
  alias RefMD.Documents.Document
  alias RefMD.Encryption.UserIdentityPublicKey
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces.{Workspace, WorkspaceMember, WorkspaceRole}

  @impl Oban.Worker
  def perform(_job) do
    mark_overdue(DateTime.utc_now())
    :ok
  end

  def mark_overdue(now) do
    %{
      workspaces: mark_workspaces(now),
      documents: mark_documents(now),
      identities: mark_identities(now)
    }
  end

  defp mark_workspaces(now) do
    eligible_initiators =
      from(wm in WorkspaceMember,
        join: role in WorkspaceRole,
        on: role.id == wm.role_id and role.workspace_id == wm.workspace_id,
        join: user in User,
        on: user.id == wm.user_id,
        join: device in Device,
        on: device.user_id == wm.user_id,
        where:
          user.account_type != "guest" and role.base_role in ["owner", "admin"] and
            is_nil(device.revoked_at) and
            is_nil(device.identity_wipe_required_at),
        distinct: wm.workspace_id,
        order_by: [
          asc: wm.workspace_id,
          asc: fragment("CASE ? WHEN 'owner' THEN 0 ELSE 1 END", role.base_role),
          asc: wm.user_id
        ],
        select: %{workspace_id: wm.workspace_id, user_id: wm.user_id}
      )

    from(w in Workspace,
      join: initiator in subquery(eligible_initiators),
      on: initiator.workspace_id == w.id,
      where:
        w.current_kek_version > 0 and w.needs_kek_rotation == false and
          (is_nil(w.kek_rotation_due_at) or w.kek_rotation_due_at <= ^now),
      update: [
        set: [
          needs_kek_rotation: true,
          kek_rotation_initiator_user_id: initiator.user_id
        ]
      ]
    )
    |> Repo.update_all([])
  end

  defp mark_documents(now) do
    from(d in Document,
      where:
        is_nil(d.archived_at) and d.needs_dek_rotation == false and
          (is_nil(d.dek_rotation_due_at) or d.dek_rotation_due_at <= ^now)
    )
    |> Repo.update_all(set: [needs_dek_rotation: true, dek_rotation_reason: "time_based"])
  end

  defp mark_identities(now) do
    from(k in UserIdentityPublicKey,
      where:
        k.lifecycle_state == "current" and k.needs_rotation == false and
          (is_nil(k.rotation_due_at) or k.rotation_due_at <= ^now)
    )
    |> Repo.update_all(set: [needs_rotation: true])
  end
end
