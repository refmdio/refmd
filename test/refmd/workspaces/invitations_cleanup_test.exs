defmodule RefMD.Workspaces.InvitationsCleanupTest do
  use RefMD.DataCase, async: true

  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workers.CleanupInvitations
  alias RefMD.Workspaces

  alias RefMD.Workspaces.{
    GuestInvitation,
    WorkspaceInvitation
  }

  test "worker deletes expired workspace invitations and unused guest invitations" do
    user = insert_user!()
    {:ok, workspace} = Workspaces.create_default_workspace(user.id, "Invitation cleanup")

    now = DateTime.utc_now()

    expired_workspace_invitation =
      insert_workspace_invitation!(workspace.id, user, DateTime.add(now, -60, :second))

    active_workspace_invitation =
      insert_workspace_invitation!(workspace.id, user, DateTime.add(now, 60, :second))

    expired_unused_guest_invitation =
      insert_guest_invitation!(workspace.id, user, DateTime.add(now, -60, :second),
        redemption_count: 0
      )

    expired_redeemed_guest_invitation =
      insert_guest_invitation!(workspace.id, user, DateTime.add(now, -60, :second),
        redemption_count: 1
      )

    active_guest_invitation =
      insert_guest_invitation!(workspace.id, user, DateTime.add(now, 60, :second),
        redemption_count: 0
      )

    assert :ok = CleanupInvitations.perform(%Oban.Job{})

    refute Repo.get(WorkspaceInvitation, expired_workspace_invitation.id)
    assert Repo.get(WorkspaceInvitation, active_workspace_invitation.id)

    refute Repo.get(GuestInvitation, expired_unused_guest_invitation.id)
    assert Repo.get(GuestInvitation, expired_redeemed_guest_invitation.id)
    assert Repo.get(GuestInvitation, active_guest_invitation.id)
  end

  test "cleanup worker is scheduled" do
    oban_config = Application.fetch_env!(:refmd, Oban)

    {Oban.Plugins.Cron, cron_opts} =
      Enum.find(oban_config[:plugins], &match?({Oban.Plugins.Cron, _}, &1))

    assert {"0 3 * * *", CleanupInvitations} in cron_opts[:crontab]
  end

  test "cleanup worker uses the Workspaces facade" do
    source = File.read!("lib/refmd/workers/cleanup_invitations.ex")

    refute source =~ "RefMD.Workspaces.Invitations"
    refute source =~ "RefMD.Workspaces.Guests.Invitations"
    assert source =~ "Workspaces.cleanup_expired_invitations()"
  end

  defp insert_user! do
    uniq = System.unique_integer([:positive])

    Repo.insert!(%User{
      id: Ecto.UUID.generate(),
      email: "invitation-cleanup-#{uniq}@example.com",
      name: "Invitation Cleanup #{uniq}"
    })
  end

  defp insert_workspace_invitation!(workspace_id, user, expires_at) do
    token_hash = hash_value()

    Repo.insert!(%WorkspaceInvitation{
      id: Ecto.UUID.generate(),
      workspace_id: workspace_id,
      token_hash: token_hash,
      token_prefix: String.slice(token_hash, 0, 4),
      invited_by: user.id,
      invited_email: "invitee-#{System.unique_integer([:positive])}@example.com",
      kek_version: 1,
      bootstrap_key_commitment: hash_value(),
      encrypted_bootstrap_package: %{"version" => 1},
      bootstrap_package_hash: hash_value(),
      bootstrap_package_key_recipient_wrap: %{"version" => 1},
      bootstrap_package_key_maintenance_wrap: %{"version" => 1},
      bootstrap_suite_id: "test-suite",
      capability_context_hash: hash_value(),
      is_used: false,
      expires_at: expires_at,
      created_at: DateTime.add(expires_at, -3600, :second)
    })
  end

  defp insert_guest_invitation!(workspace_id, user, expires_at, opts) do
    token_hash = hash_value()
    redemption_count = Keyword.fetch!(opts, :redemption_count)

    Repo.insert!(%GuestInvitation{
      id: Ecto.UUID.generate(),
      workspace_id: workspace_id,
      token_hash: token_hash,
      token_prefix: String.slice(token_hash, 0, 4),
      scope_kind: "workspace",
      permission: "view",
      kek_version: 1,
      bootstrap_key_commitment: hash_value(),
      encrypted_bootstrap_package: %{"version" => 1},
      bootstrap_package_hash: hash_value(),
      bootstrap_package_key_recipient_wrap: %{"version" => 1},
      bootstrap_package_key_maintenance_wrap: %{"version" => 1},
      bootstrap_suite_id: "test-suite",
      capability_context_hash: hash_value(),
      max_redemptions: 1,
      redemption_count: redemption_count,
      invited_by: user.id,
      expires_at: expires_at,
      created_at: DateTime.add(expires_at, -3600, :second)
    })
  end

  defp hash_value do
    32
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end
end
