defmodule RefMDWeb.GuestInvitationControllerTest do
  use RefMDWeb.ConnCase, async: true

  import Ecto.Query

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces

  alias RefMD.Workspaces.WorkspaceGuestGrant

  test "workspace and guest invitation APIs are available" do
    user_id = Ecto.UUID.generate()

    assert {:error, :missing_device} =
             Workspaces.accept_invitation(
               "token-hash",
               user_id,
               "user@example.com",
               %{}
             )

    assert [] = Workspaces.list_guest_invitations(Ecto.UUID.generate())

    assert {:error, :not_found} =
             Workspaces.redeem_guest_invitation("token-hash", %{}, %{})
  end

  test "workspace guest invitation lookup uses bootstrap scope id", %{conn: conn} do
    workspace_ctx = guest_workspace()
    raw_token = :crypto.strong_rand_bytes(32)
    token = Base.url_encode64(raw_token, padding: false)
    token_hash = Base.url_encode64(:crypto.hash(:sha256, raw_token), padding: false)

    guest_invitation!(workspace_ctx, max_redemptions: 1, token_hash: token_hash)

    conn = get(conn, "/api/invitations/lookup?token=#{token}")

    assert %{
             "kind" => "guest",
             "scope_kind" => "workspace",
             "scope_id" => "none"
           } = json_response(conn, 200)
  end

  test "active guest admission can re-enter from the same device without consuming another redemption" do
    workspace_ctx = guest_workspace()
    invitation_ctx = guest_invitation!(workspace_ctx, max_redemptions: 1)
    invitation = invitation_ctx.invitation
    attrs = guest_redeem_attrs()

    assert {:ok, first} = redeem_guest_invitation(invitation_ctx, attrs)
    assert first.guest_user_id == attrs.guest_user_id
    assert first.guest_device_id == attrs.device_id

    assert {:ok, second} = Workspaces.redeem_guest_invitation(invitation.token_hash, attrs, %{})
    assert second.guest_user_id == attrs.guest_user_id
    assert second.guest_device_id == attrs.device_id

    assert Repo.reload!(invitation).redemption_count == 1

    assert {:error, :invitation_redemptions_exhausted} =
             redeem_guest_invitation(invitation_ctx, guest_redeem_attrs())
  end

  test "active guest admissions count toward the guest member limit" do
    workspace_ctx = guest_workspace(guest_member_limit: 1)
    invitation_ctx = guest_invitation!(workspace_ctx, max_redemptions: 2)

    assert {:ok, _first} = redeem_guest_invitation(invitation_ctx, guest_redeem_attrs())

    assert {:error, :guest_member_limit_reached} =
             redeem_guest_invitation(invitation_ctx, guest_redeem_attrs())
  end

  test "existing guest redeeming a different invitation refreshes the active grant" do
    workspace_ctx = guest_workspace()
    %{workspace: workspace} = workspace_ctx
    first_invitation_ctx = guest_invitation!(workspace_ctx, max_redemptions: 1)
    attrs = guest_redeem_attrs()

    assert {:ok, first} = redeem_guest_invitation(first_invitation_ctx, attrs)

    second_invitation_ctx = guest_invitation!(workspace_ctx, max_redemptions: 1)
    second_invitation = second_invitation_ctx.invitation

    assert {:ok, second} = redeem_guest_invitation(second_invitation_ctx, attrs)

    assert second.guest_user_id == first.guest_user_id
    assert second.guest_device_id == first.guest_device_id

    grant =
      from(g in WorkspaceGuestGrant,
        where: g.workspace_id == ^workspace.id and g.user_id == ^first.guest_user_id
      )
      |> Repo.one!()

    assert grant.invite_id == second_invitation.id

    assert Repo.reload!(second_invitation).redemption_count == 1

    assert {:error, :invitation_redemptions_exhausted} =
             redeem_guest_invitation(second_invitation_ctx, guest_redeem_attrs())
  end

  defp guest_workspace(attrs \\ []) do
    owner_id = Ecto.UUID.generate()
    owner_device_id = Ecto.UUID.generate()
    owner_identity_private = hybrid_signing_private_key_material("identity", owner_id)
    owner_device_private = hybrid_signing_private_key_material("device", owner_device_id)
    {owner_identity_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)
    {owner_device_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)

    Repo.insert!(%User{
      id: owner_id,
      email: "owner-guest-invite-#{owner_id}@example.com",
      name: "Owner",
      account_type: "registered"
    })

    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Guest Invite Test")

    owner_role =
      Repo.get_by!(Workspaces.WorkspaceRole, workspace_id: workspace.id, base_role: "owner")

    {1, [workspace]} =
      from(w in Workspaces.Workspace, where: w.id == ^workspace.id, select: w)
      |> Repo.update_all(
        set: [
          guest_invites_enabled: true,
          guest_member_limit: Keyword.get(attrs, :guest_member_limit),
          current_kek_version: 1,
          min_kek_version: 1
        ]
      )

    insert_test_workspace_key_directory!(
      workspace.id,
      owner_id,
      owner_role.id,
      owner_identity_private,
      hybrid_encryption_public_key_material("identity", owner_id, owner_identity_x25519_public).public,
      owner_device_private,
      hybrid_encryption_public_key_material("device", owner_device_id, owner_device_x25519_public).public
    )

    %{
      workspace: workspace,
      owner_id: owner_id,
      owner_device_id: owner_device_id,
      owner_device_private: owner_device_private
    }
  end

  defp guest_invitation!(workspace_ctx, attrs) do
    workspace = workspace_ctx.workspace
    token_hash = Keyword.get(attrs, :token_hash, token_hash())
    invitation_id = Ecto.UUID.generate()
    bootstrap_key_commitment = bootstrap_key_commitment()
    encrypted_bootstrap_package = encrypted_bootstrap_package(workspace.id)
    bootstrap_package_hash = context_hash(encrypted_bootstrap_package)

    bootstrap_package_key_recipient_wrap =
      encrypted_bootstrap_package["package_key_recipient_wrap"]

    bootstrap_package_key_maintenance_wrap =
      encrypted_bootstrap_package["package_key_maintenance_wrap"]

    capability_context_hash =
      context_hash(%{
        "guest_invitation_id" => invitation_id,
        "permission" => "view",
        "scope_id" => "none",
        "scope_kind" => "workspace",
        "workspace_id" => workspace.id
      })

    expires_at = DateTime.add(DateTime.utc_now(), 3600, :second)

    redeem_authority_private =
      hybrid_signing_private_key_material("invitation_redeem_authority", invitation_id)

    key_directory =
      guest_invitation_created_key_directory_append(%{
        workspace_id: workspace.id,
        actor_user_id: workspace_ctx.owner_id,
        actor_device_id: workspace_ctx.owner_device_id,
        actor_private_material: workspace_ctx.owner_device_private,
        invitation_id: invitation_id,
        permission: "view",
        kek_version: 1,
        expires_at: expires_at,
        encrypted_bootstrap_package: encrypted_bootstrap_package,
        bootstrap_key_commitment: bootstrap_key_commitment,
        bootstrap_package_hash: bootstrap_package_hash,
        capability_context_hash: capability_context_hash,
        redeem_authority_private_material: redeem_authority_private
      })

    {:ok, invitation} =
      Workspaces.create_guest_invitation(%{
        workspace_id: workspace.id,
        invitation_id: invitation_id,
        token_hash: token_hash,
        token_prefix: String.slice(token_hash, 0, 4),
        scope_kind: "workspace",
        scope_id: nil,
        permission: "view",
        kek_version: 1,
        bootstrap_key_commitment: bootstrap_key_commitment,
        encrypted_bootstrap_package: encrypted_bootstrap_package,
        bootstrap_package_hash: bootstrap_package_hash,
        bootstrap_package_key_recipient_wrap: bootstrap_package_key_recipient_wrap,
        bootstrap_package_key_maintenance_wrap: bootstrap_package_key_maintenance_wrap,
        bootstrap_suite_id: "refmd-v2-invitation-bootstrap-xchacha20poly1305",
        capability_context_hash: capability_context_hash,
        max_redemptions: Keyword.fetch!(attrs, :max_redemptions),
        invited_by: workspace_ctx.owner_id,
        expires_at: expires_at,
        key_directory: key_directory
      })

    %{invitation: invitation, redeem_authority_private_material: redeem_authority_private}
  end

  defp redeem_guest_invitation(invitation_ctx, attrs) do
    invitation = invitation_ctx.invitation

    key_directory =
      guest_invitation_redeemed_key_directory_append(
        invitation,
        attrs,
        invitation_ctx.redeem_authority_private_material
      )

    Workspaces.redeem_guest_invitation(invitation.token_hash, attrs, %{}, key_directory)
  end

  defp guest_redeem_attrs do
    guest_user_id = Ecto.UUID.generate()
    device_id = Ecto.UUID.generate()
    identity_private = hybrid_signing_private_key_material("identity", guest_user_id)
    identity_public = hybrid_signing_public_key_material(identity_private)
    {identity_x25519_public, _identity_x25519_private} = :crypto.generate_key(:ecdh, :x25519)

    identity_encryption =
      hybrid_encryption_public_key_material("identity", guest_user_id, identity_x25519_public)

    device_signing = hybrid_device_material(device_id)
    {device_x25519_public, _device_x25519_private} = :crypto.generate_key(:ecdh, :x25519)

    device_encryption =
      hybrid_encryption_public_key_material("device", device_id, device_x25519_public)

    client_nonce = :crypto.strong_rand_bytes(16)
    pending_registration_challenge_hash = Hash.blake3_base64url("registration:" <> device_id)

    approval_signature =
      sign_genesis_device_bootstrap(
        identity_private,
        device_id,
        device_signing.public,
        device_x25519_public,
        device_encryption.public,
        client_nonce
      )

    %{
      guest_user_id: guest_user_id,
      device_id: device_id,
      device_hybrid_encryption_public_key_material: device_encryption.public,
      device_hybrid_signing_public_key_material: device_signing.public,
      identity_hybrid_encryption_public_key_material: identity_encryption.public,
      identity_hybrid_signing_public_key_material: identity_public,
      approval_signature: approval_signature,
      client_nonce: client_nonce,
      pending_registration_challenge_hash: pending_registration_challenge_hash,
      device_name: "Guest Browser",
      device_type: "browser"
    }
  end

  defp token_hash do
    :crypto.strong_rand_bytes(32)
    |> Base.url_encode64(padding: false)
  end

  defp bootstrap_key_commitment do
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  end

  defp context_hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()

  defp encrypted_bootstrap_package(workspace_id) do
    %{
      "protocol" => "refmd.guest-invitation-bootstrap",
      "version" => 1,
      "suite_id" => "refmd-v2-invitation-bootstrap-xchacha20poly1305",
      "workspace_id" => workspace_id,
      "kek_version" => 1,
      "aad" => %{
        "protocol" => "refmd.guest-invitation-bootstrap",
        "version" => 1,
        "suite_id" => "refmd-v2-invitation-bootstrap-xchacha20poly1305",
        "workspace_id" => workspace_id,
        "guest_invitation_id" => Ecto.UUID.generate(),
        "scope_kind" => "workspace",
        "scope_id" => "none",
        "permission" => "view",
        "key_version_context" => %{
          "workspace_kek_version" => 1,
          "share_key_version" => "NOT_APPLICABLE",
          "dek_version" => "NOT_APPLICABLE"
        },
        "token_hash" => token_hash()
      },
      "encrypted_payload" => %{
        "nonce" => :crypto.strong_rand_bytes(24) |> Base.url_encode64(padding: false),
        "ciphertext" => :crypto.strong_rand_bytes(160) |> Base.url_encode64(padding: false)
      },
      "package_key_recipient_wrap" => %{
        "nonce" => :crypto.strong_rand_bytes(24) |> Base.url_encode64(padding: false),
        "ciphertext" => :crypto.strong_rand_bytes(48) |> Base.url_encode64(padding: false)
      },
      "package_key_maintenance_wrap" => %{
        "kek_version" => 1,
        "nonce" => :crypto.strong_rand_bytes(24) |> Base.url_encode64(padding: false),
        "ciphertext" => :crypto.strong_rand_bytes(48) |> Base.url_encode64(padding: false)
      }
    }
  end
end
