defmodule RefMDWeb.GuestInvitationControllerTest do
  use RefMDWeb.ConnCase, async: true

  import Ecto.Query

  alias RefMD.{Auth, Documents, Encryption}
  alias RefMD.Crypto.{Hash, HybridEncryptionMaterial, JCS, Signature}
  alias RefMD.Devices.Device
  alias RefMD.Encryption.{KeyDirectory, RotationPolicy, WorkspaceEncryptedKey}
  alias RefMD.Repo
  alias RefMD.Sharing.{Share, ShareKey}
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.KekRotation.DeletionProofs

  alias RefMD.Workspaces.{
    InvitationDeliveryAttempt,
    WorkspaceDeviceWipeRequirement,
    WorkspaceGuestGrant,
    WorkspaceKekRotationDeletionEvidence,
    WorkspaceMember
  }

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

  test "scoped guest invitation binds the current share key without workspace crypto access", %{
    conn: conn
  } do
    workspace_ctx = guest_workspace()
    workspace = workspace_ctx.workspace

    {:ok, document} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace.id,
        "doc_type" => "document",
        "parent_id" => nil,
        "title" => "Scoped guest document",
        "encrypted_title" => <<1, 2, 3>>,
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1,
        "created_by" => workspace_ctx.owner_id
      })

    share = insert_scoped_guest_share!(document.id, workspace_ctx.owner_id)
    invitation_id = Ecto.UUID.generate()
    digest = Hash.blake3_base64url("scoped-guest-invitation:" <> invitation_id)
    token_hash = Hash.blake3_base64url("scoped-guest-token:" <> invitation_id)

    capability_context_hash =
      context_hash(%{
        "guest_invitation_id" => invitation_id,
        "permission" => "view",
        "scope_id" => document.id,
        "scope_kind" => "document",
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
        scope_kind: "document",
        scope_id: document.id,
        share_id: share.id,
        permission: "view",
        kek_version: nil,
        share_key_version: 1,
        dek_version: 1,
        expires_at: expires_at,
        bootstrap_key_commitment: digest,
        bootstrap_package_hash: digest,
        capability_context_hash: capability_context_hash,
        redeem_authority_private_material: redeem_authority_private
      })

    attrs = %{
      workspace_id: workspace.id,
      invitation_id: invitation_id,
      token_hash: token_hash,
      token_prefix: String.slice(token_hash, 0, 4),
      scope_kind: "document",
      scope_id: document.id,
      share_id: share.id,
      permission: "view",
      invited_by: workspace_ctx.owner_id,
      delivery_mode: "unknown_fragment",
      recipient_user_id: nil,
      recipient_device_ids: [],
      kek_version: nil,
      share_key_version: 1,
      dek_version: 1,
      bootstrap_key_commitment: digest,
      encrypted_bootstrap_package: %{"fixture" => "scoped-guest"},
      bootstrap_package_hash: digest,
      bootstrap_package_key_recipient_wrap: %{"fixture" => "scoped-guest"},
      bootstrap_package_key_maintenance_wrap: %{"fixture" => "scoped-guest"},
      bootstrap_suite_id: "refmd-v2-invitation-bootstrap-xchacha20poly1305",
      capability_context_hash: capability_context_hash,
      max_redemptions: 1,
      expires_at: expires_at,
      key_directory: key_directory
    }

    assert {:ok, invitation} = Workspaces.create_guest_invitation(attrs)
    assert invitation.share_id == share.id
    assert invitation.kek_version == nil
    assert invitation.share_key_version == 1
    assert invitation.dek_version == 1

    assert {:error, :invalid_key_version_context} =
             Workspaces.create_guest_invitation(%{
               attrs
               | invitation_id: Ecto.UUID.generate(),
                 token_hash: Hash.blake3_base64url("stale-scoped-guest-token"),
                 share_key_version: 2
             })

    guest_attrs = guest_redeem_attrs()

    assert {:ok, guest} =
             redeem_guest_invitation(
               %{
                 invitation: invitation,
                 redeem_authority_private_material: redeem_authority_private
               },
               guest_attrs
             )

    refute Encryption.active_workspace_scope_guest_device_admitted?(
             workspace.id,
             guest.guest_user_id,
             guest.guest_device_id
           )

    assert_workspace_crypto_rejected(conn, workspace.id, guest, guest_attrs)
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

  test "guest redemption requires distinct identity materials at the API boundary", %{conn: conn} do
    attrs = guest_redeem_attrs()

    body = %{
      token: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
      guest_user_id: attrs.guest_user_id,
      device_id: attrs.device_id,
      device_hybrid_encryption_public_key_material:
        attrs.device_hybrid_encryption_public_key_material,
      device_hybrid_signing_public_key_material: attrs.device_hybrid_signing_public_key_material,
      identity_hybrid_encryption_public_key_material:
        attrs.identity_hybrid_encryption_public_key_material,
      identity_hybrid_signing_public_key_material:
        attrs.identity_hybrid_signing_public_key_material,
      recoverable_identity_secret_record: attrs.recoverable_identity_secret_record,
      client_nonce: Base.url_encode64(attrs.client_nonce, padding: false),
      user_key_directory_events: attrs.user_key_directory_events,
      user_key_directory_checkpoint: attrs.user_key_directory_checkpoint,
      workspace_key_directory_events: [],
      workspace_key_directory_checkpoint: %{"payload" => %{}, "signatures" => []}
    }

    for field <- [
          :identity_hybrid_encryption_public_key_material,
          :identity_hybrid_signing_public_key_material,
          :recoverable_identity_secret_record
        ] do
      response = post(recycle(conn), "/api/guest/redeem", Map.delete(body, field))

      assert %{
               "error" => "invalid_request_schema",
               "details" => [%{"reason" => ":missing_field", "path" => [missing_field]}]
             } = json_response(response, 422)

      assert missing_field == Atom.to_string(field)
    end
  end

  test "active guest admission can re-enter from the same device without consuming another redemption" do
    workspace_ctx = guest_workspace()
    invitation_ctx = guest_invitation!(workspace_ctx, max_redemptions: 1)
    invitation = invitation_ctx.invitation
    attrs = guest_redeem_attrs()

    assert {:ok, first} = redeem_guest_invitation(invitation_ctx, attrs)
    assert first.guest_user_id == attrs.guest_user_id
    assert first.guest_device_id == attrs.device_id
    guest_device = Repo.get!(Device, first.guest_device_id)
    guest_identity = Encryption.get_user_identity_public_key(first.guest_user_id)
    user_checkpoint_payload = attrs.user_key_directory_checkpoint["payload"]

    assert guest_device.approval_signature == nil
    assert guest_device.approval_signature_surface == nil
    assert guest_device.approval_proof == nil
    assert guest_device.key_checkpoint_sequence == user_checkpoint_payload["sequence"]

    assert guest_device.key_checkpoint_hash ==
             Hash.blake3_base64url(JCS.canonical_bytes!(user_checkpoint_payload))

    assert guest_identity.pending_registration_challenge_hash == nil
    assert encrypted_identity = Encryption.get_user_encrypted_identity_key(attrs.guest_user_id)
    assert encrypted_identity.encryption_key_id == attrs.identity_encryption_key_id
    assert encrypted_identity.signing_key_id == attrs.identity_signing_key_id

    assert %{
             required_workspace_count: 1,
             required_workspace_targets: [
               %{workspace_id: workspace_id, key_version: workspace_key_version}
             ]
           } = Encryption.user_identity_rotation_status(attrs.guest_user_id)

    assert workspace_id == workspace_ctx.workspace.id
    assert workspace_key_version == workspace_ctx.workspace.current_kek_version

    assert {:ok, second} = Workspaces.redeem_guest_invitation(invitation.token_hash, attrs, %{})
    assert second.guest_user_id == attrs.guest_user_id
    assert second.guest_device_id == attrs.device_id

    assert Repo.reload!(invitation).redemption_count == 1

    assert {:error, :invitation_redemptions_exhausted} =
             redeem_guest_invitation(invitation_ctx, guest_redeem_attrs())
  end

  test "recipient-bound invitation re-entry accepts only its active guest device" do
    workspace_ctx = guest_workspace()
    invitation_ctx = guest_invitation!(workspace_ctx, max_redemptions: 1)
    attrs = guest_redeem_attrs()

    assert {:ok, first} = redeem_guest_invitation(invitation_ctx, attrs)

    invitation =
      invitation_ctx.invitation
      |> Ecto.Changeset.change(%{
        delivery_mode: "known_recipient",
        recipient_user_id: workspace_ctx.owner_id,
        recipient_device_ids: [workspace_ctx.owner_device_id]
      })
      |> Repo.update!()

    guest_account = %{user_id: first.guest_user_id, device_id: first.guest_device_id}

    assert {:ok, second} =
             Workspaces.redeem_guest_invitation(
               invitation.token_hash,
               attrs,
               %{},
               nil,
               guest_account
             )

    assert second.guest_user_id == first.guest_user_id
    assert second.guest_device_id == first.guest_device_id
    assert Repo.reload!(invitation).redemption_count == 1

    assert {:error, :recipient_mismatch} =
             Workspaces.redeem_guest_invitation(
               invitation.token_hash,
               attrs,
               %{},
               nil,
               %{guest_account | device_id: Ecto.UUID.generate()}
             )
  end

  test "guest workspace crypto access is bound to the admitted active device", %{conn: conn} do
    workspace_ctx = guest_workspace()
    wrong_workspace_ctx = guest_workspace()
    invitation_ctx = guest_invitation!(workspace_ctx, max_redemptions: 1)
    attrs = guest_redeem_attrs()

    assert {:ok, guest} = redeem_guest_invitation(invitation_ctx, attrs)

    assert Encryption.active_workspace_scope_guest_device_admitted?(
             workspace_ctx.workspace.id,
             guest.guest_user_id,
             guest.guest_device_id
           )

    refute Encryption.active_workspace_scope_guest_device_admitted?(
             workspace_ctx.workspace.id,
             guest.guest_user_id,
             Ecto.UUID.generate()
           )

    refute Encryption.active_workspace_scope_guest_device_admitted?(
             wrong_workspace_ctx.workspace.id,
             guest.guest_user_id,
             guest.guest_device_id
           )

    grant =
      Repo.get_by!(WorkspaceGuestGrant,
        workspace_id: workspace_ctx.workspace.id,
        user_id: guest.guest_user_id
      )

    owner_role =
      workspace_ctx.workspace.id
      |> Workspaces.list_workspace_roles()
      |> Enum.find(&(&1.base_role == "owner"))

    Repo.insert!(%WorkspaceMember{
      workspace_id: workspace_ctx.workspace.id,
      user_id: guest.guest_user_id,
      role_id: owner_role.id,
      is_default: false,
      joined_at: DateTime.utc_now()
    })

    for scope_kind <- ~w(document folder share) do
      grant
      |> Ecto.Changeset.change(scope_kind: scope_kind, scope_id: Ecto.UUID.generate())
      |> Repo.update!()

      assert {:error, :permission_denied} =
               Workspaces.authorize_workspace_guest_access(
                 workspace_ctx.workspace.id,
                 guest.guest_user_id
               )

      assert_workspace_crypto_rejected(
        conn,
        workspace_ctx.workspace.id,
        guest,
        attrs
      )
    end

    Repo.get_by!(WorkspaceGuestGrant,
      workspace_id: workspace_ctx.workspace.id,
      user_id: guest.guest_user_id
    )
    |> Ecto.Changeset.change(scope_kind: "workspace", scope_id: nil)
    |> Repo.update!()

    assert :ok =
             Workspaces.authorize_workspace_guest_access(
               workspace_ctx.workspace.id,
               guest.guest_user_id
             )

    assert_rotation_management_rejected(conn, workspace_ctx.workspace.id, guest, attrs)
    insert_workspace_key!(workspace_ctx, guest)

    key_path = "/api/encryption/workspaces/#{workspace_ctx.workspace.id}/keys"
    key_query = URI.encode_query(%{"device_id" => guest.guest_device_id})

    admitted_key_response =
      conn
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        Repo.get!(Device, guest.guest_device_id),
        attrs.device_signing_private_key,
        "GET",
        key_path,
        "",
        key_query
      )
      |> get(key_path <> "?" <> key_query)

    assert %{
             "current_kek_version" => 1,
             "keys" => [%{"key_version" => 1, "is_active" => true}]
           } = json_response(admitted_key_response, 200)

    {other_device, other_device_private} = insert_guest_device!(guest.guest_user_id)

    refute Encryption.active_workspace_scope_guest_device_admitted?(
             workspace_ctx.workspace.id,
             guest.guest_user_id,
             other_device.id
           )

    other_key_query = URI.encode_query(%{"device_id" => other_device.id})

    assert_raise ArgumentError, "rrp_actor_key_directory_inactive", fn ->
      recycle(conn)
      |> authed_conn(guest.guest_user_id, other_device.id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        other_device,
        other_device_private,
        "GET",
        key_path,
        "",
        other_key_query
      )
    end

    wrong_workspace_path =
      "/api/encryption/workspaces/#{wrong_workspace_ctx.workspace.id}/keys"

    wrong_workspace_query = URI.encode_query(%{"device_id" => guest.guest_device_id})

    wrong_workspace_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        Repo.get!(Device, guest.guest_device_id),
        attrs.device_signing_private_key,
        "GET",
        wrong_workspace_path,
        "",
        wrong_workspace_query
      )
      |> get(wrong_workspace_path <> "?" <> wrong_workspace_query)

    assert json_response(wrong_workspace_response, 403) == %{"error" => "not_a_member"}

    require_workspace_wipe!(workspace_ctx.workspace.id, guest.guest_device_id)

    wipe_path =
      "/api/encryption/workspaces/#{workspace_ctx.workspace.id}/kek-rotation/wipe-requirement"

    wipe_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        Repo.get!(Device, guest.guest_device_id),
        attrs.device_signing_private_key,
        "GET",
        wipe_path,
        ""
      )
      |> get(wipe_path)

    assert %{
             "required_kek_version" => 2,
             "rotation_completed_event_hash" => rotation_completed_event_hash
           } = json_response(wipe_response, 200)

    acknowledge_path = wipe_path <> "/acknowledge"

    acknowledge_body = %{
      "device_key_deletion_proof" =>
        signed_device_key_deletion_proof(
          workspace_ctx.workspace.id,
          guest.guest_user_id,
          guest.guest_device_id,
          attrs.device_signing_private_key,
          1,
          rotation_completed_event_hash
        )
    }

    acknowledge_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        Repo.get!(Device, guest.guest_device_id),
        attrs.device_signing_private_key,
        "POST",
        acknowledge_path,
        acknowledge_body
      )
      |> post(acknowledge_path, test_json_body(acknowledge_body))

    assert json_response(acknowledge_response, 200) == %{"ok" => true}

    grant |> Ecto.Changeset.change(revoked_at: DateTime.utc_now()) |> Repo.update!()

    revoked_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        Repo.get!(Device, guest.guest_device_id),
        attrs.device_signing_private_key,
        "GET",
        wipe_path,
        ""
      )
      |> get(wipe_path)

    assert json_response(revoked_response, 403) == %{"error" => "not_a_member"}

    grant |> Ecto.Changeset.change(revoked_at: nil) |> Repo.update!()

    guest_device = Repo.get!(Device, guest.guest_device_id)
    guest_device |> Ecto.Changeset.change(revoked_at: DateTime.utc_now()) |> Repo.update!()

    revoked_device_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        guest_device,
        attrs.device_signing_private_key,
        "GET",
        wipe_path,
        ""
      )
      |> get(wipe_path)

    assert json_response(revoked_device_response, 401) == %{"error" => "unauthorized"}
  end

  test "guest redemption exposes invitation authority ancestry for delta and reload verification" do
    workspace_ctx = guest_workspace()
    invitation_ctx = guest_invitation!(workspace_ctx, max_redemptions: 1)
    workspace_id = workspace_ctx.workspace.id
    anchor = KeyDirectory.current_pin("workspace", workspace_id)

    assert {:ok, _guest} = redeem_guest_invitation(invitation_ctx, guest_redeem_attrs())

    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)

    candidate_events =
      KeyDirectory.events_after_until(
        "workspace",
        workspace_id,
        anchor.event_head_sequence,
        checkpoint.covered_event_head_sequence
      )

    assert [created] =
             KeyDirectory.authority_events(
               "workspace",
               workspace_id,
               anchor.event_head_sequence,
               candidate_events,
               checkpoint
             )

    assert created.event_type == "guest_invitation_created"
    assert created.payload["body"]["guest_invitation_id"] == invitation_ctx.invitation.id

    assert [reloaded_created, reloaded_redeemed] =
             KeyDirectory.authority_events(
               "workspace",
               workspace_id,
               checkpoint.covered_event_head_sequence,
               [],
               checkpoint
             )

    assert reloaded_created.event_type == "guest_invitation_created"
    assert reloaded_redeemed.event_type == "guest_invitation_redeemed"
  end

  test "guest redemption domain rejects omitted identity materials without device fallback" do
    workspace_ctx = guest_workspace()
    invitation_ctx = guest_invitation!(workspace_ctx, max_redemptions: 1)
    attrs = guest_redeem_attrs()

    for field <- [
          :identity_hybrid_encryption_public_key_material,
          :identity_hybrid_signing_public_key_material
        ] do
      assert {:error, :invalid_guest_identity_materials} =
               Workspaces.redeem_guest_invitation(
                 invitation_ctx.invitation.token_hash,
                 Map.delete(attrs, field),
                 %{}
               )
    end
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

  test "known recipient guest redemption requires the bound active account device" do
    workspace_ctx = guest_workspace()
    invitation_ctx = guest_invitation!(workspace_ctx, max_redemptions: 1)

    invitation =
      invitation_ctx.invitation
      |> Ecto.Changeset.change(%{
        delivery_mode: "known_recipient",
        recipient_user_id: workspace_ctx.owner_id,
        recipient_device_ids: [workspace_ctx.owner_device_id]
      })
      |> Repo.update!()

    invitation_ctx = %{invitation_ctx | invitation: invitation}
    attrs = guest_redeem_attrs()

    recipient_account = %{
      user_id: workspace_ctx.owner_id,
      device_id: workspace_ctx.owner_device_id
    }

    assert {:error, :recipient_mismatch} =
             Workspaces.redeem_guest_invitation(invitation.token_hash, attrs, %{})

    assert {:error, :recipient_mismatch} =
             Workspaces.redeem_guest_invitation(
               invitation.token_hash,
               attrs,
               %{},
               nil,
               %{recipient_account | user_id: Ecto.UUID.generate()}
             )

    assert {:error, :recipient_delivery_required} =
             redeem_guest_invitation(invitation_ctx, attrs, recipient_account)
  end

  test "known recipient guest redemption rejects a revoked recipient device" do
    workspace_ctx = guest_workspace()
    invitation_ctx = guest_invitation!(workspace_ctx, max_redemptions: 1)

    invitation =
      invitation_ctx.invitation
      |> Ecto.Changeset.change(%{
        delivery_mode: "known_recipient",
        recipient_user_id: workspace_ctx.owner_id,
        recipient_device_ids: [workspace_ctx.owner_device_id]
      })
      |> Repo.update!()

    RefMD.Devices.Device
    |> Repo.get!(workspace_ctx.owner_device_id)
    |> Ecto.Changeset.change(revoked_at: DateTime.utc_now())
    |> Repo.update!()

    assert {:error, :recipient_device_revoked} =
             Workspaces.redeem_guest_invitation(
               invitation.token_hash,
               guest_redeem_attrs(),
               %{},
               nil,
               %{user_id: workspace_ctx.owner_id, device_id: workspace_ctx.owner_device_id}
             )
  end

  test "consumed known-recipient delivery cannot be replayed" do
    workspace_ctx = guest_workspace()
    token_hash = token_hash()
    invitation_ctx = guest_invitation!(workspace_ctx, max_redemptions: 1, token_hash: token_hash)
    attrs = guest_redeem_attrs()

    assert {:ok, first} = redeem_guest_invitation(invitation_ctx, attrs)

    invitation =
      invitation_ctx.invitation
      |> Ecto.Changeset.change(%{
        delivery_mode: "known_recipient",
        recipient_user_id: workspace_ctx.owner_id,
        recipient_device_ids: [workspace_ctx.owner_device_id]
      })
      |> Repo.update!()

    attempt =
      consumed_guest_delivery_attempt!(workspace_ctx, invitation, attrs, first)

    counts_before = %{
      devices: Repo.aggregate(Device, :count),
      grants: Repo.aggregate(WorkspaceGuestGrant, :count),
      redemptions: Repo.reload!(invitation).redemption_count,
      users: Repo.aggregate(User, :count)
    }

    assert {:error, :delivery_attempt_not_approved} =
             Workspaces.consume_guest_invitation_delivery_attempt(
               attempt.id,
               token_hash,
               workspace_ctx.owner_id,
               workspace_ctx.owner_device_id,
               %{}
             )

    assert {:error, :not_found} =
             Workspaces.consume_guest_invitation_delivery_attempt(
               attempt.id,
               token_hash,
               first.guest_user_id,
               first.guest_device_id,
               %{}
             )

    assert %{
             devices: Repo.aggregate(Device, :count),
             grants: Repo.aggregate(WorkspaceGuestGrant, :count),
             redemptions: Repo.reload!(invitation).redemption_count,
             users: Repo.aggregate(User, :count)
           } == counts_before
  end

  defp insert_scoped_guest_share!(document_id, owner_id) do
    share_id = Ecto.UUID.generate()
    token_hash = Hash.blake3_base64url("scoped-guest-share:" <> share_id)
    digest = Hash.blake3_base64url("scoped-guest-share-digest:" <> share_id)

    Repo.insert!(%Share{
      id: share_id,
      document_id: document_id,
      scope: "document",
      token_hash: token_hash,
      token_prefix: String.slice(token_hash, 0, 4),
      authorization_public_key_material: %{"fixture" => "scoped-guest"},
      share_capability_secret_commitment: digest,
      password_capability_secret_commitment: "none",
      capability_context_hash: digest,
      created_event_hash: digest,
      latest_bootstrap_event_hash: digest,
      authenticated_workspace_pin_bootstrap_hash: digest,
      authenticated_workspace_pin_bootstrap_checkpoint: %{"fixture" => "scoped-guest"},
      permission: "view",
      permission_version: 1,
      password_protected: false,
      max_views: 10,
      view_count: 0,
      expires_event_sequence: 10_000,
      created_by: owner_id
    })

    Repo.insert!(%ShareKey{
      share_id: share_id,
      document_id: document_id,
      key_version: 1,
      encrypted_dek: :crypto.strong_rand_bytes(48),
      nonce: :crypto.strong_rand_bytes(24)
    })

    Repo.get!(Share, share_id)
  end

  defp assert_workspace_crypto_rejected(conn, workspace_id, guest, attrs) do
    device = Repo.get!(Device, guest.guest_device_id)
    key_path = "/api/encryption/workspaces/#{workspace_id}/keys"
    key_query = URI.encode_query(%{"device_id" => guest.guest_device_id})

    key_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        device,
        attrs.device_signing_private_key,
        "GET",
        key_path,
        "",
        key_query
      )
      |> get(key_path <> "?" <> key_query)

    assert json_response(key_response, 403) == %{"error" => "not_a_member"}

    envelope_path = "/api/encryption/workspaces/#{workspace_id}/member-envelope"

    envelope_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        device,
        attrs.device_signing_private_key,
        "GET",
        envelope_path,
        ""
      )
      |> get(envelope_path)

    assert json_response(envelope_response, 403) == %{"error" => "not_a_member"}

    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    latest_path = "/api/workspaces/#{workspace_id}/key-directory/latest"

    latest_query =
      URI.encode_query(%{
        "checkpoint_sequence" => checkpoint.sequence,
        "checkpoint_hash" => checkpoint.checkpoint_hash,
        "event_head_sequence" => checkpoint.covered_event_head_sequence,
        "event_head_hash" => checkpoint.covered_event_head_hash
      })

    latest_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        device,
        attrs.device_signing_private_key,
        "GET",
        latest_path,
        "",
        latest_query
      )
      |> get(latest_path <> "?" <> latest_query)

    assert json_response(latest_response, 403) == %{
             "error" => "key_directory_scope_forbidden"
           }

    append_path = "/api/workspaces/#{workspace_id}/key-directory/append"

    append_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> post(append_path)

    assert append_response.status == 404

    wipe_path = "/api/encryption/workspaces/#{workspace_id}/kek-rotation/wipe-requirement"

    wipe_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        device,
        attrs.device_signing_private_key,
        "GET",
        wipe_path,
        ""
      )
      |> get(wipe_path)

    assert json_response(wipe_response, 403) == %{"error" => "not_a_member"}

    acknowledge_path = wipe_path <> "/acknowledge"

    acknowledge_body = %{
      "device_key_deletion_proof" =>
        signed_device_key_deletion_proof(
          workspace_id,
          guest.guest_user_id,
          guest.guest_device_id,
          attrs.device_signing_private_key,
          1,
          Hash.blake3_base64url("scoped-guest-wipe-rejection")
        )
    }

    acknowledge_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        device,
        attrs.device_signing_private_key,
        "POST",
        acknowledge_path,
        acknowledge_body
      )
      |> post(acknowledge_path, test_json_body(acknowledge_body))

    assert json_response(acknowledge_response, 403) == %{"error" => "not_a_member"}
  end

  defp assert_rotation_management_rejected(conn, workspace_id, guest, attrs) do
    device = Repo.get!(Device, guest.guest_device_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)

    rotation_id = Ecto.UUID.generate()

    directory_body = %{
      "old_key_version" => 1,
      "new_key_version" => 2,
      "reason" => "manual",
      "rotation_id" => rotation_id,
      "events" => [],
      "checkpoint" => %{
        "payload" => checkpoint.payload,
        "signatures" => checkpoint.signatures
      }
    }

    start_path = "/api/encryption/workspaces/#{workspace_id}/kek-rotation/intent"

    start_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        device,
        attrs.device_signing_private_key,
        "POST",
        start_path,
        directory_body
      )
      |> post(start_path, test_json_body(directory_body))

    assert json_response(start_response, 403) == %{"error" => "forbidden"}

    complete_path =
      "/api/encryption/workspaces/#{workspace_id}/rotations/#{rotation_id}/complete/intent"

    complete_body = %{
      "old_key_version" => 1,
      "new_key_version" => 2,
      "device_wrap_precommits" => [],
      "member_envelope_precommits" => [],
      "workspace_invitation_updates" => [],
      "guest_invitation_updates" => []
    }

    complete_response =
      recycle(conn)
      |> authed_conn(guest.guest_user_id, guest.guest_device_id)
      |> put_test_rrp_headers(
        guest.guest_user_id,
        device,
        attrs.device_signing_private_key,
        "POST",
        complete_path,
        complete_body
      )
      |> post(complete_path, test_json_body(complete_body))

    assert json_response(complete_response, 403) == %{"error" => "forbidden"}
  end

  defp insert_workspace_key!(workspace_ctx, guest) do
    workspace_id = workspace_ctx.workspace.id
    device = Repo.get!(Device, guest.guest_device_id)
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint_hash = Base.url_decode64!(pin.checkpoint_hash, padding: false)
    event_head_hash = Base.url_decode64!(pin.event_head_hash, padding: false)

    %WorkspaceEncryptedKey{
      created_at: DateTime.utc_now()
    }
    |> WorkspaceEncryptedKey.changeset(%{
      workspace_id: workspace_id,
      user_id: guest.guest_user_id,
      device_id: guest.guest_device_id,
      key_version: 1,
      sender_device_id: guest.guest_device_id,
      wrap_protocol: "refmd.signed-pq-wrap",
      wrap_version: 1,
      suite_id: "refmd-v2-hybrid",
      suite_rank: 1,
      purpose: "workspace_device_kek_wrap",
      resource: %{"workspace_id" => workspace_id, "key_version" => 1},
      sender: %{"user_id" => guest.guest_user_id, "device_id" => guest.guest_device_id},
      recipient: %{
        "user_id" => guest.guest_user_id,
        "device_id" => guest.guest_device_id
      },
      event_scope: %{"scope_kind" => "workspace", "scope_id" => workspace_id},
      wrap_event_sequence: pin.event_head_sequence,
      wrap_event_hash: event_head_hash,
      wrap_event_body_hash: :crypto.strong_rand_bytes(32),
      operation_checkpoint_sequence: pin.checkpoint_sequence,
      operation_checkpoint_hash: checkpoint_hash,
      operation_checkpoint_covered_head_sequence: pin.event_head_sequence,
      operation_checkpoint_covered_head_hash: event_head_hash,
      wrap_body_hash: :crypto.strong_rand_bytes(32),
      recipient_key_id: device.encryption_key_id,
      sender_signing_key_id: device.signing_key_id,
      hpke_enc: :crypto.strong_rand_bytes(1120),
      hpke_ciphertext: :crypto.strong_rand_bytes(64),
      signature_protocol: "refmd.hybrid-signature",
      signature_version: 1,
      signature_suite_id: "refmd-v2-hybrid",
      signature_suite_rank: 1,
      transcript_hash: :crypto.strong_rand_bytes(32),
      ed25519_signature: :crypto.strong_rand_bytes(64),
      mldsa65_signature: :crypto.strong_rand_bytes(3309),
      is_active: true
    })
    |> Repo.insert!()
  end

  defp guest_workspace(attrs \\ []) do
    owner_id = Ecto.UUID.generate()
    owner_device_id = Ecto.UUID.generate()
    owner_identity_private = hybrid_signing_private_key_material("identity", owner_id)
    owner_device_private = hybrid_signing_private_key_material("device", owner_device_id)
    owner_device_public = hybrid_signing_public_key_material(owner_device_private)
    {owner_identity_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)
    {owner_device_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)

    owner_device_encryption =
      hybrid_encryption_public_key_material("device", owner_device_id, owner_device_x25519_public)

    Repo.insert!(%User{
      id: owner_id,
      email: "owner-guest-invite-#{owner_id}@example.com",
      name: "Owner",
      account_type: "registered"
    })

    checkpoint_hash = Hash.blake3_base64url("guest-owner-device:" <> owner_device_id)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    Repo.insert!(%Device{
      id: owner_device_id,
      user_id: owner_id,
      name: "Owner browser",
      device_type: "browser",
      hybrid_encryption_public_key_material: owner_device_encryption.public,
      encryption_key_id: owner_device_encryption.encryption_key_id,
      hybrid_signing_public_key_material: owner_device_public,
      signing_key_id: Signature.compute_signing_key_id!(owner_device_public),
      approval_signature: %{"fixture" => "guest-owner-device"},
      approval_signature_surface: "device_approval",
      approval_proof: %{
        "target_key_checkpoint_sequence" => 1,
        "target_key_checkpoint_hash" => checkpoint_hash
      },
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: checkpoint_hash,
      client_nonce: :crypto.strong_rand_bytes(16),
      last_seen_at: now,
      created_at: now
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
          min_kek_version: 1,
          kek_rotation_due_at: RotationPolicy.next_kek_due_at()
        ]
      )

    insert_test_workspace_key_directory!(
      workspace.id,
      owner_id,
      owner_role.id,
      owner_identity_private,
      hybrid_encryption_public_key_material("identity", owner_id, owner_identity_x25519_public).public,
      owner_device_private,
      owner_device_encryption.public
    )

    %{
      workspace: workspace,
      owner_id: owner_id,
      owner_device_id: owner_device_id,
      owner_device_private: owner_device_private
    }
  end

  defp authed_conn(conn, user_id, device_id) do
    {:ok, session, token} = Auth.create_session(user_id, %{device_id: device_id})

    conn
    |> put_req_header(
      "cookie",
      "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
    )
    |> put_private(:test_session, session)
  end

  defp insert_guest_device!(user_id) do
    device_id = Ecto.UUID.generate()
    signing = hybrid_device_material(device_id)
    {x25519_public, _x25519_private} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, x25519_public)
    checkpoint_hash = Hash.blake3_base64url("guest-device:" <> device_id)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    device =
      Repo.insert!(%Device{
        id: device_id,
        user_id: user_id,
        name: "Other guest browser",
        device_type: "browser",
        hybrid_encryption_public_key_material: encryption.public,
        encryption_key_id: encryption.encryption_key_id,
        hybrid_signing_public_key_material: signing.public,
        signing_key_id: signing.signing_key_id,
        approval_signature: %{"fixture" => "other-guest-device"},
        approval_signature_surface: "device_approval",
        approval_proof: %{
          "target_key_checkpoint_sequence" => 1,
          "target_key_checkpoint_hash" => checkpoint_hash
        },
        key_checkpoint_sequence: 1,
        key_checkpoint_hash: checkpoint_hash,
        client_nonce: :crypto.strong_rand_bytes(16),
        last_seen_at: now,
        created_at: now
      })

    {device, signing.private}
  end

  defp require_workspace_wipe!(workspace_id, device_id) do
    Repo.insert!(%WorkspaceKekRotationDeletionEvidence{
      old_key_deleted_event_hash: Hash.blake3_base64url("old-key-deleted:" <> workspace_id),
      workspace_id: workspace_id,
      rotation_kind: "kek",
      scope_kind: "workspace",
      scope_id: workspace_id,
      old_key_version: 1,
      deletion_manifest: %{
        "rotation_completed_event_hash" =>
          Hash.blake3_base64url("rotation-completed:" <> workspace_id),
        "deleted_secret_ids_hash" =>
          DeletionProofs.deleted_workspace_kek_secret_ids_hash(
            workspace_id,
            1
          )
      },
      device_key_deletion_proofs: %{},
      wipe_required_device_ids: [device_id]
    })

    %WorkspaceDeviceWipeRequirement{}
    |> WorkspaceDeviceWipeRequirement.changeset(%{
      workspace_id: workspace_id,
      device_id: device_id,
      required_kek_version: 2,
      reason: "kek_rotation_deletion_proof_missing",
      required_at: DateTime.utc_now()
    })
    |> Repo.insert!()
  end

  defp guest_invitation!(workspace_ctx, attrs) do
    workspace = workspace_ctx.workspace
    token_hash = Keyword.get(attrs, :token_hash, token_hash())
    invitation_id = Ecto.UUID.generate()
    bootstrap_key_commitment = bootstrap_key_commitment()

    encrypted_bootstrap_package =
      encrypted_bootstrap_package(workspace.id, invitation_id, token_hash)

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
        delivery_mode: "unknown_fragment",
        recipient_user_id: nil,
        recipient_device_ids: [],
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
        delivery_mode: "unknown_fragment",
        recipient_user_id: nil,
        recipient_device_ids: [],
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

  defp redeem_guest_invitation(invitation_ctx, attrs, recipient_account \\ nil) do
    invitation = invitation_ctx.invitation

    key_directory =
      guest_invitation_redeemed_key_directory_append(
        invitation,
        attrs,
        invitation_ctx.redeem_authority_private_material,
        recipient_account
      )

    key_directory = Map.put(key_directory, :recipient_account, recipient_account)

    Workspaces.redeem_guest_invitation(
      invitation.token_hash,
      attrs,
      %{},
      key_directory,
      recipient_account
    )
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
    encrypted_identity_encryption = :crypto.strong_rand_bytes(48)
    identity_encryption_nonce = :crypto.strong_rand_bytes(24)
    encrypted_identity_signing = :crypto.strong_rand_bytes(48)
    identity_signing_nonce = :crypto.strong_rand_bytes(24)

    identity_encryption_key_id =
      HybridEncryptionMaterial.compute_key_id!(identity_encryption.public)

    identity_signing_key_id = Signature.compute_signing_key_id!(identity_public)

    recoverable_identity_secret_record =
      recoverable_identity_secret_record(
        guest_user_id,
        identity_signing_key_id,
        identity_encryption_key_id,
        encrypted_identity_signing,
        identity_signing_nonce,
        encrypted_identity_encryption,
        identity_encryption_nonce
      )

    key_directory =
      initial_key_directory_bootstrap(
        guest_user_id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate(),
        identity_private,
        identity_encryption.public,
        device_signing.private,
        device_encryption.public
      )

    %{
      guest_user_id: guest_user_id,
      device_id: device_id,
      device_hybrid_encryption_public_key_material: device_encryption.public,
      device_hybrid_signing_public_key_material: device_signing.public,
      identity_hybrid_encryption_public_key_material: identity_encryption.public,
      identity_hybrid_signing_public_key_material: identity_public,
      recoverable_identity_secret_record: recoverable_identity_secret_record,
      identity_encryption_key_id: identity_encryption_key_id,
      identity_signing_key_id: identity_signing_key_id,
      client_nonce: client_nonce,
      user_key_directory_events: key_directory.user_events,
      user_key_directory_checkpoint: key_directory.user_checkpoint,
      device_signing_private_key: device_signing.private,
      device_name: "Guest Browser",
      device_type: "browser"
    }
  end

  defp consumed_guest_delivery_attempt!(workspace_ctx, invitation, attrs, first) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    encode = &Base.url_encode64(&1, padding: false)

    registration = %{
      "identity_hybrid_encryption_public_key_material" =>
        attrs.identity_hybrid_encryption_public_key_material,
      "identity_hybrid_signing_public_key_material" =>
        attrs.identity_hybrid_signing_public_key_material,
      "recoverable_identity_secret_record" => attrs.recoverable_identity_secret_record,
      "device_hybrid_encryption_public_key_material" =>
        attrs.device_hybrid_encryption_public_key_material,
      "device_hybrid_signing_public_key_material" =>
        attrs.device_hybrid_signing_public_key_material,
      "user_key_directory_events" => attrs.user_key_directory_events,
      "user_key_directory_checkpoint" => attrs.user_key_directory_checkpoint
    }

    proof = %{
      "client_nonce" => encode.(attrs.client_nonce),
      "device_name" => attrs.device_name,
      "device_type" => attrs.device_type
    }

    %InvitationDeliveryAttempt{}
    |> InvitationDeliveryAttempt.create_changeset(%{
      id: Ecto.UUID.generate(),
      workspace_id: workspace_ctx.workspace.id,
      context_kind: "guest_invitation",
      context_id: invitation.id,
      recipient_user_id: workspace_ctx.owner_id,
      recipient_device_id: workspace_ctx.owner_device_id,
      target_user_id: first.guest_user_id,
      target_device_id: first.guest_device_id,
      target_encryption_key_id:
        HybridEncryptionMaterial.compute_key_id!(
          attrs.device_hybrid_encryption_public_key_material
        ),
      target_registration: registration,
      target_registration_proof: proof,
      recipient_redeem_nonce: Hash.blake3_base64url("redeem-nonce"),
      live_redeem_challenge_hash: Hash.blake3_base64url("live-challenge"),
      recipient_nonce_state_hash: Hash.blake3_base64url("nonce-state"),
      request_binding_hash: Hash.blake3_base64url("request-binding"),
      resource_hash: Hash.blake3_base64url("resource"),
      context_snapshot: %{"token_hash" => invitation.token_hash},
      status: "pending",
      expires_at: DateTime.add(now, 300, :second)
    })
    |> Repo.insert!()
    |> Ecto.Changeset.change(%{
      approved_artifacts: %{},
      approved_at: now,
      authorization_id: Ecto.UUID.generate(),
      consumed_at: now,
      status: "consumed"
    })
    |> Repo.update!()
  end

  defp token_hash do
    :crypto.strong_rand_bytes(32)
    |> Base.url_encode64(padding: false)
  end

  defp bootstrap_key_commitment do
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  end

  defp context_hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()

  defp encrypted_bootstrap_package(workspace_id, invitation_id, invitation_token_hash) do
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
        "guest_invitation_id" => invitation_id,
        "scope_kind" => "workspace",
        "scope_id" => "none",
        "permission" => "view",
        "delivery_mode" => "unknown_fragment",
        "recipient_user_id" => "NOT_APPLICABLE",
        "recipient_device_ids" => [],
        "key_version_context" => %{
          "workspace_kek_version" => 1,
          "share_key_version" => "NOT_APPLICABLE",
          "dek_version" => "NOT_APPLICABLE"
        },
        "token_hash" => invitation_token_hash
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
