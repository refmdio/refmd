defmodule RefMDWeb.GuestInvitationControllerTest do
  use RefMDWeb.ConnCase, async: true

  import Ecto.Query

  alias RefMD.Auth
  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Users
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.{GuestInvitation, WorkspaceGuestGrant, WorkspaceInvitation}

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email,
      account_type: "registered"
    })

    user_id
  end

  defp create_document(workspace_id, created_by, doc_type \\ "document", parent_id \\ nil) do
    attrs =
      %{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => doc_type,
        "parent_id" => parent_id,
        "title" => if(doc_type == "folder", do: "Folder", else: "Untitled"),
        "created_by" => created_by
      }
      |> maybe_put_encrypted_title(doc_type)

    {:ok, document} = Documents.create_document(attrs)

    document
  end

  defp maybe_put_encrypted_title(attrs, "folder"), do: attrs

  defp maybe_put_encrypted_title(attrs, _doc_type) do
    Map.merge(attrs, %{
      "encrypted_title" => <<1, 2, 3>>,
      "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
      "encrypted_title_key_version" => 1
    })
  end

  defp create_device(user_id) do
    {signing_public_key, signing_private_key} = :crypto.generate_key(:eddsa, :ed25519)
    {ecdh_public_key, _ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    {:ok, device} =
      RefMD.Devices.create_device(%{
        user_id: user_id,
        name: "Owner Browser",
        device_type: "browser",
        ecdh_public_key: ecdh_public_key,
        signing_public_key: signing_public_key,
        identity_signature: :crypto.strong_rand_bytes(64),
        client_nonce: :crypto.strong_rand_bytes(16)
      })

    %{device: device, signing_private_key: signing_private_key}
  end

  defp authed_conn(conn, user_id, device) do
    {:ok, _session, token} = Auth.create_session(user_id, %{device_id: device.id})

    put_req_header(conn, "cookie", "_refmd_session=#{Base.url_encode64(token, padding: false)}")
  end

  defp conn_with_cookie(conn, cookie_value) do
    put_req_header(conn, "cookie", "_refmd_session=#{cookie_value}")
  end

  defp with_pop_headers(conn, user_id, device, signing_private_key) do
    {:ok, challenge} = Auth.create_pop_challenge(user_id, device.id)

    message =
      RefMD.Crypto.build_signature_message("pop_challenge", %{
        "challenge" => Base.url_encode64(challenge, padding: false),
        "device_id" => device.id
      })

    signature = :crypto.sign(:eddsa, :none, message, [signing_private_key, :ed25519])

    conn
    |> put_req_header("x-pop-device-id", device.id)
    |> put_req_header("x-pop-challenge", Base.url_encode64(challenge, padding: false))
    |> put_req_header("x-pop-signature", Base.url_encode64(signature, padding: false))
  end

  defp invitation_params(overrides \\ %{}) do
    token = :crypto.strong_rand_bytes(32)
    token_hash = Base.url_encode64(:crypto.hash(:sha256, token), padding: false)

    Map.merge(
      %{
        "invitation_id" => Ecto.UUID.generate(),
        "token_hash" => token_hash,
        "token_prefix" => String.slice(Base.url_encode64(token, padding: false), 0, 4),
        "target_scope" => "workspace",
        "permission" => "edit",
        "encrypted_kek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "kek_nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "kek_version" => 1,
        "max_redemptions" => 1,
        "expires_at" => DateTime.add(DateTime.utc_now(), 86_400, :second) |> DateTime.to_iso8601()
      },
      overrides
    )
    |> Map.put("_raw_token", Base.url_encode64(token, padding: false))
  end

  defp redeem_body(token, %{} = material) do
    %{
      "token" => token,
      "guest_user_id" => material.guest_user_id,
      "device_signing_pub_key" =>
        Base.url_encode64(material.device_signing_pub_key, padding: false),
      "device_encryption_pub_key" =>
        Base.url_encode64(material.device_encryption_pub_key, padding: false),
      "identity_signing_pub_key" =>
        Base.url_encode64(material.identity_signing_pub_key, padding: false),
      "identity_encryption_pub_key" =>
        Base.url_encode64(material.identity_encryption_pub_key, padding: false),
      "identity_signature" => Base.url_encode64(material.identity_signature, padding: false),
      "client_nonce" => Base.url_encode64(material.client_nonce, padding: false),
      "recovery_encrypted_umk" =>
        Base.url_encode64(material.recovery_encrypted_umk, padding: false),
      "recovery_nonce" => Base.url_encode64(material.recovery_nonce, padding: false),
      "encrypted_identity_encryption_private" =>
        Base.url_encode64(material.encrypted_identity_encryption_private, padding: false),
      "encrypted_identity_encryption_private_nonce" =>
        Base.url_encode64(material.encrypted_identity_encryption_private_nonce, padding: false),
      "encrypted_identity_signing_private" =>
        Base.url_encode64(material.encrypted_identity_signing_private, padding: false),
      "encrypted_identity_signing_private_nonce" =>
        Base.url_encode64(material.encrypted_identity_signing_private_nonce, padding: false),
      "device_name" => material.device_name,
      "device_type" => material.device_type
    }
  end

  defp redeem_body(token, signing_public_key, ecdh_public_key) do
    redeem_body(token, guest_redeem_material(signing_public_key, ecdh_public_key))
  end

  defp guest_redeem_material(signing_public_key, ecdh_public_key) do
    {identity_signing_public_key, identity_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {identity_ecdh_public_key, identity_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    client_nonce = :crypto.strong_rand_bytes(16)

    identity_signature =
      RefMD.Crypto.build_signature_message("device_registration", %{
        "client_nonce" => Base.url_encode64(client_nonce, padding: false),
        "device_ecdh_public_key" => Base.url_encode64(ecdh_public_key, padding: false),
        "device_signing_public_key" => Base.url_encode64(signing_public_key, padding: false)
      })
      |> then(&:crypto.sign(:eddsa, :none, &1, [identity_signing_private_key, :ed25519]))

    %{
      guest_user_id: Ecto.UUID.generate(),
      device_signing_pub_key: signing_public_key,
      device_encryption_pub_key: ecdh_public_key,
      identity_signing_pub_key: identity_signing_public_key,
      identity_encryption_pub_key: identity_ecdh_public_key,
      identity_signature: identity_signature,
      client_nonce: client_nonce,
      recovery_encrypted_umk: :crypto.strong_rand_bytes(48),
      recovery_nonce: :crypto.strong_rand_bytes(24),
      encrypted_identity_encryption_private: identity_ecdh_private_key <> <<0::128>>,
      encrypted_identity_encryption_private_nonce: :crypto.strong_rand_bytes(24),
      encrypted_identity_signing_private: identity_signing_private_key <> <<0::128>>,
      encrypted_identity_signing_private_nonce: :crypto.strong_rand_bytes(24),
      device_name: "Guest Browser",
      device_type: "browser"
    }
  end

  defp guest_invitation_attrs(workspace_id, invited_by, overrides \\ %{}) do
    params = invitation_params()
    {:ok, expires_at, _offset} = DateTime.from_iso8601(params["expires_at"])

    Map.merge(
      %{
        workspace_id: workspace_id,
        invitation_id: params["invitation_id"],
        token_hash: params["token_hash"],
        token_prefix: params["token_prefix"],
        target_scope: params["target_scope"],
        target_document_id: params["target_document_id"],
        permission: params["permission"],
        encrypted_kek: Base.url_decode64!(params["encrypted_kek"], padding: false),
        kek_nonce: Base.url_decode64!(params["kek_nonce"], padding: false),
        kek_version: params["kek_version"],
        max_redemptions: params["max_redemptions"],
        invited_by: invited_by,
        expires_at: expires_at
      },
      overrides
    )
  end

  defp workspace_invitation_attrs(workspace_id, invited_by, invited_email, overrides \\ %{}) do
    params = invitation_params()
    {:ok, expires_at, _offset} = DateTime.from_iso8601(params["expires_at"])

    Map.merge(
      %{
        workspace_id: workspace_id,
        invitation_id: params["invitation_id"],
        token_hash: params["token_hash"],
        token_prefix: params["token_prefix"],
        encrypted_kek: Base.url_decode64!(params["encrypted_kek"], padding: false),
        kek_nonce: Base.url_decode64!(params["kek_nonce"], padding: false),
        kek_version: params["kek_version"],
        role_id: nil,
        invited_by: invited_by,
        invited_email: invited_email,
        expires_at: expires_at,
        raw_token: params["_raw_token"]
      },
      overrides
    )
  end

  setup do
    owner_id = create_user("owner-guest-invite@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Guest Invite Workspace")
    Workspaces.update_current_kek_version(workspace.id, 1)
    {:ok, workspace} = Workspaces.update_workspace(workspace, %{guest_invites_enabled: true})
    owner_device = create_device(owner_id)
    document = create_document(workspace.id, owner_id)

    %{
      owner_id: owner_id,
      workspace: workspace,
      owner_device: owner_device,
      document: document
    }
  end

  test "lookup reports guest invitation kind", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace
  } do
    params = invitation_params()

    {:ok, _invitation} =
      Workspaces.create_guest_invitation(
        guest_invitation_attrs(workspace.id, owner_id, %{
          invitation_id: params["invitation_id"],
          token_hash: params["token_hash"],
          token_prefix: params["token_prefix"]
        })
      )

    conn = post(conn, "/api/workspaces/invitations/lookup", %{"token" => params["_raw_token"]})

    assert json_response(conn, 200) == %{"kind" => "guest"}
  end

  test "lookup reports member invitation kind", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace
  } do
    attrs = workspace_invitation_attrs(workspace.id, owner_id, "invitee@example.com")

    %WorkspaceInvitation{}
    |> WorkspaceInvitation.changeset(
      attrs
      |> Map.delete(:raw_token)
      |> Map.put(:id, attrs.invitation_id)
      |> Map.put(:created_at, DateTime.utc_now())
    )
    |> Repo.insert!()

    conn = post(conn, "/api/workspaces/invitations/lookup", %{"token" => attrs.raw_token})

    assert json_response(conn, 200) == %{"kind" => "member"}
  end

  test "owner can create, list, and revoke guest invitations", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert %{
             "invitation_id" => invitation_id,
             "workspace_id" => workspace_id,
             "invited_by" => invited_by,
             "permission" => "edit",
             "target_scope" => "workspace",
             "revoked_at" => nil
           } = json_response(conn, 201)

    assert workspace_id == workspace.id
    assert invited_by == owner_id

    conn =
      build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> get("/api/workspaces/#{workspace.id}/guest-invitations")

    assert %{"invitations" => [listed]} = json_response(conn, 200)
    assert listed["invitation_id"] == invitation_id
    assert listed["invited_by"] == owner_id

    conn =
      build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> delete("/api/workspaces/#{workspace.id}/guest-invitations/#{invitation_id}")

    assert response(conn, 204)
    assert Repo.get!(GuestInvitation, invitation_id).revoked_at

    conn =
      build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> get("/api/workspaces/#{workspace.id}/guest-invitations")

    assert %{"invitations" => []} = json_response(conn, 200)
  end

  test "redeem reports invalid guest user id separately", %{conn: conn} do
    {signing_public_key, _signing_private_key} = :crypto.generate_key(:eddsa, :ed25519)
    {ecdh_public_key, _ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    token = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    conn =
      conn
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        token
        |> redeem_body(guest_redeem_material(signing_public_key, ecdh_public_key))
        |> Map.put("guest_user_id", "not-a-uuid")
      )

    assert json_response(conn, 400) == %{"error" => "invalid_guest_user_id_format"}
  end

  test "redeem reports guest user id conflicts", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)
    existing_user_id = create_user("existing-guest-user-id-conflict@example.com")
    {signing_public_key, _signing_private_key} = :crypto.generate_key(:eddsa, :ed25519)
    {ecdh_public_key, _ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    material = %{
      guest_redeem_material(signing_public_key, ecdh_public_key)
      | guest_user_id: existing_user_id
    }

    redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], material)
      )

    assert json_response(redeem_conn, 409) == %{"error" => "guest_user_id_conflict"}
  end

  test "redeem creates a guest user, device, membership, and re-entry reuses the same device",
       %{
         conn: conn,
         owner_id: owner_id,
         workspace: workspace,
         owner_device: owner_device
       } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    invitation_id = json_response(create_conn, 201)["invitation_id"]

    {guest_signing_public_key, _guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    redeem_payload = guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)

    redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert %{
             "workspace_id" => workspace_id,
             "guest_user_id" => guest_user_id,
             "guest_device_id" => guest_device_id,
             "invitation_id" => ^invitation_id
           } = json_response(redeem_conn, 200)

    assert workspace_id == workspace.id
    assert redeem_conn.resp_cookies["_refmd_session"].path == "/api"
    assert Users.get_user(guest_user_id).account_type == "guest"
    assert Workspaces.get_workspace_member(workspace.id, guest_user_id)

    grant =
      from(g in WorkspaceGuestGrant,
        where: g.workspace_id == ^workspace.id and g.user_id == ^guest_user_id
      )
      |> Repo.one()

    assert grant.permission == "edit"

    reentry_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert %{
             "guest_user_id" => ^guest_user_id,
             "guest_device_id" => ^guest_device_id
           } = json_response(reentry_conn, 200)

    invitation = Repo.get!(GuestInvitation, invitation_id)
    assert invitation.redemption_count == 1
  end

  test "create rejects archived guest invitation targets", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    target = create_document(workspace.id, owner_id)
    assert {:ok, archived_target} = Documents.archive_document(target)

    params =
      invitation_params(%{
        "target_scope" => "document",
        "target_document_id" => archived_target.id,
        "permission" => "view"
      })

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 422) == %{"error" => "invalid_target_document"}
  end

  test "guest re-entry accepts an active guest session cookie", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, _guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    redeem_payload = guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)

    first_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert %{"guest_user_id" => guest_user_id} = json_response(first_redeem_conn, 200)
    guest_cookie = first_redeem_conn.resp_cookies["_refmd_session"].value

    reentry_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert json_response(reentry_conn, 200)["guest_user_id"] == guest_user_id
  end

  test "redeem rejects an active registered user session", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, _guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    redeem_conn =
      build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], guest_signing_public_key, guest_ecdh_public_key)
      )

    assert json_response(redeem_conn, 409) == %{"error" => "active_user_session"}
    refute redeem_conn.resp_cookies["_refmd_session"]
  end

  test "same guest device can redeem a broader second invitation in the same workspace", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device,
    document: document
  } do
    first_params =
      invitation_params(%{
        "target_scope" => "document",
        "target_document_id" => document.id,
        "permission" => "view"
      })

    second_params = invitation_params(%{"target_scope" => "workspace", "permission" => "edit"})

    for params <- [first_params, second_params] do
      create_conn =
        conn
        |> authed_conn(owner_id, owner_device.device)
        |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
        |> post(
          "/api/workspaces/#{workspace.id}/guest-invitations",
          Map.delete(params, "_raw_token")
        )

      assert json_response(create_conn, 201)
    end

    {guest_signing_public_key, guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    redeem_payload = guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)

    first_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(first_params["_raw_token"], redeem_payload)
      )

    %{
      "guest_user_id" => guest_user_id,
      "guest_device_id" => guest_device_id
    } = json_response(first_redeem_conn, 200)

    second_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(second_params["_raw_token"], redeem_payload)
      )

    assert %{
             "guest_user_id" => ^guest_user_id,
             "guest_device_id" => ^guest_device_id
           } = json_response(second_redeem_conn, 200)

    guest_cookie = second_redeem_conn.resp_cookies["_refmd_session"].value
    guest_device = RefMD.Devices.get_device(guest_device_id)

    create_document_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> post("/api/documents", %{
        "workspace_id" => workspace.id,
        "id" => Ecto.UUID.generate(),
        "doc_type" => "document",
        "title" => "Broader Grant Draft",
        "encrypted_title" => Base.url_encode64(<<4, 5, 6>>, padding: false),
        "encrypted_title_nonce" =>
          Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "encrypted_title_key_version" => 1
      })

    workspace_id = workspace.id

    assert %{"workspace_id" => ^workspace_id, "doc_type" => "document"} =
             json_response(create_document_conn, 201)
  end

  test "guest_member_limit blocks onboarding for a new guest device", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    {:ok, _workspace} =
      Workspaces.update_workspace(workspace, %{guest_member_limit: 1, guest_invites_enabled: true})

    params = invitation_params(%{"max_redemptions" => 2})

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, _guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    redeem_payload = guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)

    first_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert json_response(first_redeem_conn, 200)

    {second_signing_public_key, _second_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {second_ecdh_public_key, _second_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    second_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], second_signing_public_key, second_ecdh_public_key)
      )

    assert json_response(second_redeem_conn, 409) == %{"error" => "guest_member_limit_reached"}
  end

  test "guest invitation list remains available and read-only when guest invites are disabled", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    invitation_id = json_response(create_conn, 201)["invitation_id"]

    {:ok, _workspace} =
      Workspaces.update_workspace(workspace, %{guest_invites_enabled: false})

    index_conn =
      build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> get("/api/workspaces/#{workspace.id}/guest-invitations")

    assert %{"invitations" => [listed]} = json_response(index_conn, 200)
    assert listed["invitation_id"] == invitation_id
    assert listed["revoked_at"] == nil

    delete_conn =
      build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> delete("/api/workspaces/#{workspace.id}/guest-invitations/#{invitation_id}")

    assert json_response(delete_conn, 409) == %{"error" => "guest_invites_disabled"}
  end

  test "security rotation invitation cleanup revokes both member and guest invitations", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    invitation_id = json_response(create_conn, 201)["invitation_id"]

    viewer_role =
      workspace.id
      |> Workspaces.list_workspace_roles()
      |> Enum.find(&(&1.base_role == "viewer"))

    member_token = :crypto.strong_rand_bytes(32)

    member_invitation_attrs = %{
      workspace_id: workspace.id,
      invitation_id: Ecto.UUID.generate(),
      token_hash: Base.url_encode64(:crypto.hash(:sha256, member_token), padding: false),
      token_prefix: String.slice(Base.url_encode64(member_token, padding: false), 0, 4),
      role_id: viewer_role.id,
      invited_by: owner_id,
      invited_email: "registered-invitee@example.com",
      encrypted_kek: :crypto.strong_rand_bytes(48),
      kek_nonce: :crypto.strong_rand_bytes(24),
      kek_version: 1,
      expires_at: DateTime.add(DateTime.utc_now(), 86_400, :second)
    }

    member_invitation_id =
      %WorkspaceInvitation{created_at: DateTime.utc_now()}
      |> WorkspaceInvitation.changeset(%{
        id: member_invitation_attrs.invitation_id,
        workspace_id: member_invitation_attrs.workspace_id,
        token_hash: member_invitation_attrs.token_hash,
        token_prefix: member_invitation_attrs.token_prefix,
        role_id: member_invitation_attrs.role_id,
        invited_by: member_invitation_attrs.invited_by,
        invited_email: member_invitation_attrs.invited_email,
        encrypted_kek: member_invitation_attrs.encrypted_kek,
        kek_nonce: member_invitation_attrs.kek_nonce,
        kek_version: member_invitation_attrs.kek_version,
        expires_at: member_invitation_attrs.expires_at
      })
      |> Repo.insert!()
      |> Map.fetch!(:id)

    assert %{member_invitations: 1, guest_invitations: 1} =
             Workspaces.revoke_all_active_access_invitations([workspace.id])

    from(w in Workspaces.Workspace, where: w.id == ^workspace.id)
    |> Repo.update_all(set: [needs_kek_rotation: true])

    assert Repo.get!(GuestInvitation, invitation_id).revoked_at != nil
    assert Repo.get!(WorkspaceInvitation, member_invitation_id).revoked_at != nil

    {guest_signing_public_key, _guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], guest_signing_public_key, guest_ecdh_public_key)
      )

    assert json_response(redeem_conn, 410) == %{"error" => "invitation_revoked"}
  end

  test "same-device guest re-entry is rejected after guest invites are disabled", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, _guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    redeem_payload = guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)

    first_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert %{
             "guest_user_id" => _guest_user_id,
             "guest_device_id" => _guest_device_id
           } = json_response(first_redeem_conn, 200)

    {:ok, _workspace} =
      Workspaces.update_workspace(workspace, %{guest_invites_enabled: false})

    second_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert json_response(second_redeem_conn, 409) == %{"error" => "guest_invites_disabled"}
  end

  test "same-device guest re-entry remains blocked during rotation after invitation cleanup", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, _guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    redeem_payload = guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)

    first_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert json_response(first_redeem_conn, 200)

    assert %{guest_invitations: 1} =
             Workspaces.revoke_all_active_access_invitations([workspace.id])

    from(w in Workspaces.Workspace, where: w.id == ^workspace.id)
    |> Repo.update_all(set: [needs_kek_rotation: true])

    second_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert json_response(second_redeem_conn, 409) == %{"error" => "kek_rotation_in_progress"}
  end

  test "same-device guest re-entry is rejected while KEK rotation is in progress", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, _guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    redeem_payload = guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)

    first_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert json_response(first_redeem_conn, 200)

    from(w in Workspaces.Workspace, where: w.id == ^workspace.id)
    |> Repo.update_all(set: [needs_kek_rotation: true])

    second_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert json_response(second_redeem_conn, 409) == %{"error" => "kek_rotation_in_progress"}
  end

  test "same-device guest re-entry is rejected when invitation KEK is outdated", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, _guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    redeem_payload = guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)

    first_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert json_response(first_redeem_conn, 200)

    from(w in Workspaces.Workspace, where: w.id == ^workspace.id)
    |> Repo.update_all(set: [current_kek_version: 2, min_kek_version: 2])

    second_redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert json_response(second_redeem_conn, 410) == %{"error" => "invitation_kek_outdated"}
  end

  test "re-entry does not reuse a guest device when only the public keys are replayed", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    invitation_id = json_response(create_conn, 201)["invitation_id"]

    {guest_signing_public_key, _guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    redeem_payload = guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)

    redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert json_response(redeem_conn, 200)["invitation_id"] == invitation_id

    revoke_conn =
      build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> delete("/api/workspaces/#{workspace.id}/guest-invitations/#{invitation_id}")

    assert response(revoke_conn, 204)

    reentry_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    assert json_response(reentry_conn, 200)["guest_user_id"] ==
             json_response(redeem_conn, 200)["guest_user_id"]

    replay_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(
          params["_raw_token"],
          guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)
        )
      )

    assert json_response(replay_conn, 410) == %{"error" => "invitation_revoked"}
  end

  test "guest principals cannot be moved out of the guest role via member role changes", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, _guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    redeem_payload = guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)

    redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    guest_user_id = json_response(redeem_conn, 200)["guest_user_id"]

    viewer_role =
      Repo.one!(
        from(r in RefMD.Workspaces.WorkspaceRole,
          where: r.workspace_id == ^workspace.id and r.base_role == "viewer"
        )
      )

    change_conn =
      build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> patch("/api/workspaces/#{workspace.id}/members/#{guest_user_id}", %{
        "role_id" => viewer_role.id
      })

    assert json_response(change_conn, 422) == %{"error" => "guest_role_immutable"}
    assert Workspaces.get_member_role(workspace.id, guest_user_id) == "guest"
  end

  test "revoked guest devices lose API access", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    redeem_payload = guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)

    redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    %{
      "guest_user_id" => guest_user_id,
      "guest_device_id" => guest_device_id
    } = json_response(redeem_conn, 200)

    guest_cookie = redeem_conn.resp_cookies["_refmd_session"].value
    guest_device = RefMD.Devices.get_device(guest_device_id)

    from(d in RefMD.Devices.Device, where: d.id == ^guest_device_id)
    |> Repo.update_all(set: [revoked_at: DateTime.utc_now()])

    workspace_ids_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> get("/api/workspaces/ids")

    assert json_response(workspace_ids_conn, 403) == %{"error" => "pop_invalid_device"}
  end

  test "workspace invitations reject the guest builtin role", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    guest_role =
      Repo.one!(
        from(r in RefMD.Workspaces.WorkspaceRole,
          where: r.workspace_id == ^workspace.id and r.base_role == "guest"
        )
      )

    token = :crypto.strong_rand_bytes(32)

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post("/api/workspaces/#{workspace.id}/invitations", %{
        "invitation_id" => Ecto.UUID.generate(),
        "token_hash" => Base.url_encode64(:crypto.hash(:sha256, token), padding: false),
        "token_prefix" => String.slice(Base.url_encode64(token, padding: false), 0, 4),
        "encrypted_kek" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
        "kek_nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "kek_version" => 1,
        "role_id" => guest_role.id,
        "invited_email" => "registered-invitee@example.com",
        "expires_at" => DateTime.add(DateTime.utc_now(), 86_400, :second) |> DateTime.to_iso8601()
      })

    assert json_response(create_conn, 422) == %{"error" => "invalid_role"}
  end

  test "guest builtin role cannot become the default workspace role", %{
    workspace: workspace
  } do
    guest_role =
      Repo.one!(
        from(r in RefMD.Workspaces.WorkspaceRole,
          where: r.workspace_id == ^workspace.id and r.base_role == "guest"
        )
      )

    assert {:error, :guest_role_default_not_allowed} =
             Workspaces.update_role(guest_role, %{is_default: true})
  end

  test "removing a guest member revokes discoverability and the active guest grant", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    redeem_payload = guest_redeem_material(guest_signing_public_key, guest_ecdh_public_key)

    redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], redeem_payload)
      )

    %{
      "guest_user_id" => guest_user_id,
      "guest_device_id" => guest_device_id
    } = json_response(redeem_conn, 200)

    guest_cookie = redeem_conn.resp_cookies["_refmd_session"].value
    guest_device = RefMD.Devices.get_device(guest_device_id)

    delete_conn =
      build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> delete("/api/workspaces/#{workspace.id}/members/#{guest_user_id}")

    assert %{"ok" => true, "workspaces_needing_kek_rotation" => [_ | _]} =
             json_response(delete_conn, 200)

    assert Workspaces.get_workspace_member(workspace.id, guest_user_id) == nil

    grant =
      from(g in WorkspaceGuestGrant,
        where: g.workspace_id == ^workspace.id and g.user_id == ^guest_user_id
      )
      |> Repo.one()

    assert grant.revoked_at != nil

    workspace_ids_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> get("/api/workspaces/ids")

    assert json_response(workspace_ids_conn, 200) == %{"workspace_ids" => []}
  end

  test "create_guest_invitation rechecks actor role inside the transaction", %{
    owner_id: owner_id,
    workspace: workspace
  } do
    membership = Workspaces.get_workspace_member(workspace.id, owner_id)
    Repo.delete!(membership)

    assert {:error, :permission_denied} =
             Workspaces.create_guest_invitation(guest_invitation_attrs(workspace.id, owner_id))
  end

  test "revoke_guest_invitation rechecks actor role inside the transaction", %{
    owner_id: owner_id,
    workspace: workspace
  } do
    {:ok, invitation} =
      Workspaces.create_guest_invitation(guest_invitation_attrs(workspace.id, owner_id))

    membership = Workspaces.get_workspace_member(workspace.id, owner_id)
    Repo.delete!(membership)

    assert {:error, :permission_denied} =
             Workspaces.revoke_guest_invitation(workspace.id, invitation.id, owner_id)
  end

  test "create_guest_invitation rejects guest permission escalation beyond the actor role", %{
    owner_id: owner_id,
    workspace: workspace
  } do
    {:ok, limited_admin_role} =
      Workspaces.create_custom_role(workspace.id, "Limited Admin", "admin", [
        %{"permission" => "document:write", "granted" => false},
        %{"permission" => "document:archive", "granted" => false}
      ])

    from(m in RefMD.Workspaces.WorkspaceMember,
      where: m.workspace_id == ^workspace.id and m.user_id == ^owner_id
    )
    |> Repo.update_all(set: [role_id: limited_admin_role.id])

    assert {:error, :permission_escalation} =
             Workspaces.create_guest_invitation(
               guest_invitation_attrs(workspace.id, owner_id, %{permission: "edit"})
             )
  end

  test "workspace-scoped edit guest can discover the workspace and create documents", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    params = invitation_params()

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], guest_signing_public_key, guest_ecdh_public_key)
      )

    %{
      "guest_user_id" => guest_user_id,
      "guest_device_id" => guest_device_id
    } = json_response(redeem_conn, 200)

    guest_cookie = redeem_conn.resp_cookies["_refmd_session"].value
    guest_device = RefMD.Devices.get_device(guest_device_id)

    workspaces_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> get("/api/workspaces")

    assert %{"workspaces" => [listed_workspace]} = json_response(workspaces_conn, 200)
    assert listed_workspace["id"] == workspace.id

    workspace_ids_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> get("/api/workspaces/ids")

    assert json_response(workspace_ids_conn, 200) == %{"workspace_ids" => [workspace.id]}

    create_document_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> post("/api/documents", %{
        "workspace_id" => workspace.id,
        "id" => Ecto.UUID.generate(),
        "doc_type" => "document",
        "title" => "Guest Draft",
        "encrypted_title" => Base.url_encode64(<<4, 5, 6>>, padding: false),
        "encrypted_title_nonce" =>
          Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "encrypted_title_key_version" => 1
      })

    workspace_id = workspace.id

    assert %{"workspace_id" => ^workspace_id, "doc_type" => "document"} =
             json_response(create_document_conn, 201)
  end

  test "document-scoped guest is discoverable but limited to scoped and crypto-safe surfaces", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device,
    document: document
  } do
    params =
      invitation_params(%{
        "target_scope" => "document",
        "target_document_id" => document.id,
        "permission" => "view"
      })

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], guest_signing_public_key, guest_ecdh_public_key)
      )

    %{
      "guest_user_id" => guest_user_id,
      "guest_device_id" => guest_device_id
    } = json_response(redeem_conn, 200)

    guest_cookie = redeem_conn.resp_cookies["_refmd_session"].value
    guest_device = RefMD.Devices.get_device(guest_device_id)

    workspaces_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> get("/api/workspaces")

    assert %{"workspaces" => [listed_workspace]} = json_response(workspaces_conn, 200)
    assert listed_workspace["id"] == workspace.id
    assert listed_workspace["current_user_base_role"] == "guest"

    workspace_ids_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> get("/api/workspaces/ids")

    assert json_response(workspace_ids_conn, 200) == %{"workspace_ids" => [workspace.id]}

    workspace_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> get("/api/workspaces/#{workspace.id}")

    assert %{
             "id" => workspace_id,
             "current_user_base_role" => "guest"
           } = json_response(workspace_conn, 200)

    assert workspace_id == workspace.id

    roles_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> get("/api/workspaces/#{workspace.id}/roles")

    assert %{"roles" => roles} = json_response(roles_conn, 200)
    assert Enum.any?(roles, &(&1["base_role"] == "guest"))

    members_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> get("/api/workspaces/#{workspace.id}/members")

    assert json_response(members_conn, 403) == %{"error" => "permission_denied"}

    member_keys_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> get("/api/workspaces/#{workspace.id}/member-keys")

    assert %{"members" => [_ | _]} = json_response(member_keys_conn, 200)

    devices_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> get("/api/workspaces/#{workspace.id}/members/#{owner_id}/devices")

    assert %{"devices" => [_ | _]} = json_response(devices_conn, 200)
  end

  test "folder-scoped guest can discover the workspace but cannot create outside the granted subtree",
       %{
         conn: conn,
         owner_id: owner_id,
         workspace: workspace,
         owner_device: owner_device
       } do
    folder = create_document(workspace.id, owner_id, "folder")

    params =
      invitation_params(%{
        "target_scope" => "folder",
        "target_document_id" => folder.id,
        "permission" => "edit"
      })

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], guest_signing_public_key, guest_ecdh_public_key)
      )

    %{
      "guest_user_id" => guest_user_id,
      "guest_device_id" => guest_device_id
    } = json_response(redeem_conn, 200)

    guest_cookie = redeem_conn.resp_cookies["_refmd_session"].value
    guest_device = RefMD.Devices.get_device(guest_device_id)

    workspaces_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> get("/api/workspaces")

    assert %{"workspaces" => [listed_workspace]} = json_response(workspaces_conn, 200)
    assert listed_workspace["id"] == workspace.id

    create_document_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> post("/api/documents", %{
        "workspace_id" => workspace.id,
        "id" => Ecto.UUID.generate(),
        "doc_type" => "document",
        "title" => "Outside Folder",
        "encrypted_title" => Base.url_encode64(<<1, 2, 3>>, padding: false),
        "encrypted_title_nonce" =>
          Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
        "encrypted_title_key_version" => 1
      })

    assert json_response(create_document_conn, 403) == %{"error" => "permission_denied"}
  end

  test "folder-scoped guest cannot reorder a child document outside the granted subtree", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    folder = create_document(workspace.id, owner_id, "folder")
    child = create_document(workspace.id, owner_id, "document", folder.id)

    params =
      invitation_params(%{
        "target_scope" => "folder",
        "target_document_id" => folder.id,
        "permission" => "edit"
      })

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], guest_signing_public_key, guest_ecdh_public_key)
      )

    %{
      "guest_user_id" => guest_user_id,
      "guest_device_id" => guest_device_id
    } = json_response(redeem_conn, 200)

    guest_cookie = redeem_conn.resp_cookies["_refmd_session"].value
    guest_device = RefMD.Devices.get_device(guest_device_id)

    reorder_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> patch("/api/documents/reorder", %{
        "workspace_id" => workspace.id,
        "document_id" => child.id,
        "parent_id" => nil,
        "position" => 0
      })

    assert json_response(reorder_conn, 403) == %{"error" => "permission_denied"}
  end

  test "folder-scoped guest cannot move a document outside the granted subtree via PATCH", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    folder = create_document(workspace.id, owner_id, "folder")
    child = create_document(workspace.id, owner_id, "document", folder.id)

    params =
      invitation_params(%{
        "target_scope" => "folder",
        "target_document_id" => folder.id,
        "permission" => "edit"
      })

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_pop_headers(owner_id, owner_device.device, owner_device.signing_private_key)
      |> post(
        "/api/workspaces/#{workspace.id}/guest-invitations",
        Map.delete(params, "_raw_token")
      )

    assert json_response(create_conn, 201)

    {guest_signing_public_key, guest_signing_private_key} =
      :crypto.generate_key(:eddsa, :ed25519)

    {guest_ecdh_public_key, _guest_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    redeem_conn =
      build_conn()
      |> post(
        "/api/workspaces/guest-invitations/redeem",
        redeem_body(params["_raw_token"], guest_signing_public_key, guest_ecdh_public_key)
      )

    %{
      "guest_user_id" => guest_user_id,
      "guest_device_id" => guest_device_id
    } = json_response(redeem_conn, 200)

    guest_cookie = redeem_conn.resp_cookies["_refmd_session"].value
    guest_device = RefMD.Devices.get_device(guest_device_id)

    update_conn =
      build_conn()
      |> conn_with_cookie(guest_cookie)
      |> with_pop_headers(guest_user_id, guest_device, guest_signing_private_key)
      |> patch("/api/documents/#{child.id}", %{
        "parent_id" => nil
      })

    assert json_response(update_conn, 403) == %{"error" => "permission_denied"}
  end
end
