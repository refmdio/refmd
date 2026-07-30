defmodule RefMDWeb.SecurityNotificationControllerTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Auth
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.Notification
  alias RefMD.TestCrypto
  alias RefMD.Users.User

  test "lists durable notifications for the current user", %{conn: conn} do
    user_id = create_user("security-notifications-controller@example.com")
    %{device: device, signing_private_key: signing_private_key} = create_device(user_id)

    notification =
      insert_notification!(%{
        recipient_kind: "user",
        recipient_id: user_id,
        type: "plugin.consent_required",
        severity: "action_required",
        action_ref: %{"application_id" => "application-one"},
        dedupe_key: "plugin.consent_required:application-one:bundle-one:#{user_id}"
      })

    other_user_id = create_user("security-notifications-other@example.com")

    insert_notification!(%{
      recipient_kind: "user",
      recipient_id: other_user_id,
      type: "device.pending_approval",
      severity: "action_required",
      action_ref: %{},
      dedupe_key: "device.pending_approval:other"
    })

    path = "/api/security/notifications"

    response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_rrp_headers(user_id, device, signing_private_key, "GET", path, "", "")
      |> get(path)
      |> json_response(200)

    assert [%{"id" => id, "type" => "plugin.consent_required", "severity" => "action_required"}] =
             response["notifications"]

    assert id == notification.id
  end

  test "lists durable notifications for the current device", %{conn: conn} do
    user_id = create_user("security-notifications-device@example.com")
    %{device: device, signing_private_key: signing_private_key} = create_device(user_id)

    notification =
      insert_notification!(%{
        recipient_kind: "device",
        recipient_id: device.id,
        user_id: user_id,
        type: "plugin.runtime_revoked",
        severity: "warning",
        action_ref: %{"application_id" => "application-one"},
        dedupe_key: "plugin.runtime_revoked:application-one:#{device.id}"
      })

    other_device_id = Ecto.UUID.generate()

    insert_notification!(%{
      recipient_kind: "device",
      recipient_id: other_device_id,
      user_id: user_id,
      type: "plugin.runtime_disabled",
      severity: "warning",
      action_ref: %{},
      dedupe_key: "plugin.runtime_disabled:other"
    })

    path = "/api/security/notifications"
    query = URI.encode_query(%{"recipient_kind" => "device", "recipient_id" => device.id})

    response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_rrp_headers(user_id, device, signing_private_key, "GET", path, "", query)
      |> get(path <> "?" <> query)
      |> json_response(200)

    assert [%{"id" => id, "type" => "plugin.runtime_revoked", "severity" => "warning"}] =
             response["notifications"]

    assert id == notification.id
  end

  test "rejects durable notification listing for another device", %{conn: conn} do
    user_id = create_user("security-notifications-device-denied@example.com")
    %{device: device, signing_private_key: signing_private_key} = create_device(user_id)
    other_device_id = Ecto.UUID.generate()
    path = "/api/security/notifications"
    query = URI.encode_query(%{"recipient_kind" => "device", "recipient_id" => other_device_id})

    response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_rrp_headers(user_id, device, signing_private_key, "GET", path, "", query)
      |> get(path <> "?" <> query)
      |> json_response(403)

    assert response == %{"error" => "notification_recipient_forbidden"}
  end

  test "marks a user notification as read", %{conn: conn} do
    user_id = create_user("security-notifications-read@example.com")
    %{device: device, signing_private_key: signing_private_key} = create_device(user_id)

    notification =
      insert_notification!(%{
        recipient_kind: "user",
        recipient_id: user_id,
        type: "plugin.consent_required",
        severity: "action_required",
        action_ref: %{"application_id" => "application-one"},
        dedupe_key: "plugin.consent_required:application-one:bundle-one:#{user_id}"
      })

    path = "/api/security/notifications/#{notification.id}/read"

    response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_rrp_headers(user_id, device, signing_private_key, "PATCH", path, "")
      |> patch(path)
      |> json_response(200)

    assert %{"notification" => %{"id" => id, "read_at" => read_at}} = response
    assert id == notification.id
    assert is_binary(read_at)
    assert Repo.get!(Notification, notification.id).read_at
  end

  test "dismisses a user notification", %{conn: conn} do
    user_id = create_user("security-notifications-dismiss@example.com")
    %{device: device, signing_private_key: signing_private_key} = create_device(user_id)

    notification =
      insert_notification!(%{
        recipient_kind: "user",
        recipient_id: user_id,
        type: "workspace.kek_rotation_needed",
        severity: "action_required",
        action_ref: %{"workspace_id" => Ecto.UUID.generate()},
        dedupe_key: "workspace.kek_rotation_needed:workspace-one"
      })

    path = "/api/security/notifications/#{notification.id}/dismiss"

    response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_rrp_headers(user_id, device, signing_private_key, "PATCH", path, "")
      |> patch(path)
      |> json_response(200)

    assert %{"notification" => %{"id" => id, "dismissed_at" => dismissed_at}} = response
    assert id == notification.id
    assert is_binary(dismissed_at)
    assert Repo.get!(Notification, notification.id).dismissed_at
  end

  test "does not update another user's notification state", %{conn: conn} do
    user_id = create_user("security-notifications-forbidden@example.com")
    other_user_id = create_user("security-notifications-forbidden-other@example.com")
    %{device: device, signing_private_key: signing_private_key} = create_device(user_id)

    notification =
      Repo.insert!(%Notification{
        recipient_kind: "user",
        recipient_id: other_user_id,
        type: "plugin.consent_required",
        severity: "action_required",
        action_ref: %{},
        dedupe_key: "plugin.consent_required:other"
      })

    path = "/api/security/notifications/#{notification.id}/dismiss"

    response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_rrp_headers(user_id, device, signing_private_key, "PATCH", path, "")
      |> patch(path)
      |> json_response(404)

    assert response == %{"error" => "security_notification_not_found"}
    refute Repo.get!(Notification, notification.id).dismissed_at
  end

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email
    })

    TestCrypto.install_signed_audit_genesis!("user", user_id, user_id)
    user_id
  end

  defp insert_notification!(attrs) do
    recipient_id = attrs.recipient_id

    {actor, resource_kind} =
      case attrs.recipient_kind do
        "user" ->
          {%{
             "user_id" => recipient_id,
             "device_id" => nil,
             "session_id" => nil,
             "principal_kind" => "user",
             "principal_id" => recipient_id
           }, "credential"}

        "device" ->
          {%{
             "user_id" => attrs.user_id,
             "device_id" => recipient_id,
             "session_id" => nil,
             "principal_kind" => "user",
             "principal_id" => attrs.user_id
           }, "device"}
      end

    event = %{
      class: "security_runtime",
      type: attrs.type,
      actor: actor,
      scope: %{"workspace_id" => nil, "document_id" => nil, "share_id" => nil},
      resource: %{"kind" => resource_kind, "id" => recipient_id, "version_hash" => nil},
      action: %{"operation" => attrs.type, "result" => "completed", "reason_code" => nil},
      sensitivity: Security.empty_sensitivity(),
      correlation: %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => nil
      }
    }

    {:ok, %{notifications: [notification]}} = Security.record_audit_event(event, [attrs])
    notification
  end

  defp create_device(user_id) do
    device_id = Ecto.UUID.generate()
    keys = hybrid_device_material(device_id)
    {ecdh_public_key, _ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, ecdh_public_key)
    client_nonce = :crypto.strong_rand_bytes(16)

    {:ok, device} =
      RefMD.Devices.create_device(%{
        id: device_id,
        user_id: user_id,
        name: "Browser",
        device_type: "browser",
        hybrid_encryption_public_key_material: encryption.public,
        encryption_key_id: encryption.encryption_key_id,
        hybrid_signing_public_key_material: keys.public,
        signing_key_id: keys.signing_key_id,
        approval_signature:
          genesis_device_bootstrap_signature(
            user_id,
            device_id,
            keys.public,
            ecdh_public_key,
            encryption.public,
            client_nonce
          ),
        approval_signature_surface: "genesis_device_bootstrap",
        approval_proof:
          genesis_device_approval_proof(
            user_id,
            device_id,
            keys.public,
            ecdh_public_key,
            encryption.public,
            client_nonce
          ),
        client_nonce: client_nonce
      })

    %{device: device, signing_private_key: keys.private}
  end

  defp authed_conn(conn, user_id, device) do
    {:ok, session, token} = Auth.create_session(user_id, %{device_id: device.id})

    conn
    |> put_req_header(
      "cookie",
      "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
    )
    |> put_private(:test_session, session)
  end
end
