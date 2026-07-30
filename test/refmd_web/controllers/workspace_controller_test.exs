defmodule RefMDWeb.WorkspaceControllerTest do
  use RefMDWeb.ConnCase, async: true

  import Ecto.Query

  alias RefMD.Auth
  alias RefMD.Crypto.{Hash, Signature}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.{AuditChainEvent, AuditEvent}
  alias RefMD.Users
  alias RefMD.Users.User
  alias RefMD.Workspaces

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email
    })

    user_id
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
        name: "Owner Browser",
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

  defp install_signed_workspace_genesis!(workspace, owner_id, owner_device) do
    Repo.delete_all(
      from(event in AuditEvent, where: event.chain_scope == ^"workspace:#{workspace.id}")
    )

    attrs = workspace_genesis_attrs(workspace.id, owner_id, owner_device.device.id)

    event_hash =
      %{
        event_id: attrs.event_id,
        chain_scope_kind: "workspace",
        chain_scope_id: workspace.id,
        sequence: 1,
        previous_event_hash: "GENESIS",
        event_type: attrs.type,
        event_body: attrs.event_body
      }
      |> AuditChainEvent.build!()
      |> AuditChainEvent.hash!()

    payload = %{
      "protocol" => "refmd.signed-audit-checkpoint",
      "version" => 1,
      "chain_scope_kind" => "workspace",
      "chain_scope_id" => workspace.id,
      "sequence" => 1,
      "event_hash" => event_hash,
      "signer_user_id" => owner_id,
      "signer_device_id" => owner_device.device.id,
      "signing_key_id" => owner_device.device.signing_key_id,
      "authorization_checkpoint_scope_kind" => "workspace",
      "authorization_checkpoint_scope_id" => workspace.id,
      "authorization_checkpoint_sequence" => 0,
      "authorization_checkpoint_hash" => "GENESIS",
      "covered_event_class" => "authority",
      "covered_event_type" => "workspace.genesis"
    }

    transcript =
      Audit.build_audit_checkpoint_transcript!(
        "workspace_device",
        "device",
        owner_device.device.id,
        payload
      )

    envelope = %{
      "payload" => payload,
      "signature" =>
        Signature.__test_sign_hybrid_signature__(
          "audit_checkpoint",
          transcript,
          owner_device.signing_private_key,
          owner_device.device.hybrid_signing_public_key_material
        ),
      "checkpoint_hash" => Audit.checkpoint_hash!("workspace_device", payload)
    }

    assert {:ok, _result} =
             Security.record_signed_audit_events([attrs], envelope, [],
               genesis_candidate_authority: %{
                 chain_scope_kind: "workspace",
                 chain_scope_id: workspace.id,
                 signer_user_id: owner_id,
                 signer_device_id: owner_device.device.id,
                 public_key_material: owner_device.device.hybrid_signing_public_key_material
               }
             )
  end

  defp workspace_genesis_attrs(workspace_id, owner_id, device_id) do
    %{
      event_id: Ecto.UUID.generate(),
      class: "authority",
      type: "workspace.genesis",
      event_body: %{
        "protocol" => "refmd.audit.high-risk-mutation",
        "version" => 1,
        "event_type" => "workspace.genesis",
        "mutation_id" => Ecto.UUID.generate(),
        "chain_scope_kind" => "workspace",
        "chain_scope_id" => workspace_id,
        "actor" => %{"kind" => "device", "user_id" => owner_id, "device_id" => device_id},
        "subject_kind" => "workspace",
        "subject_id" => workspace_id,
        "canonical_request_hash" => Hash.blake3_base64url("workspace-controller-request"),
        "key_directory_effects_hash" => Hash.blake3_base64url("workspace-controller-effects")
      },
      actor: %{
        "user_id" => owner_id,
        "device_id" => device_id,
        "session_id" => nil,
        "principal_kind" => "user",
        "principal_id" => owner_id
      },
      scope: %{"workspace_id" => workspace_id, "document_id" => nil, "share_id" => nil},
      resource: %{"kind" => "workspace", "id" => workspace_id, "version_hash" => nil},
      action: %{
        "operation" => "workspace.genesis",
        "result" => "completed",
        "reason_code" => nil
      },
      sensitivity: Security.empty_sensitivity(),
      correlation: %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => nil
      }
    }
  end

  defp with_rrp_headers(conn, user_id, device, signing_private_key, method, path, body) do
    put_test_rrp_headers(conn, user_id, device, signing_private_key, method, path, body)
  end

  setup do
    owner_id = create_user("owner-workspace-controller@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Workspace Controller")
    owner_device = create_device(owner_id)
    install_signed_workspace_genesis!(workspace, owner_id, owner_device)

    %{owner_id: owner_id, workspace: workspace, owner_device: owner_device}
  end

  test "workspace and guest recipient lookup reject registered recipients without active devices",
       %{
         conn: conn,
         owner_id: owner_id,
         workspace: workspace,
         owner_device: owner_device
       } do
    recipient_email = "revoked-invitation-recipient@example.com"
    recipient_id = create_user(recipient_email)
    Users.update_encryption_setup(recipient_id)
    recipient_device = create_device(recipient_id)

    recipient_device.device
    |> Ecto.Changeset.change(revoked_at: DateTime.utc_now())
    |> Repo.update!()

    for recipient_path <- ["invitations/recipient", "guest-invitations/recipient"] do
      path = "/api/workspaces/#{workspace.id}/#{recipient_path}"
      query = URI.encode_query(%{"email" => recipient_email})

      response =
        conn
        |> recycle()
        |> authed_conn(owner_id, owner_device.device)
        |> put_test_rrp_headers(
          owner_id,
          owner_device.device,
          owner_device.signing_private_key,
          "GET",
          path,
          "",
          query
        )
        |> get(path <> "?" <> query)

      assert json_response(response, 409) == %{"error" => "recipient_delivery_unavailable"}
    end
  end

  test "rejects invalid guest_member_limit type", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    path = "/api/workspaces/#{workspace.id}"
    body = %{"guest_member_limit" => "10"}

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PATCH",
        path,
        body
      )
      |> patch(path, test_json_body(body))

    assert json_response(conn, 400) == %{
             "error" => "invalid_value",
             "field" => "guest_member_limit"
           }
  end

  test "rejects encrypted workspace metadata under an obsolete KEK", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    workspace
    |> Ecto.Changeset.change(
      current_kek_version: 2,
      kek_rotation_due_at: DateTime.add(DateTime.utc_now(), 3600, :second)
    )
    |> Repo.update!()

    path = "/api/workspaces/#{workspace.id}"

    body = %{
      "encrypted_name" => Base.url_encode64(:crypto.strong_rand_bytes(48), padding: false),
      "encrypted_name_nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
      "encrypted_name_key_version" => 1
    }

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PATCH",
        path,
        body
      )
      |> patch(path, test_json_body(body))

    assert json_response(conn, 422) == %{"error" => "kek_rotation_required"}
  end

  test "updates workspace plugin network proxy setting", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    path = "/api/workspaces/#{workspace.id}/features"

    body = %{
      "plugin_network_proxy" => %{
        "id" => "workspace-proxy",
        "label" => "Workspace Proxy",
        "base_url" => "https://proxy.example/refmd/",
        "scope" => "workspace",
        "enabled" => true,
        "operator_label" => "Example NetOps",
        "allowed_workspace_ids" => [workspace.id],
        "allowed_user_ids" => [owner_id],
        "verification_material" => %{"response_signing_key" => "proxy-key-1"},
        "revoked" => false,
        "policy" => %{"max_response_size" => 65_536}
      }
    }

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PATCH",
        path,
        body
      )
      |> patch(path, test_json_body(body))

    proxy = json_response(conn, 200)["plugin_network_proxy"]
    assert proxy["id"] == "workspace-proxy"
    assert proxy["label"] == "Workspace Proxy"
    assert proxy["base_url"] == "https://proxy.example/refmd"
    assert proxy["scope"] == "workspace"
    assert proxy["enabled"] == true
    assert proxy["operator_label"] == "Example NetOps"
    assert proxy["allowed_workspace_ids"] == [workspace.id]
    assert proxy["allowed_user_ids"] == [owner_id]
    assert proxy["verification_material"] == %{"response_signing_key" => "proxy-key-1"}
    assert proxy["revoked"] == false
    assert proxy["policy"] == %{"max_response_size" => 65_536}
  end

  test "rejects invalid workspace plugin network proxy enforcement metadata", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    path = "/api/workspaces/#{workspace.id}/features"

    body = %{
      "plugin_network_proxy" => %{
        "id" => "workspace-proxy",
        "label" => "Workspace Proxy",
        "base_url" => "https://proxy.example/refmd",
        "scope" => "workspace",
        "enabled" => true,
        "operator_label" => "Example NetOps",
        "allowed_workspace_ids" => [workspace.id, 42]
      }
    }

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PATCH",
        path,
        body
      )
      |> patch(path, test_json_body(body))

    assert %{"error" => "invalid_request_schema"} = json_response(conn, 422)
  end

  test "rejects invalid workspace plugin network proxy scope", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    path = "/api/workspaces/#{workspace.id}/features"

    body = %{
      "plugin_network_proxy" => %{
        "id" => "user-proxy",
        "label" => "User Proxy",
        "base_url" => "https://proxy.example/refmd",
        "scope" => "user",
        "enabled" => true
      }
    }

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PATCH",
        path,
        body
      )
      |> patch(path, test_json_body(body))

    assert %{"error" => "validation_error"} = json_response(conn, 422)
  end

  test "updates workspace user plugin policy setting", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    path = "/api/workspaces/#{workspace.id}/features"

    body = %{
      "plugin_user_policy" => %{
        "default_mode" => "deny_all",
        "allowed_plugin_ids" => ["com.example.allowed"],
        "denied_plugin_ids" => ["com.example.denied"],
        "require_admin_approval" => false
      }
    }

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PATCH",
        path,
        body
      )
      |> patch(path, test_json_body(body))

    assert %{
             "plugin_user_policy" => %{
               "default_mode" => "deny_all",
               "allowed_plugin_ids" => ["com.example.allowed"],
               "denied_plugin_ids" => ["com.example.denied"],
               "require_admin_approval" => false
             }
           } = json_response(conn, 200)
  end

  test "rejects invalid workspace user plugin policy", %{
    conn: conn,
    owner_id: owner_id,
    workspace: workspace,
    owner_device: owner_device
  } do
    path = "/api/workspaces/#{workspace.id}/features"

    body = %{
      "plugin_user_policy" => %{
        "allowed_plugin_ids" => ["com.example.same"],
        "denied_plugin_ids" => ["com.example.same"]
      }
    }

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PATCH",
        path,
        body
      )
      |> patch(path, test_json_body(body))

    assert %{"error" => "validation_error"} = json_response(conn, 422)
  end
end
