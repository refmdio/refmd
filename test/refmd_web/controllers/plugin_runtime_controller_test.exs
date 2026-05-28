defmodule RefMDWeb.PluginRuntimeControllerTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Auth
  alias RefMD.Crypto.{Hash, Signature}
  alias RefMD.Crypto.Signature.Plugin, as: PluginSignature
  alias RefMD.Devices.Device
  alias RefMD.Plugins
  alias RefMD.Plugins.Packages
  alias RefMD.Plugins.PluginActivation
  alias RefMD.Plugins.RuntimeDescriptors
  alias RefMD.Repo
  alias RefMD.Security.AuditEvent
  alias RefMD.Security.Notification
  alias RefMD.TestCrypto
  alias RefMD.Users.User
  alias RefMD.Workspaces

  test "returns a pinned runtime bundle only for matching state and consent heads", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Runtime Controller")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    {:ok, application} =
      create_plugin_application(%{
        workspace_id: workspace.id,
        plugin_id: "com.example.runtime",
        created_by_user_id: user_id,
        state_head_hash: "state-head"
      })

    manifest =
      ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.runtime","version":"1.0.0","permissions":["document:read:active"],"network":{"endpoints":[{"id":"api","url":"https://api.example.com/data","methods":["GET"],"routes":["proxy"],"headers":[],"bodySchema":"none","maxRequestBytes":256,"maxResponseBytes":512}]},"rendererSlots":[{"kind":"block","type":"summary"}],"documentScopes":[{"kind":"workspace"}]})

    archive_path =
      plugin_archive_path(%{
        "manifest.json" => manifest,
        "main.js" => "export default {}"
      })

    {:ok, candidate} =
      Plugins.create_local_bundle_candidate(archive_path, %{
        package_id: application.package_id,
        workspace_id: workspace.id,
        created_by_user_id: user_id,
        created_by_device_id: device.id
      })

    approval =
      approval_attrs(candidate, %{
        approver_user_id: user_id,
        approver_device_id: device.id,
        approval_epoch: 1,
        previous_approval_event_hash: "GENESIS"
      })

    {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

    {:ok, %{application: updated}} =
      Plugins.apply_package_to_workspace(workspace.id, package.id, user_id, device.id)

    {:ok, bundle} = Plugins.current_bundle_with_pin(updated.id, updated.state_head_hash)

    {:ok, consent} =
      Plugins.append_consent_event(
        consent_attrs(%{
          application_id: application.id,
          workspace_id: workspace.id,
          plugin_id: application.plugin_id,
          version: bundle.version,
          bundle_hash: bundle.bundle_hash,
          manifest_hash: bundle.manifest_hash,
          permissions_hash: bundle.permissions_hash,
          endpoint_hash: bundle.endpoint_hash,
          document_scope_hash: bundle.document_scope_hash,
          user_id: user_id,
          device_id: device.id,
          signer_user_id: user_id,
          signer_device_id: device.id
        })
      )

    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/sandbox-documents"
    capability_grant_id = runtime_capability_grant_id(updated, bundle, consent)

    body =
      Jason.encode!(%{
        "state_head_hash" => updated.state_head_hash,
        "consent_head_hash" => consent.event_hash,
        "capability_grant_id" => capability_grant_id
      })

    sandbox_session_conn =
      conn
      |> authed_conn(user_id, device)

    response =
      sandbox_session_conn
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, body)
      |> post(path, body)
      |> json_response(200)

    assert response["plugin_id"] == "com.example.runtime"
    assert response["bundle_hash"] == bundle.bundle_hash
    assert response["bundle_id"] == bundle.id
    assert response["owner_scope_kind"] == "workspace"
    assert response["state_head_hash"] == updated.state_head_hash
    assert response["approval_proof"]["event_hash"] == bundle.approval_event_hash
    assert response["consent_proof"]["event_hash"] == consent.event_hash
    assert response["sandbox_document_url"] =~ "/api/plugin-runtime/sandbox-documents/"
    assert response["boot_nonce"] =~ ~r/^[A-Za-z0-9_-]+$/
    assert response["frame_generation"] > 0
    assert response["capability_grant_id"] == capability_grant_id
    refute Map.has_key?(response, "main_js")

    forged_body =
      Jason.encode!(%{
        "state_head_hash" => updated.state_head_hash,
        "consent_head_hash" => consent.event_hash,
        "capability_grant_id" => Ecto.UUID.generate()
      })

    forged_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, forged_body)
      |> post(path, forged_body)

    assert json_response(forged_conn, 403) == %{
             "error" => "plugin_sandbox_document_capability_grant_mismatch"
           }

    forged_document_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_iframe_fetch_headers()

    forged_session =
      Plugins.create_sandbox_document_session(%{
        workspace_id: workspace.id,
        package_id: updated.package_id,
        application_id: updated.id,
        activation_id: consent.activation_id,
        owner_scope_kind: runtime_owner_scope_kind(application),
        user_id: user_id,
        device_id: device.id,
        auth_session_id: forged_document_conn.private.test_session.id,
        bundle_id: bundle.id,
        bundle_hash: bundle.bundle_hash,
        manifest_hash: bundle.manifest_hash,
        resource_manifest_hash: bundle.resource_manifest_hash,
        state_head_hash: updated.state_head_hash,
        consent_head_hash: consent.event_hash,
        consent_epoch: consent.consent_epoch,
        capability_grant_id: Ecto.UUID.generate()
      })

    forged_document_conn =
      forged_document_conn
      |> get("/api/plugin-runtime/sandbox-documents/#{forged_session.id}")

    assert json_response(forged_document_conn, 403) == %{
             "error" => "plugin_sandbox_document_capability_grant_mismatch"
           }

    valid_session_attrs = %{
      workspace_id: workspace.id,
      package_id: updated.package_id,
      application_id: updated.id,
      activation_id: consent.activation_id,
      owner_scope_kind: "workspace",
      user_id: user_id,
      device_id: device.id,
      auth_session_id: forged_document_conn.private.test_session.id,
      bundle_id: bundle.id,
      bundle_hash: bundle.bundle_hash,
      manifest_hash: bundle.manifest_hash,
      resource_manifest_hash: bundle.resource_manifest_hash,
      state_head_hash: updated.state_head_hash,
      consent_head_hash: consent.event_hash,
      consent_epoch: consent.consent_epoch,
      capability_grant_id: capability_grant_id
    }

    for attrs <- [
          %{package_id: Ecto.UUID.generate()},
          %{activation_id: Ecto.UUID.generate()},
          %{owner_scope_kind: "user"},
          %{bundle_id: Ecto.UUID.generate()},
          %{bundle_hash: hash("stale-bundle")},
          %{manifest_hash: hash("stale-manifest")},
          %{resource_manifest_hash: hash("stale-resource-manifest")},
          %{consent_epoch: consent.consent_epoch + 1}
        ] do
      mismatched_session =
        valid_session_attrs
        |> Map.merge(attrs)
        |> Plugins.create_sandbox_document_session()

      mismatched_conn =
        forged_document_conn
        |> same_auth_session_conn()
        |> put_iframe_fetch_headers()
        |> get("/api/plugin-runtime/sandbox-documents/#{mismatched_session.id}")

      assert json_response(mismatched_conn, 403) == %{
               "error" => "plugin_sandbox_document_session_mismatch"
             }
    end

    mismatch_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, body)
      |> post(path, body)
      |> json_response(200)

    mismatched_session_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_iframe_fetch_headers()
      |> get(mismatch_response["sandbox_document_url"])

    assert json_response(mismatched_session_conn, 403) == %{
             "error" => "plugin_sandbox_document_session_mismatch"
           }

    document_conn =
      sandbox_session_conn
      |> same_auth_session_conn()
      |> put_iframe_fetch_headers()
      |> get(response["sandbox_document_url"])

    assert get_resp_header(document_conn, "x-frame-options") == []
    assert [csp] = get_resp_header(document_conn, "content-security-policy")
    assert csp =~ "sandbox allow-scripts"
    assert csp =~ "frame-ancestors 'self'"
    assert csp =~ "script-src 'sha256-"
    assert response(document_conn, 200) =~ "export default {}"

    replay_conn =
      sandbox_session_conn
      |> same_auth_session_conn()
      |> put_iframe_fetch_headers()
      |> get(response["sandbox_document_url"])

    assert json_response(replay_conn, 403) == %{
             "error" => "plugin_sandbox_document_session_not_found"
           }

    stale_body =
      Jason.encode!(%{
        "state_head_hash" => hash("old-state"),
        "consent_head_hash" => consent.event_hash,
        "capability_grant_id" => capability_grant_id
      })

    stale_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, stale_body)
      |> post(path, stale_body)

    assert json_response(stale_conn, 409) == %{"error" => "plugin_state_rollback"}

    PluginActivation
    |> Repo.get!(consent.activation_id)
    |> PluginActivation.changeset(%{enabled: false})
    |> Repo.update!()

    disabled_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, body)
      |> post(path, body)

    assert json_response(disabled_conn, 403) == %{"error" => "plugin_activation_disabled"}
  end

  test "serves WASM resource bundles only with explicit accepted browser gate evidence", %{
    conn: conn
  } do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Runtime WASM")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    wasm_bytes = <<0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00>>

    %{updated: application, bundle: bundle, consent: consent} =
      create_runtime_application_with_entries(workspace.id, user_id, device, %{
        "manifest.json" =>
          ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.runtime","name":"Runtime","version":"1.0.0","permissions":["storage:read:workspace"],"documentScopes":[],"resources":[{"path":"resources/engine/search.wasm","kind":"wasm","media_type":"application/wasm"}]}),
        "main.js" => "export default {}",
        "resources/engine/search.wasm" => wasm_bytes
      })

    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/sandbox-documents"
    capability_grant_id = runtime_capability_grant_id(application, bundle, consent)

    body =
      Jason.encode!(%{
        "state_head_hash" => application.state_head_hash,
        "consent_head_hash" => consent.event_hash,
        "capability_grant_id" => capability_grant_id
      })

    sandbox_session_conn = conn |> authed_conn(user_id, device)

    no_gate_conn =
      sandbox_session_conn
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, body)
      |> post(path, body)

    assert json_response(no_gate_conn, 409) == %{"error" => "plugin_wasm_runtime_disabled"}

    unsupported_body =
      Jason.encode!(%{
        "state_head_hash" => application.state_head_hash,
        "consent_head_hash" => consent.event_hash,
        "capability_grant_id" => capability_grant_id,
        "wasm_browser_target" => "unsupported-browser"
      })

    unsupported_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        path,
        unsupported_body
      )
      |> post(path, unsupported_body)

    assert json_response(unsupported_conn, 409) == %{"error" => "plugin_wasm_variant_invalid"}

    previous_targets = Application.get_env(:refmd, :plugin_wasm_browser_targets, [])
    Application.put_env(:refmd, :plugin_wasm_browser_targets, ["test-browser"])
    on_exit(fn -> Application.put_env(:refmd, :plugin_wasm_browser_targets, previous_targets) end)

    accepted_body =
      Jason.encode!(%{
        "state_head_hash" => application.state_head_hash,
        "consent_head_hash" => consent.event_hash,
        "capability_grant_id" => capability_grant_id,
        "wasm_browser_target" => "test-browser"
      })

    accepted_session_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)

    response =
      accepted_session_conn
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, accepted_body)
      |> post(path, accepted_body)
      |> json_response(200)

    document_conn =
      accepted_session_conn
      |> same_auth_session_conn()
      |> put_iframe_fetch_headers()
      |> get(response["sandbox_document_url"])

    assert [csp] = get_resp_header(document_conn, "content-security-policy")
    assert csp =~ "'wasm-unsafe-eval'"
    refute csp =~ "'unsafe-eval'"
    html = response(document_conn, 200)
    assert html =~ "NativeWebAssembly.instantiate"
    assert html =~ "resources/engine/search.wasm"
    assert html =~ "browserTarget"
    assert html =~ "Object.defineProperty(globalThis, 'WebAssembly'"
  end

  test "updates current device activation state through plugin activation API", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Activation Update")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{updated: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/plugin-activations/#{consent.activation_id}"
    disable_body = Jason.encode!(%{"enabled" => false})

    disable_response =
      conn
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(user_id, device, signing_private_key, "PATCH", path, disable_body)
      |> patch(path, disable_body)
      |> json_response(200)

    assert disable_response["activation"]["id"] == consent.activation_id
    assert disable_response["activation"]["enabled"] == false
    assert Repo.get!(PluginActivation, consent.activation_id).enabled == false

    assert notification =
             Repo.get_by(Notification,
               type: "plugin.runtime_disabled",
               recipient_kind: "device",
               recipient_id: device.id
             )

    assert notification.action_ref["workspace_id"] == workspace.id
    assert notification.action_ref["package_id"] == application.package_id
    assert notification.action_ref["application_id"] == application.id
    assert notification.action_ref["activation_id"] == consent.activation_id
    assert notification.action_ref["plugin_id"] == application.plugin_id
    assert notification.action_ref["bundle_hash"] == bundle.bundle_hash

    runtime_path =
      "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/sandbox-documents"

    capability_grant_id = runtime_capability_grant_id(application, bundle, consent)

    runtime_body =
      Jason.encode!(%{
        "state_head_hash" => application.state_head_hash,
        "consent_head_hash" => consent.event_hash,
        "capability_grant_id" => capability_grant_id
      })

    disabled_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        runtime_path,
        runtime_body
      )
      |> post(runtime_path, runtime_body)

    assert json_response(disabled_conn, 403) == %{"error" => "plugin_activation_disabled"}

    enable_body = Jason.encode!(%{"enabled" => true})

    enable_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(user_id, device, signing_private_key, "PATCH", path, enable_body)
      |> patch(path, enable_body)
      |> json_response(200)

    assert enable_response["activation"]["enabled"] == true

    enabled_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        runtime_path,
        runtime_body
      )
      |> post(runtime_path, runtime_body)
      |> json_response(200)

    assert enabled_response["activation_id"] == consent.activation_id
  end

  test "rejects plugin activation updates owned by another user", %{conn: conn} do
    owner = create_runtime_account()
    %{user_id: owner_user_id, device: owner_device} = owner

    {:ok, workspace} =
      Workspaces.create_default_workspace(owner_user_id, "Plugin Activation Owner")

    insert_runtime_workspace_key_directory!(workspace.id, owner_user_id, owner)

    %{consent: consent} =
      create_runtime_application(workspace.id, owner_user_id, owner_device)

    requester = create_runtime_account()

    path = "/api/plugin-activations/#{consent.activation_id}"
    body = Jason.encode!(%{"enabled" => false})

    conn =
      conn
      |> authed_conn(requester.user_id, requester.device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(
        requester.user_id,
        requester.device,
        requester.signing_private_key,
        "PATCH",
        path,
        body
      )
      |> patch(path, body)

    assert json_response(conn, 404) == %{"error" => "not_found"}
    assert Repo.get!(PluginActivation, consent.activation_id).enabled == true
  end

  test "deletes current device activation and purges runtime eligibility", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Activation Delete")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/plugin-activations/#{consent.activation_id}"

    delete_response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "DELETE", path, "", "")
      |> delete(path)
      |> json_response(200)

    assert delete_response["activation"]["id"] == consent.activation_id
    assert delete_response["activation"]["enabled"] == false
    assert delete_response["activation"]["deleted_at"]
    assert delete_response["activation"]["workspace_id"] == workspace.id
    assert delete_response["activation"]["package_id"] == application.package_id
    assert delete_response["activation"]["application_id"] == application.id
    assert delete_response["activation"]["plugin_id"] == application.plugin_id
    assert delete_response["activation"]["bundle_hash"] == bundle.bundle_hash

    deleted = Repo.get!(PluginActivation, consent.activation_id)
    assert deleted.enabled == false
    assert deleted.deleted_at

    assert notification =
             Repo.get_by(Notification,
               type: "plugin.runtime_activation_deleted",
               recipient_kind: "device",
               recipient_id: device.id
             )

    assert notification.action_ref["workspace_id"] == workspace.id
    assert notification.action_ref["package_id"] == application.package_id
    assert notification.action_ref["application_id"] == application.id
    assert notification.action_ref["activation_id"] == consent.activation_id
    assert notification.action_ref["plugin_id"] == application.plugin_id
    assert notification.action_ref["bundle_hash"] == bundle.bundle_hash

    runtime_path =
      "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/sandbox-documents"

    runtime_body =
      Jason.encode!(%{
        "state_head_hash" => application.state_head_hash,
        "consent_head_hash" => consent.event_hash,
        "capability_grant_id" => runtime_capability_grant_id(application, bundle, consent)
      })

    deleted_runtime_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        runtime_path,
        runtime_body
      )
      |> post(runtime_path, runtime_body)

    assert json_response(deleted_runtime_conn, 403) == %{"error" => "plugin_activation_disabled"}

    list_path = "/api/plugin-activations"

    list_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "GET", list_path, "", "")
      |> get(list_path)
      |> json_response(200)

    refute Enum.any?(list_response["activations"], &(&1["id"] == consent.activation_id))

    {:ok, %{activation: replacement}} =
      Plugins.apply_package_to_workspace(workspace.id, application.package_id, user_id, device.id)

    assert replacement.id != consent.activation_id
    assert replacement.enabled == true
    assert replacement.deleted_at == nil

    assert [] =
             Repo.query!("""
             SELECT indexname
             FROM pg_indexes
             WHERE tablename = 'plugin_activations'
               AND indexname IN (
                 'plugin_activations_user_actor_index',
                 'plugin_activations_device_actor_index'
               )
             """).rows
  end

  test "sandbox document load revalidates current workspace membership", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Runtime RBAC")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, updated: updated, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/sandbox-documents"
    capability_grant_id = runtime_capability_grant_id(updated, bundle, consent)

    body =
      Jason.encode!(%{
        "state_head_hash" => updated.state_head_hash,
        "consent_head_hash" => consent.event_hash,
        "capability_grant_id" => capability_grant_id
      })

    sandbox_session_conn =
      conn
      |> authed_conn(user_id, device)

    response =
      sandbox_session_conn
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, body)
      |> post(path, body)
      |> json_response(200)

    workspace.id
    |> Workspaces.get_workspace_member(user_id)
    |> Repo.delete!()

    document_conn =
      sandbox_session_conn
      |> same_auth_session_conn()
      |> put_iframe_fetch_headers()
      |> get(response["sandbox_document_url"])

    assert json_response(document_conn, 403) == %{
             "error" => "plugin_sandbox_document_workspace_forbidden"
           }
  end

  test "sandbox document load rejects invalid fetch metadata before consuming session", %{
    conn: conn
  } do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Runtime Fetch Metadata")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, updated: updated, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/sandbox-documents"
    capability_grant_id = runtime_capability_grant_id(updated, bundle, consent)

    body =
      Jason.encode!(%{
        "state_head_hash" => updated.state_head_hash,
        "consent_head_hash" => consent.event_hash,
        "capability_grant_id" => capability_grant_id
      })

    sandbox_session_conn =
      conn
      |> authed_conn(user_id, device)

    response =
      sandbox_session_conn
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, body)
      |> post(path, body)
      |> json_response(200)

    missing_metadata_conn =
      sandbox_session_conn
      |> same_auth_session_conn()
      |> get(response["sandbox_document_url"])

    assert json_response(missing_metadata_conn, 403) == %{
             "error" => "plugin_sandbox_document_fetch_context_invalid"
           }

    top_level_conn =
      sandbox_session_conn
      |> same_auth_session_conn()
      |> put_req_header("sec-fetch-dest", "document")
      |> put_req_header("sec-fetch-mode", "navigate")
      |> put_req_header("sec-fetch-site", "same-origin")
      |> get(response["sandbox_document_url"])

    assert json_response(top_level_conn, 403) == %{
             "error" => "plugin_sandbox_document_fetch_context_invalid"
           }

    cross_site_conn =
      sandbox_session_conn
      |> same_auth_session_conn()
      |> put_req_header("sec-fetch-dest", "iframe")
      |> put_req_header("sec-fetch-mode", "navigate")
      |> put_req_header("sec-fetch-site", "cross-site")
      |> get(response["sandbox_document_url"])

    assert json_response(cross_site_conn, 403) == %{
             "error" => "plugin_sandbox_document_fetch_context_invalid"
           }

    valid_conn =
      sandbox_session_conn
      |> same_auth_session_conn()
      |> put_iframe_fetch_headers()
      |> get(response["sandbox_document_url"])

    assert response(valid_conn, 200) =~ "export default {}"
  end

  test "lists runtime descriptors only for current allowed plugin consent", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Runtime Descriptors")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, updated: updated, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime"

    response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "GET", path, "", "")
      |> get(path)
      |> json_response(200)

    assert [
             %{
               "plugin_id" => "com.example.runtime",
               "application_id" => application_id,
               "state_head_hash" => state_head_hash,
               "consent_head_hash" => consent_head_hash,
               "capability_grant_id" => capability_grant_id,
               "bundle_hash" => bundle_hash
             }
           ] = response["applications"]

    assert application_id == application.id
    assert state_head_hash == updated.state_head_hash
    assert consent_head_hash == consent.event_hash
    assert {:ok, _} = Ecto.UUID.cast(capability_grant_id)
    assert bundle_hash == bundle.bundle_hash
  end

  test "applies a user-owned package to workspace runtime through management API", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account
    device = TestCrypto.ensure_test_user_pop_key_directory!(user_id, device)

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "User Plugin Runtime")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    archive_path =
      plugin_archive_path(%{
        "manifest.json" =>
          ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"optional"},"id":"com.example.user-runtime","name":"User Runtime","version":"1.0.0","permissions":[],"documentScopes":[]}),
        "main.js" => "export default {}"
      })

    {:ok, candidate} =
      Plugins.create_local_bundle_candidate(archive_path, %{
        owner_scope_kind: "user",
        created_by_user_id: user_id,
        created_by_device_id: device.id
      })

    approval =
      approval_attrs(candidate, %{
        approver_user_id: user_id,
        approver_device_id: device.id,
        approval_epoch: 1,
        previous_approval_event_hash: "GENESIS"
      })

    {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)
    bundle = Repo.get!(RefMD.Plugins.PluginBundle, package.current_bundle_id)
    apply_path = "/api/workspaces/#{workspace.id}/plugin-applications"
    apply_body = Jason.encode!(%{"package_id" => package.id})

    apply_response =
      conn
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        apply_path,
        apply_body
      )
      |> post(apply_path, apply_body)
      |> json_response(200)

    application_id = get_in(apply_response, ["application", "id"])
    activation_id = get_in(apply_response, ["activation", "id"])
    assert get_in(apply_response, ["application", "application_mode"]) == "user_applied"
    assert get_in(apply_response, ["activation", "application_id"]) == application_id

    activations_path = "/api/plugin-activations"

    activations_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "GET",
        activations_path,
        "",
        ""
      )
      |> get(activations_path)
      |> json_response(200)

    assert Enum.any?(
             activations_response["activations"],
             &(&1["id"] == activation_id and &1["application_id"] == application_id)
           )

    {:ok, consent} =
      Plugins.append_consent_event(
        consent_attrs(%{
          application_id: application_id,
          workspace_id: workspace.id,
          plugin_id: package.plugin_id,
          version: bundle.version,
          bundle_hash: bundle.bundle_hash,
          manifest_hash: bundle.manifest_hash,
          permissions_hash: bundle.permissions_hash,
          endpoint_hash: bundle.endpoint_hash,
          document_scope_hash: bundle.document_scope_hash,
          user_id: user_id,
          device_id: device.id,
          signer_user_id: user_id,
          signer_device_id: device.id
        })
      )

    runtime_path = "/api/workspaces/#{workspace.id}/plugin-runtime"

    runtime_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "GET", runtime_path, "", "")
      |> get(runtime_path)
      |> json_response(200)

    assert [
             %{
               "application_id" => ^application_id,
               "activation_id" => ^activation_id,
               "owner_scope_kind" => "user",
               "state_head_hash" => state_head_hash,
               "consent_head_hash" => consent_head_hash
             }
           ] = runtime_response["applications"]

    assert state_head_hash == package.state_head_hash
    assert consent_head_hash == consent.event_hash
  end

  test "lists consent-required plugin descriptors without enabling runtime load", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Consent Required")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    {:ok, application} =
      create_plugin_application(%{
        workspace_id: workspace.id,
        plugin_id: "com.example.runtime",
        created_by_user_id: user_id,
        state_head_hash: "state-head"
      })

    archive_path =
      plugin_archive_path(%{
        "manifest.json" =>
          ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.runtime","name":"Runtime","author":"Example Author","version":"1.0.0"}),
        "main.js" => "export default {}"
      })

    {:ok, candidate} =
      Plugins.create_local_bundle_candidate(archive_path, %{
        package_id: application.package_id,
        workspace_id: workspace.id,
        created_by_user_id: user_id,
        created_by_device_id: device.id
      })

    approval =
      approval_attrs(candidate, %{
        approver_user_id: user_id,
        approver_device_id: device.id,
        approval_epoch: 1,
        previous_approval_event_hash: "GENESIS"
      })

    {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

    {:ok, %{application: updated}} =
      Plugins.apply_package_to_workspace(workspace.id, package.id, user_id, device.id)

    runtime_path = "/api/workspaces/#{workspace.id}/plugin-runtime"
    consent_path = "/api/workspaces/#{workspace.id}/plugin-runtime/consent-required"

    runtime_response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "GET", runtime_path, "", "")
      |> get(runtime_path)
      |> json_response(200)

    assert runtime_response["applications"] == []

    consent_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "GET", consent_path, "", "")
      |> get(consent_path)
      |> json_response(200)

    assert [
             %{
               "application_id" => application_id,
               "activation_id" => activation_id,
               "state_head_hash" => state_head_hash,
               "consent_head_hash" => nil,
               "author" => author,
               "signer_user_id" => signer_user_id,
               "signer_device_id" => signer_device_id
             }
           ] = consent_response["applications"]

    assert application_id == application.id
    assert state_head_hash == updated.state_head_hash
    assert author == "Example Author"
    assert signer_user_id == user_id
    assert signer_device_id == device.id

    assert Repo.get_by!(RefMD.Plugins.PluginActivation,
             id: activation_id,
             application_id: application.id,
             user_id: user_id,
             device_id: device.id
           )
  end

  test "runtime descriptors preserve document, network, and high-risk consent policy", %{
    conn: conn
  } do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Runtime Policy")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    manifest =
      ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.runtime","name":"Runtime","version":"1.0.0","permissions":["network:fetch","document:read:active","storage:write:cache"],"network":{"endpoints":[{"id":"github-rest","url":"https://api.github.com/repos/refmdio/refmd/issues","methods":["GET"],"routes":["proxy"],"headers":["accept"],"bodySchema":"none","maxRequestBytes":1024,"maxResponseBytes":2048}]},"rendererSlots":[{"kind":"block","type":"chart"}],"documentScopes":[{"kind":"workspace"},{"kind":"active","id":"active"},{"kind":"selected","id":"selected"},{"kind":"allowed_documents","documentIds":["doc-allowed"]}]})

    create_runtime_application(workspace.id, user_id, device, manifest)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime"

    response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "GET", path, "", "")
      |> get(path)
      |> json_response(200)

    assert [
             %{
               "document_scope" => %{
                 "workspaceReadAllowed" => true,
                 "activeDocumentReadAllowed" => true,
                 "selectedDocumentsReadAllowed" => true,
                 "allowedDocumentIds" => ["doc-allowed"]
               },
               "network_endpoints" => [
                 %{
                   "id" => "github-rest",
                   "url" => "https://api.github.com/repos/refmdio/refmd/issues",
                   "methods" => ["GET"],
                   "routes" => ["proxy"],
                   "headers" => ["accept"],
                   "bodySchema" => "none",
                   "maxRequestBytes" => 1024,
                   "maxResponseBytes" => 2048
                 }
               ],
               "renderer_slots" => [%{"kind" => "block", "type" => "chart"}],
               "high_risk_consents" => [
                 "plaintext_network_egress",
                 "plaintext_cache_storage"
               ]
             }
           ] = response["applications"]
  end

  test "runtime descriptors ignore manifest-authored high-risk consent labels", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Runtime Label Ignore")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    manifest =
      ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.runtime","name":"Runtime","version":"1.0.0","permissions":[],"highRiskConsents":["plaintext_network_egress","plaintext_document_write"],"network":{"endpoints":[]}})

    create_runtime_application(workspace.id, user_id, device, manifest)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime"

    response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "GET", path, "", "")
      |> get(path)
      |> json_response(200)

    assert [%{"high_risk_consents" => []}] = response["applications"]
  end

  test "workspace plugin management routes create candidates, promote, and append consent", %{
    conn: conn
  } do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Management")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    manifest =
      ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.runtime","version":"1.0.0","permissions":["document:read:active"],"network":{"endpoints":[{"id":"api","url":"https://api.example.com/data","methods":["GET"],"routes":["proxy"],"headers":[],"bodySchema":"none","maxRequestBytes":256,"maxResponseBytes":512}]},"rendererSlots":[{"kind":"block","type":"summary"}],"documentScopes":[{"kind":"workspace"}]})

    archive_path =
      plugin_archive_path(%{
        "manifest.json" => manifest,
        "main.js" => "export default {}"
      })

    local_path = "/api/workspaces/#{workspace.id}/plugin-packages"

    local_body = %{
      "source_kind" => "local_upload",
      "archive_base64" => Base.encode64(File.read!(archive_path))
    }

    scoped_user_body = Map.put(local_body, "owner_scope_kind", "user")

    scoped_user_response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        local_path,
        scoped_user_body,
        ""
      )
      |> post(local_path, test_json_body(scoped_user_body))
      |> json_response(422)

    assert scoped_user_response["error"] == "plugin_package_scope_unsupported"

    manifest_routed_path = "/api/plugin-candidates"

    other_account = create_runtime_account()

    %{
      user_id: other_user_id,
      device: other_device,
      signing_private_key: other_signing_private_key
    } = other_account

    unauthorized_workspace_body = %{
      "source_kind" => "local_upload",
      "archive_base64" => "not-base64",
      "workspace_id" => workspace.id
    }

    unauthorized_workspace_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(other_user_id, other_device)
      |> put_test_pop_headers(
        other_user_id,
        other_device,
        other_signing_private_key,
        "POST",
        manifest_routed_path,
        unauthorized_workspace_body,
        ""
      )
      |> post(manifest_routed_path, test_json_body(unauthorized_workspace_body))
      |> json_response(403)

    assert unauthorized_workspace_response["error"] == "plugin_package_forbidden"

    manifest_routed_body =
      local_body
      |> Map.put("workspace_id", workspace.id)

    manifest_routed_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        manifest_routed_path,
        manifest_routed_body,
        ""
      )
      |> post(manifest_routed_path, test_json_body(manifest_routed_body))
      |> json_response(200)

    assert get_in(manifest_routed_response, ["candidate", "owner_scope_kind"]) == "workspace"
    assert get_in(manifest_routed_response, ["candidate", "workspace_id"]) == workspace.id

    assert get_in(manifest_routed_response, [
             "candidate",
             "scope_summary",
             "supported_owner_scopes"
           ]) == ["workspace"]

    assert get_in(manifest_routed_response, [
             "candidate",
             "scope_summary",
             "default_owner_scope"
           ]) == "workspace"

    assert get_in(manifest_routed_response, [
             "candidate",
             "scope_summary",
             "workspace_application"
           ]) == "required"

    assert get_in(manifest_routed_response, [
             "candidate",
             "approval_summary",
             "subject",
             "owner_scope_kind"
           ]) == "workspace"

    assert get_in(manifest_routed_response, [
             "candidate",
             "approval_summary",
             "subject",
             "approver_device_id"
           ]) == device.id

    assert get_in(manifest_routed_response, [
             "candidate",
             "approval_summary",
             "actor",
             "key_scope_id"
           ]) == workspace.id

    assert get_in(manifest_routed_response, [
             "candidate",
             "approval_summary",
             "previous_approval_event_hash"
           ]) == "GENESIS"

    user_manifest =
      ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"none"},"id":"com.example.user","version":"1.0.0","permissions":[]})

    user_archive_path =
      plugin_archive_path(%{
        "manifest.json" => user_manifest,
        "main.js" => "export default {}"
      })

    user_manifest_body = %{
      "source_kind" => "local_upload",
      "archive_base64" => Base.encode64(File.read!(user_archive_path)),
      "workspace_id" => workspace.id
    }

    user_manifest_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        manifest_routed_path,
        user_manifest_body,
        ""
      )
      |> post(manifest_routed_path, test_json_body(user_manifest_body))
      |> json_response(200)

    assert get_in(user_manifest_response, ["candidate", "owner_scope_kind"]) == "user"
    assert is_nil(get_in(user_manifest_response, ["candidate", "workspace_id"]))

    assert get_in(user_manifest_response, [
             "candidate",
             "scope_summary",
             "supported_owner_scopes"
           ]) == ["user"]

    assert get_in(user_manifest_response, [
             "candidate",
             "approval_summary",
             "subject",
             "owner_scope_kind"
           ]) == "user"

    assert get_in(user_manifest_response, [
             "candidate",
             "approval_summary",
             "actor",
             "key_scope_kind"
           ]) == "user"

    assert get_in(user_manifest_response, [
             "candidate",
             "approval_summary",
             "actor",
             "key_scope_id"
           ]) == user_id

    user_manifest_candidate_id = get_in(user_manifest_response, ["candidate", "id"])
    user_manifest_candidate = Plugins.get_bundle_candidate(user_manifest_candidate_id)

    user_manifest_approval =
      approval_attrs(user_manifest_candidate, %{
        approver_user_id: user_id,
        approver_device_id: device.id,
        approval_epoch: 1,
        previous_approval_event_hash: "GENESIS"
      })

    user_manifest_promote_path = "/api/plugin-candidates/#{user_manifest_candidate_id}/approval"

    user_manifest_promote_body = %{
      "approval_event_hash" => user_manifest_approval.approval_event_hash,
      "approval_epoch" => user_manifest_approval.approval_epoch,
      "previous_approval_event_hash" => user_manifest_approval.previous_approval_event_hash,
      "created_at_ms" => user_manifest_approval.created_at_ms,
      "hybrid_signature" => user_manifest_approval.hybrid_signature,
      "workspace_id" => workspace.id
    }

    user_manifest_promote_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        user_manifest_promote_path,
        user_manifest_promote_body,
        ""
      )
      |> post(user_manifest_promote_path, test_json_body(user_manifest_promote_body))
      |> json_response(200)

    assert get_in(user_manifest_promote_response, ["package", "owner_scope_kind"]) == "user"
    assert get_in(user_manifest_promote_response, ["application", "workspace_id"]) == workspace.id

    assert get_in(user_manifest_promote_response, ["application", "application_mode"]) ==
             "user_applied"

    assert get_in(user_manifest_promote_response, ["activation", "application_id"]) ==
             get_in(user_manifest_promote_response, ["application", "id"])

    member_account = create_runtime_account()

    %{
      user_id: member_user_id,
      device: member_device,
      signing_private_key: member_signing_private_key
    } = member_account

    add_workspace_member(workspace.id, member_user_id, "editor")

    dual_manifest =
      ~s({"scope":{"supportedOwnerScopes":["user","workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"optional"},"id":"com.example.dual","version":"1.0.0","permissions":[]})

    dual_archive_path =
      plugin_archive_path(%{
        "manifest.json" => dual_manifest,
        "main.js" => "export default {}"
      })

    dual_manifest_body = %{
      "source_kind" => "local_upload",
      "archive_base64" => Base.encode64(File.read!(dual_archive_path))
    }

    dual_manifest_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(member_user_id, member_device)
      |> put_test_pop_headers(
        member_user_id,
        member_device,
        member_signing_private_key,
        "POST",
        manifest_routed_path,
        dual_manifest_body,
        ""
      )
      |> post(manifest_routed_path, test_json_body(dual_manifest_body))
      |> json_response(200)

    assert get_in(dual_manifest_response, ["candidate", "owner_scope_kind"]) == "user"
    assert is_nil(get_in(dual_manifest_response, ["candidate", "workspace_id"]))

    assert get_in(dual_manifest_response, [
             "candidate",
             "scope_summary",
             "supported_owner_scopes"
           ]) == ["user", "workspace"]

    assert get_in(dual_manifest_response, [
             "candidate",
             "scope_summary",
             "default_owner_scope"
           ]) == "workspace"

    assert get_in(dual_manifest_response, [
             "candidate",
             "approval_summary",
             "subject",
             "owner_scope_kind"
           ]) == "user"

    assert get_in(dual_manifest_response, [
             "candidate",
             "approval_summary",
             "actor",
             "key_scope_kind"
           ]) == "user"

    assert get_in(dual_manifest_response, [
             "candidate",
             "approval_summary",
             "actor",
             "key_scope_id"
           ]) == member_user_id

    local_response =
      conn
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        local_path,
        local_body,
        ""
      )
      |> post(local_path, test_json_body(local_body))
      |> json_response(200)

    candidate_id = get_in(local_response, ["candidate", "id"])
    candidate = Plugins.get_bundle_candidate(candidate_id)
    refute candidate.application_id

    summary_path = "/api/plugin-candidates/#{candidate_id}"

    summary_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "GET", summary_path, "", "")
      |> get(summary_path)
      |> json_response(200)

    assert %{
             "archive_hash" => _,
             "source_url_hash" => "NO_SOURCE_URL",
             "main_js_hash" => _,
             "styles_css_hash" => _,
             "permissions_hash" => _,
             "endpoint_hash" => _,
             "renderer_slots_hash" => _,
             "document_scope_hash" => _,
             "capability_summary" => %{
               "permissions" => ["document:read:active"],
               "network_endpoints" => [%{"id" => "api"}],
               "renderer_slots" => [%{"kind" => "block"}],
               "document_scopes" => [%{"kind" => "workspace"}]
             },
             "scope_summary" => %{
               "supported_owner_scopes" => ["workspace"],
               "default_owner_scope" => "workspace",
               "workspace_application" => "required"
             },
             "approval_summary" => %{
               "approval_event_hash" => approval_event_hash,
               "approval_epoch" => 1,
               "previous_approval_event_hash" => "GENESIS",
               "actor" => %{
                 "device_id" => device_id,
                 "key_scope_kind" => "workspace",
                 "key_scope_id" => workspace_id
               },
               "subject" => %{
                 "owner_scope_kind" => "workspace",
                 "approver_user_id" => approver_user_id,
                 "approver_device_id" => approver_device_id,
                 "previous_approval_event_hash" => "GENESIS"
               }
             }
           } = summary_response["candidate"]

    assert is_binary(approval_event_hash)
    assert device_id == device.id
    assert workspace_id == workspace.id
    assert approver_user_id == user_id
    assert approver_device_id == device.id

    approval =
      approval_attrs(candidate, %{
        approver_user_id: user_id,
        approver_device_id: device.id,
        approval_epoch: 1,
        previous_approval_event_hash: "GENESIS"
      })

    promote_path = "/api/plugin-candidates/#{candidate_id}/approval"

    promote_body = %{
      "approval_event_hash" => approval.approval_event_hash,
      "approval_epoch" => approval.approval_epoch,
      "previous_approval_event_hash" => approval.previous_approval_event_hash,
      "created_at_ms" => approval.created_at_ms,
      "hybrid_signature" => approval.hybrid_signature
    }

    promote_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        promote_path,
        promote_body,
        ""
      )
      |> post(promote_path, test_json_body(promote_body))
      |> json_response(200)

    assert get_in(promote_response, ["package", "current_bundle_id"])
    package_id = get_in(promote_response, ["package", "id"])

    package_list_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "GET", local_path, "", "")
      |> get(local_path)
      |> json_response(200)

    assert Enum.any?(package_list_response["packages"], fn package ->
             package["id"] == candidate.package_id and
               package["owner_scope_kind"] == "workspace" and
               package["owner_workspace_id"] == workspace.id
           end)

    apply_path = "/api/workspaces/#{workspace.id}/plugin-applications"
    apply_body = %{"package_id" => package_id}

    apply_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        apply_path,
        apply_body,
        ""
      )
      |> post(apply_path, test_json_body(apply_body))
      |> json_response(200)

    application_id = get_in(apply_response, ["application", "id"])
    activation_id = get_in(apply_response, ["activation", "id"])
    state_head_hash = get_in(apply_response, ["application", "state_head_hash"])

    assert is_binary(application_id)
    assert is_binary(activation_id)
    assert get_in(apply_response, ["application", "application_mode"]) == "workspace_shared"
    assert get_in(apply_response, ["application", "package_id"]) == candidate.package_id
    assert get_in(apply_response, ["activation", "application_id"]) == application_id

    list_path = "/api/workspaces/#{workspace.id}/plugin-applications"

    list_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "GET", list_path, "", "")
      |> get(list_path)
      |> json_response(200)

    assert Enum.any?(list_response["plugins"], fn plugin ->
             plugin["id"] == application_id and
               plugin["plugin_id"] == "com.example.runtime" and
               plugin["state_head_hash"] == state_head_hash
           end)

    duplicate = create_runtime_application(workspace.id, user_id, device)
    duplicate_id = duplicate.updated.id

    update_path = "/api/workspaces/#{workspace.id}/plugin-applications/#{application_id}"
    disable_body = %{"enabled" => false}

    disable_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "PATCH",
        update_path,
        disable_body,
        ""
      )
      |> patch(update_path, test_json_body(disable_body))
      |> json_response(200)

    assert get_in(disable_response, ["plugin", "enabled"]) == false
    assert Repo.get!(RefMD.Plugins.PluginApplication, duplicate_id).enabled == true

    enable_body = %{"enabled" => true}

    Phoenix.ConnTest.build_conn()
    |> authed_conn(user_id, device)
    |> put_test_pop_headers(
      user_id,
      device,
      signing_private_key,
      "PATCH",
      update_path,
      enable_body,
      ""
    )
    |> patch(update_path, test_json_body(enable_body))
    |> json_response(200)

    policy_body = %{"workspace_policy_result" => "needs_admin_review"}

    policy_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "PATCH",
        update_path,
        policy_body,
        ""
      )
      |> patch(update_path, test_json_body(policy_body))
      |> json_response(200)

    assert get_in(policy_response, ["plugin", "workspace_policy_result"]) == "needs_admin_review"

    allow_body = %{"workspace_policy_result" => "allowed"}

    Phoenix.ConnTest.build_conn()
    |> authed_conn(user_id, device)
    |> put_test_pop_headers(
      user_id,
      device,
      signing_private_key,
      "PATCH",
      update_path,
      allow_body,
      ""
    )
    |> patch(update_path, test_json_body(allow_body))
    |> json_response(200)

    {:ok, bundle} =
      Plugins.current_bundle_with_pin(
        application_id,
        state_head_hash
      )

    consent =
      consent_attrs(%{
        application_id: application_id,
        workspace_id: workspace.id,
        plugin_id: "com.example.runtime",
        version: bundle.version,
        bundle_hash: bundle.bundle_hash,
        manifest_hash: bundle.manifest_hash,
        permissions_hash: bundle.permissions_hash,
        endpoint_hash: bundle.endpoint_hash,
        document_scope_hash: bundle.document_scope_hash,
        user_id: user_id,
        device_id: device.id,
        signer_user_id: user_id,
        signer_device_id: device.id
      })

    consent_path =
      "/api/workspaces/#{workspace.id}/plugin-applications/#{application_id}/consent-events"

    consent_body = %{
      "plugin_id" => consent.plugin_id,
      "package_id" => candidate.package_id,
      "application_id" => application_id,
      "activation_id" => activation_id,
      "owner_scope_kind" => "workspace",
      "application_scope_kind" => "workspace",
      "workspace_id" => workspace.id,
      "version" => consent.version,
      "bundle_hash" => consent.bundle_hash,
      "manifest_hash" => consent.manifest_hash,
      "resource_manifest_hash" => bundle.resource_manifest_hash,
      "permissions_hash" => consent.permissions_hash,
      "endpoint_hash" => consent.endpoint_hash,
      "document_scope_hash" => consent.document_scope_hash,
      "signer_user_id" => user_id,
      "signer_device_id" => device.id,
      "user_id" => user_id,
      "device_id" => device.id,
      "decision" => consent.decision,
      "consent_epoch" => consent.consent_epoch,
      "previous_event_hash" => consent.previous_event_hash,
      "event_hash" => consent.event_hash,
      "hybrid_signature" => consent.hybrid_signature
    }

    consent_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        consent_path,
        consent_body,
        ""
      )
      |> post(consent_path, test_json_body(consent_body))
      |> json_response(200)

    assert get_in(consent_response, ["consent_event", "event_hash"]) == consent.event_hash

    delete_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "DELETE", update_path, "", "")
      |> delete(update_path)
      |> json_response(200)

    assert get_in(delete_response, ["plugin", "id"]) == application_id
    assert get_in(delete_response, ["plugin", "enabled"]) == false
    assert get_in(delete_response, ["plugin", "current_bundle_id"]) == nil
    assert get_in(delete_response, ["plugin", "deleted_at"])

    deleted_application = Repo.get!(RefMD.Plugins.PluginApplication, application_id)
    assert deleted_application.deleted_at
    assert deleted_application.enabled == false
    assert deleted_application.current_bundle_id == nil

    deleted_activation = Repo.get!(PluginActivation, activation_id)
    assert deleted_activation.deleted_at
    assert deleted_activation.enabled == false

    list_after_delete_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "GET", list_path, "", "")
      |> get(list_path)
      |> json_response(200)

    refute Enum.any?(list_after_delete_response["plugins"], &(&1["id"] == application_id))

    activations_after_delete_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "GET",
        "/api/plugin-activations",
        "",
        ""
      )
      |> get("/api/plugin-activations")
      |> json_response(200)

    refute Enum.any?(
             activations_after_delete_response["activations"],
             &(&1["id"] == activation_id)
           )

    runtime_path =
      "/api/workspaces/#{workspace.id}/plugin-runtime/#{application_id}/sandbox-documents"

    runtime_body =
      Jason.encode!(%{
        "state_head_hash" => state_head_hash,
        "consent_head_hash" => consent.event_hash,
        "capability_grant_id" => Ecto.UUID.generate()
      })

    deleted_runtime_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        runtime_path,
        runtime_body
      )
      |> post(runtime_path, runtime_body)

    assert json_response(deleted_runtime_conn, 403) == %{"error" => "plugin_application_disabled"}

    reapply_response =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        apply_path,
        apply_body,
        ""
      )
      |> post(apply_path, test_json_body(apply_body))
      |> json_response(200)

    assert get_in(reapply_response, ["application", "id"]) == application_id
    refute get_in(reapply_response, ["application", "deleted_at"])
    assert get_in(reapply_response, ["application", "enabled"]) == true
    assert get_in(reapply_response, ["activation", "id"]) != activation_id
  end

  test "plugin artifact acquisition and sandbox arming routes reject missing PoP", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Missing PoP")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    sandbox_path =
      "/api/workspaces/#{workspace.id}/plugin-runtime/#{Ecto.UUID.generate()}/sandbox-documents"

    sandbox_body = %{
      "state_head_hash" => "state-head",
      "consent_head_hash" => "consent-head",
      "capability_grant_id" => Ecto.UUID.generate()
    }

    sandbox_response =
      conn
      |> authed_conn(user_id, device)
      |> put_req_header("content-type", "application/json")
      |> post(sandbox_path, test_json_body(sandbox_body))
      |> json_response(403)

    assert sandbox_response["error"] == "pop_missing_device_id"

    local_body = %{
      "source_kind" => "local_upload",
      "archive_base64" => Base.encode64("not-a-plugin-archive")
    }

    missing_pop_posts = [
      {"/api/workspaces/#{workspace.id}/plugin-packages", local_body},
      {"/api/plugin-packages", local_body},
      {"/api/plugin-candidates", Map.put(local_body, "workspace_id", workspace.id)},
      {"/api/plugin-candidates/#{Ecto.UUID.generate()}/approval",
       %{
         "approval_event_hash" => hash("approval"),
         "approval_epoch" => 1,
         "previous_approval_event_hash" => "GENESIS",
         "created_at_ms" => 1,
         "hybrid_signature" => %{"protocol" => "refmd.hybrid-signature"}
       }}
    ]

    for {path, body} <- missing_pop_posts do
      response =
        Phoenix.ConnTest.build_conn()
        |> authed_conn(user_id, device)
        |> put_req_header("content-type", "application/json")
        |> post(path, test_json_body(body))
        |> json_response(403)

      assert response["error"] == "pop_missing_device_id"
    end
  end

  test "records plugin runtime audit events through the security audit plane", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Runtime Audit")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"
    frame_generation = current_runtime_frame_generation!(application, bundle, consent)

    body = %{
      "type" => "plugin.sandbox.loaded",
      "plugin_id" => "com.example.runtime",
      "package_id" => application.package_id,
      "application_id" => application.id,
      "activation_id" => consent.activation_id,
      "owner_scope_kind" => "workspace",
      "state_head_hash" => application.state_head_hash,
      "consent_head_hash" => consent.event_hash,
      "capability_grant_id" => runtime_capability_grant_id(application, bundle, consent),
      "consent_epoch" => consent.consent_epoch,
      "frame_generation" => frame_generation,
      "workspace_id" => workspace.id,
      "bundle_hash" => bundle.bundle_hash,
      "manifest_hash" => bundle.manifest_hash,
      "capability_id" => "capability",
      "operation" => "plugin.sandbox.load",
      "resource" => %{
        "kind" => "plugin",
        "id" => "com.example.runtime",
        "version_hash" => hash("bundle")
      },
      "action" => %{"operation" => "plugin.sandbox.load", "result" => "completed"},
      "sensitivity" => %{
        "plaintext_scope_kind" => "none",
        "plaintext_bytes" => 0,
        "egress_bytes" => 0,
        "storage_bytes" => 0
      },
      "correlation" => %{
        "request_id" => "request-1",
        "capability_id" => "capability",
        "execution_context_id" => "execution-context-1",
        "authority_event_ref" => "authority-event-1"
      }
    }

    conn =
      conn
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, body, "")
      |> post(path, test_json_body(body))

    assert json_response(conn, 200) == %{"ok" => true}

    audit = Repo.get_by!(AuditEvent, type: "plugin.sandbox.loaded")
    assert audit.class == "security_runtime"
    assert audit.scope["workspace_id"] == workspace.id
    assert audit.resource["id"] == "com.example.runtime"
    assert audit.resource["package_id"] == application.package_id
    assert audit.resource["application_id"] == application.id
    assert audit.resource["activation_id"] == consent.activation_id
    assert audit.resource["owner_scope_kind"] == "workspace"
    assert audit.correlation["package_id"] == application.package_id
    assert audit.correlation["application_id"] == application.id
    assert audit.correlation["activation_id"] == consent.activation_id
    assert audit.correlation["owner_scope_kind"] == "workspace"

    assert audit.correlation["capability_grant_id"] ==
             runtime_capability_grant_id(application, bundle, consent)

    navigation_body =
      body
      |> Map.put("type", "plugin.runtime.navigation_suspected")
      |> Map.put("operation", "plugin.runtime.navigation.detect")
      |> put_in(["action", "operation"], "plugin.runtime.navigation.detect")
      |> put_in(["action", "result"], "completed")
      |> put_in(["action", "reason_code"], "frame_navigation")
      |> put_in(["correlation", "request_id"], "request-navigation")

    navigation_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        path,
        navigation_body,
        ""
      )
      |> post(path, test_json_body(navigation_body))

    assert json_response(navigation_conn, 200) == %{"ok" => true}

    navigation_audit = Repo.get_by!(AuditEvent, type: "plugin.runtime.navigation_suspected")
    assert navigation_audit.action["reason_code"] == "frame_navigation"
    refute Map.has_key?(navigation_audit.action, "url")
    refute Map.has_key?(navigation_audit.action, "target_url")
    refute Map.has_key?(navigation_audit.action, "destination_url")

    bundle_import_body =
      body
      |> Map.put("type", "plugin.bundle.imported")
      |> Map.put("operation", "plugin.bundle.import")
      |> put_in(["action", "operation"], "plugin.bundle.import")

    bundle_import_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        path,
        bundle_import_body,
        ""
      )
      |> post(path, test_json_body(bundle_import_body))

    assert json_response(bundle_import_conn, 200) == %{"ok" => true}

    assert Repo.get_by!(AuditEvent, type: "plugin.bundle.imported").action["operation"] ==
             "plugin.bundle.import"

    document_write_body =
      body
      |> Map.put("type", "plugin.document_write.requested")
      |> Map.put("operation", "documents.applyEncryptedUpdate")
      |> put_in(["resource", "kind"], "document")
      |> put_in(["resource", "id"], "doc-1")
      |> put_in(["resource", "version_hash"], "doc-1")
      |> put_in(["action", "operation"], "documents.applyEncryptedUpdate")
      |> put_in(["sensitivity", "storage_bytes"], 8)
      |> put_in(["correlation", "request_id"], "request-2")

    document_write_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        path,
        document_write_body,
        ""
      )
      |> post(path, test_json_body(document_write_body))

    assert json_response(document_write_conn, 200) == %{"ok" => true}
    assert Repo.get_by!(AuditEvent, type: "plugin.document_write.requested")

    network_body =
      body
      |> Map.put("type", "plugin.network.requested")
      |> Map.put("operation", "app.network.fetch:POST:proxy")
      |> put_in(["resource", "kind"], "network_endpoint")
      |> put_in(["resource", "id"], "github-rest")
      |> put_in(["resource", "version_hash"], "https://api.github.com/issues|route=proxy")
      |> put_in(["action", "operation"], "app.network.fetch:POST:proxy")
      |> put_in(["action", "result"], "allowed")
      |> put_in(["action", "endpoint_id"], "github-rest")
      |> put_in(["action", "route"], "proxy")
      |> put_in(["action", "proxy_id"], "org-proxy")
      |> put_in(["action", "method"], "POST")
      |> put_in(["action", "target_origin"], "https://api.github.com")
      |> put_in(["action", "target_path"], "/repos/refmdio/refmd/issues")
      |> put_in(["action", "request_bytes"], 5)
      |> put_in(["action", "credential_handle_used"], false)
      |> put_in(["sensitivity", "egress_bytes"], 5)
      |> put_in(["correlation", "request_id"], "request-network")

    network_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        path,
        network_body,
        ""
      )
      |> post(path, test_json_body(network_body))

    assert json_response(network_conn, 200) == %{"ok" => true}

    network_audit = Repo.get_by!(AuditEvent, type: "plugin.network.requested")
    assert network_audit.action["endpoint_id"] == "github-rest"
    assert network_audit.action["route"] == "proxy"
    assert network_audit.action["proxy_id"] == "org-proxy"
    assert network_audit.action["target_origin"] == "https://api.github.com"
    assert network_audit.action["target_path"] == "/repos/refmdio/refmd/issues"
    assert network_audit.action["request_bytes"] == 5
    assert network_audit.action["credential_handle_used"] == false
    refute Map.has_key?(network_audit.action, "request_body")

    blocked_network_body =
      network_body
      |> Map.put("type", "plugin.network.blocked")
      |> put_in(["action", "result"], "denied")
      |> put_in(["action", "reason_code"], "proxy_confirmation_required")
      |> put_in(["action", "route"], "proxy")
      |> put_in(["action", "proxy_id"], "org-proxy")
      |> update_in(["action"], &Map.delete(&1, "fallback_reason"))
      |> put_in(["action", "response_bytes"], 0)
      |> put_in(["correlation", "request_id"], "request-network-blocked")

    blocked_network_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        path,
        blocked_network_body,
        ""
      )
      |> post(path, test_json_body(blocked_network_body))

    assert json_response(blocked_network_conn, 200) == %{"ok" => true}

    blocked_network_audit = Repo.get_by!(AuditEvent, type: "plugin.network.blocked")
    assert blocked_network_audit.action["route"] == "proxy"
    assert blocked_network_audit.action["proxy_id"] == "org-proxy"
    assert blocked_network_audit.action["reason_code"] == "proxy_confirmation_required"
    refute Map.has_key?(blocked_network_audit.action, "fallback_reason")

    for {reason_code, route} <- [
          {"network_endpoint_unknown", "proxy"},
          {"network_route_unavailable", "direct"},
          {"plugin_proxy_forbidden", "proxy"}
        ] do
      pre_target_blocked_body =
        network_body
        |> Map.put("type", "plugin.network.blocked")
        |> put_in(["action", "result"], "denied")
        |> put_in(["action", "reason_code"], reason_code)
        |> put_in(["action", "route"], route)
        |> put_in(["action", "response_bytes"], 0)
        |> update_in(["action"], &Map.delete(&1, "target_origin"))
        |> update_in(["action"], &Map.delete(&1, "target_path"))
        |> update_in(["action"], &Map.delete(&1, "proxy_id"))
        |> put_in(["correlation", "request_id"], "request-network-pre-target-#{reason_code}")

      pre_target_blocked_conn =
        Phoenix.ConnTest.build_conn()
        |> authed_conn(user_id, device)
        |> put_test_pop_headers(
          user_id,
          device,
          signing_private_key,
          "POST",
          path,
          pre_target_blocked_body,
          ""
        )
        |> post(path, test_json_body(pre_target_blocked_body))

      assert json_response(pre_target_blocked_conn, 200) == %{"ok" => true}

      assert Enum.find(Repo.all(AuditEvent), fn audit ->
               audit.type == "plugin.network.blocked" and
                 audit.action["reason_code"] == reason_code
             end)
    end

    sensitive_network_body = put_in(network_body, ["action", "request_body"], "secret")

    sensitive_network_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        path,
        sensitive_network_body,
        ""
      )
      |> post(path, test_json_body(sensitive_network_body))

    assert %{"error" => "plugin_runtime_audit_envelope_invalid"} =
             json_response(sensitive_network_conn, 422)

    for {scope_kind, request_id} <- [
          {"inline", "request-inline"},
          {"editor_context", "request-editor"}
        ] do
      plaintext_body =
        body
        |> Map.put("type", "plugin.plaintext_payload.delivered")
        |> Map.put("contextKind", "renderer")
        |> Map.put("payloadKind", "plaintext:render:block:summary")
        |> put_in(["sensitivity", "plaintext_scope_kind"], scope_kind)
        |> put_in(["sensitivity", "plaintext_bytes"], 16)
        |> put_in(["correlation", "request_id"], request_id)

      plaintext_conn =
        Phoenix.ConnTest.build_conn()
        |> authed_conn(user_id, device)
        |> put_test_pop_headers(
          user_id,
          device,
          signing_private_key,
          "POST",
          path,
          plaintext_body,
          ""
        )
        |> post(path, test_json_body(plaintext_body))

      assert json_response(plaintext_conn, 200) == %{"ok" => true}
    end

    plaintext_denied_without_context_body =
      body
      |> Map.put("type", "plugin.plaintext_payload.denied")
      |> Map.put("operation", "documents.getActiveDocument")
      |> Map.put("payloadKind", "plaintext:document:active")
      |> Map.delete("contextKind")
      |> put_in(["action", "operation"], "documents.getActiveDocument")
      |> put_in(["action", "result"], "denied")
      |> put_in(["action", "reason_code"], "execution_context_required")
      |> put_in(["sensitivity", "plaintext_scope_kind"], "active_document")
      |> put_in(["sensitivity", "plaintext_bytes"], 0)
      |> put_in(["correlation", "request_id"], "request-plaintext-denied-no-context")
      |> put_in(["correlation", "execution_context_id"], "")
      |> put_in(["correlation", "authority_event_ref"], "")

    plaintext_denied_without_context_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        path,
        plaintext_denied_without_context_body,
        ""
      )
      |> post(path, test_json_body(plaintext_denied_without_context_body))

    assert json_response(plaintext_denied_without_context_conn, 200) == %{"ok" => true}

    plaintext_denied_audit =
      Repo.all(AuditEvent)
      |> Enum.find(fn audit ->
        audit.type == "plugin.plaintext_payload.denied" and
          audit.action["operation"] == "documents.getActiveDocument"
      end)

    assert plaintext_denied_audit
    assert plaintext_denied_audit.action["reason_code"] == "execution_context_required"
    assert plaintext_denied_audit.correlation["execution_context_id"] == ""
  end

  test "records pre-load plugin capability audit before the sandbox frame is active", %{
    conn: conn
  } do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Preload Audit")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"
    frame_generation = preload_runtime_frame_generation!(application, bundle, consent)

    body = %{
      "type" => "plugin.capability.issued",
      "plugin_id" => "com.example.runtime",
      "package_id" => application.package_id,
      "application_id" => application.id,
      "activation_id" => consent.activation_id,
      "owner_scope_kind" => "workspace",
      "capability_grant_id" => runtime_capability_grant_id(application, bundle, consent),
      "consent_epoch" => consent.consent_epoch,
      "frame_generation" => frame_generation,
      "workspace_id" => workspace.id,
      "bundle_hash" => bundle.bundle_hash,
      "manifest_hash" => bundle.manifest_hash,
      "capability_id" => "capability",
      "operation" => "plugin.capability.issue",
      "resource" => %{
        "kind" => "plugin",
        "id" => "com.example.runtime",
        "version_hash" => bundle.bundle_hash
      },
      "action" => %{"operation" => "plugin.capability.issue", "result" => "completed"},
      "sensitivity" => %{
        "plaintext_scope_kind" => "none",
        "plaintext_bytes" => 0,
        "egress_bytes" => 0,
        "storage_bytes" => 0
      },
      "correlation" => %{
        "request_id" => "",
        "capability_id" => "capability",
        "execution_context_id" => "",
        "authority_event_ref" => ""
      }
    }

    conn =
      conn
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, body, "")
      |> post(path, test_json_body(body))

    assert json_response(conn, 200) == %{"ok" => true}
    assert Repo.get_by!(AuditEvent, type: "plugin.capability.issued")

    plaintext_denied_without_context_body =
      body
      |> Map.put("type", "plugin.plaintext_payload.denied")
      |> Map.put("operation", "documents.getActiveDocument")
      |> Map.put("payloadKind", "plaintext:document:active")
      |> put_in(["action", "operation"], "documents.getActiveDocument")
      |> put_in(["action", "result"], "denied")
      |> put_in(["action", "reason_code"], "execution_context_required")
      |> put_in(["sensitivity", "plaintext_scope_kind"], "active_document")
      |> put_in(["correlation", "request_id"], "request-plaintext-denied-before-loaded")

    plaintext_denied_without_context_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        path,
        plaintext_denied_without_context_body,
        ""
      )
      |> post(path, test_json_body(plaintext_denied_without_context_body))

    assert json_response(plaintext_denied_without_context_conn, 200) == %{"ok" => true}
    assert Repo.get_by!(AuditEvent, type: "plugin.plaintext_payload.denied")
  end

  test "records Host UI registration audit for a current served primary sandbox frame" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Served UI Registration Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.ui.registration.accepted",
        "operation" => "ui.document_tree.register_virtual_section",
        "action" => %{
          "operation" => "ui.document_tree.register_virtual_section",
          "result" => "allowed"
        }
      })

    frame_generation = served_runtime_frame_generation!(application, bundle, consent, :primary)

    body =
      body
      |> Map.put("frame_generation", frame_generation)
      |> Map.put("frame_scope", "primary")

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, body)
             |> json_response(200)

    audit = Repo.get_by!(AuditEvent, type: "plugin.ui.registration.accepted")
    assert audit.action["operation"] == "ui.document_tree.register_virtual_section"
  end

  test "rejects Host UI registration audit for superseded served primary and secondary frames" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Stale Served UI Registration Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.ui.registration.accepted",
        "operation" => "ui.document_tree.register_virtual_section",
        "action" => %{
          "operation" => "ui.document_tree.register_virtual_section",
          "result" => "allowed"
        }
      })

    stale_frame_generation =
      served_runtime_frame_generation!(application, bundle, consent, :primary)

    _newer_frame_generation =
      served_runtime_frame_generation!(application, bundle, consent, :primary)

    stale_body =
      body
      |> Map.put("frame_generation", stale_frame_generation)
      |> Map.put("frame_scope", "primary")

    assert %{"error" => "plugin_runtime_audit_application_invalid"} =
             post_runtime_audit(user_id, device, signing_private_key, path, stale_body)
             |> json_response(403)

    secondary_frame_generation =
      served_runtime_frame_generation!(application, bundle, consent, :secondary)

    secondary_body =
      body
      |> Map.put("frame_generation", secondary_frame_generation)
      |> Map.put("frame_scope", "secondary")

    assert %{"error" => "plugin_runtime_audit_application_invalid"} =
             post_runtime_audit(user_id, device, signing_private_key, path, secondary_body)
             |> json_response(403)
  end

  test "rejects plaintext runtime audit events without required metadata", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Plaintext Audit Reject")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"
    frame_generation = current_runtime_frame_generation!(application, bundle, consent)

    body = %{
      "type" => "plugin.plaintext_payload.delivered",
      "plugin_id" => "com.example.runtime",
      "package_id" => application.package_id,
      "application_id" => application.id,
      "activation_id" => consent.activation_id,
      "owner_scope_kind" => "workspace",
      "capability_grant_id" => runtime_capability_grant_id(application, bundle, consent),
      "consent_epoch" => consent.consent_epoch,
      "frame_generation" => frame_generation,
      "workspace_id" => workspace.id,
      "bundle_hash" => bundle.bundle_hash,
      "manifest_hash" => bundle.manifest_hash,
      "capability_id" => "capability",
      "operation" => "plugin.plaintext_payload.delivered",
      "contextKind" => "renderer",
      "payloadKind" => "plaintext:render:block:summary",
      "resource" => %{
        "kind" => "plugin",
        "id" => "com.example.runtime",
        "version_hash" => bundle.bundle_hash
      },
      "action" => %{"operation" => "plugin.plaintext_payload.delivered", "result" => "allowed"},
      "sensitivity" => %{
        "plaintext_scope_kind" => "block",
        "plaintext_bytes" => 16,
        "egress_bytes" => 0,
        "storage_bytes" => 0
      },
      "correlation" => %{
        "request_id" => "request-plaintext",
        "capability_id" => "capability",
        "execution_context_id" => "execution-context-1",
        "authority_event_ref" => "authority-event-1"
      }
    }

    assert_rejects_runtime_audit(
      conn,
      user_id,
      device,
      signing_private_key,
      path,
      Map.delete(body, "sensitivity")
    )

    assert_rejects_runtime_audit(
      conn,
      user_id,
      device,
      signing_private_key,
      path,
      Map.delete(body, "correlation")
    )

    for rejected_body <- [
          put_in(body, ["correlation", "execution_context_id"], ""),
          put_in(body, ["sensitivity", "plaintext_scope_kind"], "none"),
          put_in(body, ["action", "content"], "selected document body"),
          Map.delete(body, "payloadKind"),
          Map.delete(body, "contextKind")
        ] do
      assert_rejects_runtime_audit(
        conn,
        user_id,
        device,
        signing_private_key,
        path,
        rejected_body
      )
    end
  end

  test "rejects network runtime audit events without required metadata", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Network Audit Reject")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"
    frame_generation = current_runtime_frame_generation!(application, bundle, consent)

    body = %{
      "type" => "plugin.network.requested",
      "plugin_id" => "com.example.runtime",
      "package_id" => application.package_id,
      "application_id" => application.id,
      "activation_id" => consent.activation_id,
      "owner_scope_kind" => "workspace",
      "capability_grant_id" => runtime_capability_grant_id(application, bundle, consent),
      "consent_epoch" => consent.consent_epoch,
      "frame_generation" => frame_generation,
      "workspace_id" => workspace.id,
      "bundle_hash" => bundle.bundle_hash,
      "manifest_hash" => bundle.manifest_hash,
      "capability_id" => "capability",
      "operation" => "app.network.fetch:POST:proxy",
      "resource" => %{
        "kind" => "network_endpoint",
        "id" => "github-rest",
        "version_hash" => "https://api.github.com/issues|route=proxy"
      },
      "action" => %{
        "operation" => "app.network.fetch:POST:proxy",
        "result" => "allowed",
        "endpoint_id" => "github-rest",
        "route" => "proxy",
        "proxy_id" => "org-proxy",
        "method" => "POST",
        "target_origin" => "https://api.github.com",
        "target_path" => "/repos/refmdio/refmd/issues",
        "request_bytes" => 5,
        "credential_handle_used" => false
      },
      "sensitivity" => %{
        "plaintext_scope_kind" => "none",
        "plaintext_bytes" => 0,
        "egress_bytes" => 5,
        "storage_bytes" => 0
      },
      "correlation" => %{
        "request_id" => "request-network",
        "capability_id" => "capability",
        "execution_context_id" => "execution-context-1",
        "authority_event_ref" => "authority-event-1"
      }
    }

    for rejected_body <- [
          update_in(body, ["action"], &Map.delete(&1, "endpoint_id")),
          update_in(body, ["action"], &Map.delete(&1, "target_origin")),
          update_in(body, ["action"], &Map.delete(&1, "target_path")),
          update_in(body, ["action"], &Map.delete(&1, "request_bytes")),
          update_in(body, ["action"], &Map.delete(&1, "credential_handle_used")),
          put_in(body, ["action", "method"], ""),
          put_in(body, ["action", "target_origin"], "https://api.github.com/path"),
          put_in(body, ["action", "target_path"], "repos/refmdio/refmd/issues"),
          put_in(body, ["action", "request_bytes"], "5"),
          put_in(body, ["action", "credential_handle_used"], "false"),
          put_in(body, ["action", "raw"], "secret response body"),
          body
          |> put_in(["action", "result"], "completed")
          |> update_in(["action"], &Map.delete(&1, "response_bytes")),
          body
          |> put_in(["action", "route"], "proxy")
          |> update_in(["action"], &Map.delete(&1, "proxy_id"))
        ] do
      assert_rejects_runtime_audit(
        conn,
        user_id,
        device,
        signing_private_key,
        path,
        rejected_body
      )
    end

    blocked_body =
      body
      |> Map.put("type", "plugin.network.blocked")
      |> put_in(["action", "result"], "denied")
      |> put_in(["action", "reason_code"], "proxy_confirmation_required")
      |> put_in(["action", "route"], "proxy")
      |> put_in(["action", "proxy_id"], "org-proxy")
      |> update_in(["action"], &Map.delete(&1, "fallback_reason"))
      |> put_in(["action", "response_bytes"], 0)
      |> put_in(["correlation", "request_id"], "request-network-blocked")

    for rejected_body <- [
          update_in(blocked_body, ["action"], &Map.delete(&1, "response_bytes")),
          put_in(blocked_body, ["action", "fallback_reason"], "")
        ] do
      assert_rejects_runtime_audit(
        conn,
        user_id,
        device,
        signing_private_key,
        path,
        rejected_body
      )
    end
  end

  test "rejects arbitrary action metadata on generic runtime audit events", %{conn: conn} do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Generic Audit Metadata Reject")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.sandbox.loaded",
        "operation" => "plugin.sandbox.load",
        "action" => %{
          "operation" => "plugin.sandbox.load",
          "result" => "completed",
          "payload" => "document body"
        }
      })

    assert_rejects_runtime_audit(conn, user_id, device, signing_private_key, path, body)
  end

  test "rejects runtime audit events for nonexistent or stale plugin runtime state" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Runtime Audit Reject")
    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"
    frame_generation = current_runtime_frame_generation!(application, bundle, consent)

    base_body = %{
      "type" => "plugin.sandbox.loaded",
      "plugin_id" => "com.example.runtime",
      "package_id" => application.package_id,
      "application_id" => application.id,
      "activation_id" => consent.activation_id,
      "owner_scope_kind" => "workspace",
      "capability_grant_id" => runtime_capability_grant_id(application, bundle, consent),
      "consent_epoch" => consent.consent_epoch,
      "frame_generation" => frame_generation,
      "workspace_id" => workspace.id,
      "bundle_hash" => bundle.bundle_hash,
      "manifest_hash" => bundle.manifest_hash,
      "capability_id" => "capability",
      "operation" => "plugin.sandbox.load",
      "resource" => %{
        "kind" => "plugin",
        "id" => "com.example.runtime",
        "version_hash" => bundle.bundle_hash
      },
      "action" => %{"operation" => "plugin.sandbox.load", "result" => "completed"},
      "sensitivity" => %{
        "plaintext_scope_kind" => "none",
        "plaintext_bytes" => 0,
        "egress_bytes" => 0,
        "storage_bytes" => 0
      },
      "correlation" => %{
        "request_id" => "request-1",
        "capability_id" => "capability",
        "execution_context_id" => "execution-context-1",
        "authority_event_ref" => "authority-event-1"
      }
    }

    for rejected_body <- [
          %{base_body | "application_id" => Ecto.UUID.generate()},
          %{base_body | "plugin_id" => "com.example.other"},
          %{base_body | "package_id" => Ecto.UUID.generate()},
          %{base_body | "owner_scope_kind" => "user"},
          %{base_body | "bundle_hash" => hash("stale-bundle")},
          %{base_body | "manifest_hash" => hash("stale-manifest")},
          %{base_body | "activation_id" => Ecto.UUID.generate()},
          %{base_body | "capability_grant_id" => Ecto.UUID.generate()},
          %{base_body | "consent_epoch" => consent.consent_epoch + 1}
        ] do
      rejected_conn =
        Phoenix.ConnTest.build_conn()
        |> authed_conn(user_id, device)
        |> put_test_pop_headers(
          user_id,
          device,
          signing_private_key,
          "POST",
          path,
          rejected_body,
          ""
        )
        |> post(path, test_json_body(rejected_body))

      assert json_response(rejected_conn, 403) == %{
               "error" => "plugin_runtime_audit_application_invalid"
             }
    end

    unsupported_body = %{base_body | "type" => "plugin.runtime.forged"}

    unsupported_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        path,
        unsupported_body,
        ""
      )
      |> post(path, test_json_body(unsupported_body))

    assert json_response(unsupported_conn, 422) == %{
             "error" => "plugin_runtime_audit_type_invalid"
           }

    for rejected_body <- [
          put_in(base_body, ["sensitivity", "debug"], "selected document body"),
          put_in(base_body, ["sensitivity", "plaintext_bytes"], "5"),
          put_in(base_body, ["sensitivity", "plaintext_scope_kind"], "everything"),
          put_in(base_body, ["correlation", "request_body"], "secret request body"),
          put_in(base_body, ["correlation", "request_id"], %{"nested" => "value"})
        ] do
      rejected_conn =
        Phoenix.ConnTest.build_conn()
        |> authed_conn(user_id, device)
        |> put_test_pop_headers(
          user_id,
          device,
          signing_private_key,
          "POST",
          path,
          rejected_body,
          ""
        )
        |> post(path, test_json_body(rejected_body))

      assert json_response(rejected_conn, 422) == %{
               "error" => "plugin_runtime_audit_envelope_invalid"
             }
    end

    _newer_frame_generation = current_runtime_frame_generation!(application, bundle, consent)

    stale_frame_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(
        user_id,
        device,
        signing_private_key,
        "POST",
        path,
        base_body,
        ""
      )
      |> post(path, test_json_body(base_body))

    assert json_response(stale_frame_conn, 403) == %{
             "error" => "plugin_runtime_audit_application_invalid"
           }
  end

  test "accepts terminal lifecycle audits after application disable" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Disabled Terminal Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{updated: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    {:ok, _disabled} = Plugins.update_application(application, %{enabled: false})

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    destroyed_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.sandbox.destroyed",
        "operation" => "plugin.sandbox.destroy",
        "action" => %{
          "operation" => "plugin.sandbox.destroy",
          "result" => "completed",
          "reason_code" => "application_disabled"
        }
      })

    destroyed_conn =
      post_runtime_audit(
        user_id,
        device,
        signing_private_key,
        path,
        destroyed_body
      )

    assert json_response(destroyed_conn, 200) == %{"ok" => true}

    assert Repo.get_by!(AuditEvent, type: "plugin.sandbox.destroyed").resource["version_hash"] ==
             bundle.bundle_hash

    loaded_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.sandbox.loaded",
        "operation" => "plugin.sandbox.load",
        "action" => %{"operation" => "plugin.sandbox.load", "result" => "completed"}
      })

    loaded_conn =
      post_runtime_audit(
        user_id,
        device,
        signing_private_key,
        path,
        loaded_body
      )

    assert json_response(loaded_conn, 403) == %{
             "error" => "plugin_runtime_audit_application_invalid"
           }
  end

  test "accepts UI cleanup audits after application disable" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Disabled Cleanup Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{updated: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    cleanup_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.ui.registry_entry_disposed",
        "operation" => "ui.cleanup",
        "action" => %{
          "operation" => "ui.cleanup",
          "result" => "denied",
          "reason_code" => "application_disabled"
        }
      })

    {:ok, _disabled} = Plugins.update_application(application, %{enabled: false})

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    cleanup_conn =
      post_runtime_audit(
        user_id,
        device,
        signing_private_key,
        path,
        cleanup_body
      )

    assert json_response(cleanup_conn, 200) == %{"ok" => true}
  end

  test "accepts terminal and cleanup audits after activation deletion" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Deleted Activation Cleanup Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    destroyed_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.sandbox.destroyed",
        "operation" => "plugin.sandbox.destroy",
        "action" => %{
          "operation" => "plugin.sandbox.destroy",
          "result" => "completed",
          "reason_code" => "plugin_runtime_activation_deleted"
        }
      })

    revoked_body =
      destroyed_body
      |> terminal_revoked_body("activation-delete-revoked")
      |> put_in(["action", "reason_code"], "plugin_runtime_activation_deleted")

    cleanup_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.ui.registry_entry_disposed",
        "operation" => "ui.cleanup",
        "action" => %{
          "operation" => "ui.cleanup",
          "result" => "denied",
          "reason_code" => "owner_cleanup"
        },
        "correlation" => %{
          "request_id" => "activation-delete-cleanup",
          "capability_id" => "capability",
          "execution_context_id" => "execution-context-1",
          "authority_event_ref" => "authority-event-1"
        }
      })

    {:ok, _deleted} =
      Plugins.delete_activation(Repo.get!(PluginActivation, consent.activation_id),
        actor_device_id: device.id
      )

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, destroyed_body)
             |> json_response(200)

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, revoked_body)
             |> json_response(200)

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, cleanup_body)
             |> json_response(200)

    loaded_body =
      destroyed_body
      |> Map.put("type", "plugin.sandbox.loaded")
      |> Map.put("operation", "plugin.sandbox.load")
      |> Map.put("action", %{"operation" => "plugin.sandbox.load", "result" => "completed"})
      |> put_in(["correlation", "request_id"], "activation-delete-loaded")

    assert %{"error" => "plugin_runtime_audit_application_invalid"} =
             post_runtime_audit(user_id, device, signing_private_key, path, loaded_body)
             |> json_response(403)
  end

  test "accepts terminal and cleanup audits after application deletion" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Deleted Application Cleanup Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    destroyed_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.sandbox.destroyed",
        "operation" => "plugin.sandbox.destroy",
        "action" => %{
          "operation" => "plugin.sandbox.destroy",
          "result" => "completed",
          "reason_code" => "plugin_runtime_uninstalled"
        }
      })

    revoked_body =
      destroyed_body
      |> terminal_revoked_body("application-delete-revoked")
      |> put_in(["action", "reason_code"], "plugin_runtime_uninstalled")

    cleanup_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.ui.registry_entry_disposed",
        "operation" => "ui.cleanup",
        "action" => %{
          "operation" => "ui.cleanup",
          "result" => "denied",
          "reason_code" => "owner_cleanup"
        },
        "correlation" => %{
          "request_id" => "application-delete-cleanup",
          "capability_id" => "capability",
          "execution_context_id" => "execution-context-1",
          "authority_event_ref" => "authority-event-1"
        }
      })

    {:ok, _deleted} = Plugins.delete_application(application)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, destroyed_body)
             |> json_response(200)

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, revoked_body)
             |> json_response(200)

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, cleanup_body)
             |> json_response(200)

    loaded_body =
      destroyed_body
      |> Map.put("type", "plugin.sandbox.loaded")
      |> Map.put("operation", "plugin.sandbox.load")
      |> Map.put("action", %{"operation" => "plugin.sandbox.load", "result" => "completed"})
      |> put_in(["correlation", "request_id"], "application-delete-loaded")

    assert %{"error" => "plugin_runtime_audit_application_invalid"} =
             post_runtime_audit(user_id, device, signing_private_key, path, loaded_body)
             |> json_response(403)
  end

  test "accepts cleanup audits after consent revoke" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Revoked Consent Cleanup Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    cleanup_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.ui.registry_entry_disposed",
        "operation" => "ui.cleanup",
        "action" => %{
          "operation" => "ui.cleanup",
          "result" => "denied",
          "reason_code" => "owner_cleanup"
        },
        "correlation" => %{
          "request_id" => "consent-revoke-cleanup",
          "capability_id" => "capability",
          "execution_context_id" => "execution-context-1",
          "authority_event_ref" => "authority-event-1"
        }
      })

    {:ok, _revoke} =
      Plugins.append_consent_event(
        consent_attrs(%{
          application_id: application.id,
          workspace_id: workspace.id,
          plugin_id: application.plugin_id,
          version: bundle.version,
          bundle_hash: bundle.bundle_hash,
          manifest_hash: bundle.manifest_hash,
          permissions_hash: bundle.permissions_hash,
          endpoint_hash: bundle.endpoint_hash,
          document_scope_hash: bundle.document_scope_hash,
          user_id: user_id,
          device_id: device.id,
          signer_user_id: user_id,
          signer_device_id: device.id,
          consent_epoch: consent.consent_epoch + 1,
          previous_event_hash: consent.event_hash,
          decision: "revoke"
        })
      )

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, cleanup_body)
             |> json_response(200)

    loaded_body =
      cleanup_body
      |> Map.put("type", "plugin.sandbox.loaded")
      |> Map.put("operation", "plugin.sandbox.load")
      |> Map.put("action", %{"operation" => "plugin.sandbox.load", "result" => "completed"})
      |> put_in(["correlation", "request_id"], "consent-revoke-loaded")

    assert %{"error" => "plugin_runtime_audit_application_invalid"} =
             post_runtime_audit(user_id, device, signing_private_key, path, loaded_body)
             |> json_response(403)
  end

  test "accepts UI cleanup audits for a replaced primary runtime frame" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Replaced Cleanup Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{updated: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    cleanup_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.ui.iframe.lifecycle",
        "operation" => "ui.cleanup",
        "action" => %{
          "operation" => "ui.cleanup",
          "result" => "denied",
          "reason_code" => "frame_replaced"
        }
      })

    _new_frame_generation = current_runtime_frame_generation!(application, bundle, consent)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    cleanup_conn =
      post_runtime_audit(
        user_id,
        device,
        signing_private_key,
        path,
        cleanup_body
      )

    assert json_response(cleanup_conn, 200) == %{"ok" => true}

    stale_loaded_body =
      cleanup_body
      |> Map.put("type", "plugin.sandbox.loaded")
      |> Map.put("operation", "plugin.sandbox.load")
      |> Map.put("action", %{"operation" => "plugin.sandbox.load", "result" => "completed"})

    stale_loaded_conn =
      post_runtime_audit(
        user_id,
        device,
        signing_private_key,
        path,
        stale_loaded_body
      )

    assert json_response(stale_loaded_conn, 403) == %{
             "error" => "plugin_runtime_audit_application_invalid"
           }
  end

  test "accepts terminal lifecycle audits for a replaced primary runtime frame" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Replaced Primary Terminal Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    destroyed_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.sandbox.destroyed",
        "operation" => "plugin.sandbox.destroy",
        "action" => %{
          "operation" => "plugin.sandbox.destroy",
          "result" => "completed",
          "reason_code" => "runtime_replaced"
        }
      })

    _new_frame_generation = current_runtime_frame_generation!(application, bundle, consent)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, destroyed_body)
             |> json_response(200)

    revoked_body =
      destroyed_body
      |> terminal_revoked_body("replaced-primary-revoke")
      |> put_in(["action", "reason_code"], "runtime_replaced")

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, revoked_body)
             |> json_response(200)

    stale_loaded_body =
      destroyed_body
      |> Map.put("type", "plugin.sandbox.loaded")
      |> Map.put("operation", "plugin.sandbox.load")
      |> Map.put("action", %{"operation" => "plugin.sandbox.load", "result" => "completed"})

    assert %{"error" => "plugin_runtime_audit_application_invalid"} =
             post_runtime_audit(user_id, device, signing_private_key, path, stale_loaded_body)
             |> json_response(403)
  end

  test "accepts terminal lifecycle audit pairs in either order" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Terminal Audit Ordering")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    destroyed_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.sandbox.destroyed",
        "operation" => "plugin.sandbox.destroy",
        "action" => %{
          "operation" => "plugin.sandbox.destroy",
          "result" => "completed",
          "reason_code" => "runtime_destroyed"
        }
      })

    revoked_body =
      terminal_revoked_body(destroyed_body, "request-terminal-revoked")

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, destroyed_body)
             |> json_response(200)

    duplicate_destroyed_body =
      put_in(
        destroyed_body,
        ["correlation", "request_id"],
        "request-terminal-destroyed-duplicate"
      )

    assert %{"ok" => true} =
             post_runtime_audit(
               user_id,
               device,
               signing_private_key,
               path,
               duplicate_destroyed_body
             )
             |> json_response(200)

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, revoked_body)
             |> json_response(200)

    duplicate_revoked_body =
      put_in(revoked_body, ["correlation", "request_id"], "request-terminal-revoked-duplicate")

    assert %{"ok" => true} =
             post_runtime_audit(
               user_id,
               device,
               signing_private_key,
               path,
               duplicate_revoked_body
             )
             |> json_response(200)

    loaded_after_terminal =
      destroyed_body
      |> Map.put("type", "plugin.sandbox.loaded")
      |> Map.put("operation", "plugin.sandbox.load")
      |> Map.put("action", %{"operation" => "plugin.sandbox.load", "result" => "completed"})
      |> put_in(["correlation", "request_id"], "request-terminal-loaded")

    assert %{"error" => "plugin_runtime_audit_application_invalid"} =
             post_runtime_audit(user_id, device, signing_private_key, path, loaded_after_terminal)
             |> json_response(403)

    revoked_first_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.capability.revoked",
        "operation" => "plugin.capability.revoke",
        "action" => %{
          "operation" => "plugin.capability.revoke",
          "result" => "completed",
          "reason_code" => "runtime_destroyed"
        }
      })

    destroyed_second_body =
      revoked_first_body
      |> Map.put("type", "plugin.sandbox.destroyed")
      |> Map.put("operation", "plugin.sandbox.destroy")
      |> Map.put("action", %{
        "operation" => "plugin.sandbox.destroy",
        "result" => "completed",
        "reason_code" => "runtime_destroyed"
      })
      |> put_in(["correlation", "request_id"], "request-terminal-destroyed-second")

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, revoked_first_body)
             |> json_response(200)

    duplicate_revoked_first_body =
      put_in(
        revoked_first_body,
        ["correlation", "request_id"],
        "request-terminal-revoked-first-duplicate"
      )

    assert %{"ok" => true} =
             post_runtime_audit(
               user_id,
               device,
               signing_private_key,
               path,
               duplicate_revoked_first_body
             )
             |> json_response(200)

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, destroyed_second_body)
             |> json_response(200)

    duplicate_destroyed_second_body =
      put_in(
        destroyed_second_body,
        ["correlation", "request_id"],
        "request-terminal-destroyed-second-duplicate"
      )

    assert %{"ok" => true} =
             post_runtime_audit(
               user_id,
               device,
               signing_private_key,
               path,
               duplicate_destroyed_second_body
             )
             |> json_response(200)
  end

  test "accepts terminal lifecycle audits for served secondary frames before runtime load" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Secondary Served Terminal Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    frame_generation =
      served_runtime_frame_generation!(application, bundle, consent, :secondary)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    destroyed_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.sandbox.destroyed",
        "operation" => "plugin.sandbox.destroy",
        "frame_generation" => frame_generation,
        "frame_scope" => "secondary",
        "action" => %{
          "operation" => "plugin.sandbox.destroy",
          "result" => "completed",
          "reason_code" => "iframe_unmounted"
        }
      })

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, destroyed_body)
             |> json_response(200)

    revoked_body =
      destroyed_body
      |> terminal_revoked_body("secondary-served-revoke")
      |> Map.put("frame_generation", frame_generation)
      |> Map.put("frame_scope", "secondary")

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, revoked_body)
             |> json_response(200)
  end

  test "accepts terminal lifecycle audits for pending secondary frames before document load" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Secondary Pending Terminal Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    frame_generation =
      pending_runtime_frame_generation!(application, bundle, consent, :secondary)

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    destroyed_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.sandbox.destroyed",
        "operation" => "plugin.sandbox.destroy",
        "frame_generation" => frame_generation,
        "frame_scope" => "secondary",
        "action" => %{
          "operation" => "plugin.sandbox.destroy",
          "result" => "completed",
          "reason_code" => "plugin_ui_iframe_removed"
        }
      })

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, destroyed_body)
             |> json_response(200)

    revoked_body =
      destroyed_body
      |> terminal_revoked_body("secondary-pending-revoke")
      |> Map.put("frame_generation", frame_generation)
      |> Map.put("frame_scope", "secondary")
      |> put_in(["action", "reason_code"], "plugin_ui_iframe_removed")

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, revoked_body)
             |> json_response(200)

    loaded_after_terminal =
      destroyed_body
      |> Map.put("type", "plugin.sandbox.loaded")
      |> Map.put("operation", "plugin.sandbox.load")
      |> Map.put("action", %{"operation" => "plugin.sandbox.load", "result" => "completed"})

    assert %{"error" => "plugin_runtime_audit_application_invalid"} =
             post_runtime_audit(user_id, device, signing_private_key, path, loaded_after_terminal)
             |> json_response(403)
  end

  test "accepts terminal lifecycle audits for user-owned pending secondary frames" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account
    device = TestCrypto.ensure_test_user_pop_key_directory!(user_id, device)

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "User Plugin Secondary Pending Terminal Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{application: application, bundle: bundle, consent: consent} =
      create_user_runtime_application(workspace.id, user_id, device)

    frame_generation =
      pending_runtime_frame_generation!(application, bundle, consent, :secondary)

    owner_key = {
      application.workspace_id,
      application.package_id,
      application.id,
      consent.activation_id,
      "user",
      user_id,
      device.id,
      application.state_head_hash,
      consent.event_hash,
      consent.consent_epoch,
      runtime_capability_grant_id(application, bundle, consent)
    }

    assert [
             {{:sandbox_frame, {^owner_key, ^frame_generation}},
              %{scope: :secondary, state: :pending}}
           ] =
             :ets.lookup(
               RefMD.Plugins.SandboxDocuments,
               {:sandbox_frame, {owner_key, frame_generation}}
             )

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    destroyed_body =
      runtime_audit_body(workspace.id, application, bundle, consent, %{
        "type" => "plugin.sandbox.destroyed",
        "owner_scope_kind" => "user",
        "operation" => "plugin.sandbox.destroy",
        "frame_generation" => frame_generation,
        "frame_scope" => "secondary",
        "state_head_hash" => application.state_head_hash,
        "consent_head_hash" => consent.event_hash,
        "action" => %{
          "operation" => "plugin.sandbox.destroy",
          "result" => "completed",
          "reason_code" => "plugin_ui_iframe_removed"
        }
      })

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, destroyed_body)
             |> json_response(200)

    revoked_body =
      destroyed_body
      |> terminal_revoked_body("user-secondary-pending-revoke")
      |> Map.put("frame_generation", frame_generation)
      |> Map.put("frame_scope", "secondary")
      |> put_in(["action", "reason_code"], "plugin_ui_iframe_removed")

    assert %{"ok" => true} =
             post_runtime_audit(user_id, device, signing_private_key, path, revoked_body)
             |> json_response(200)
  end

  test "accepts terminal lifecycle audits for replaced historical bundles" do
    account = create_runtime_account()
    %{user_id: user_id, device: device, signing_private_key: signing_private_key} = account

    {:ok, workspace} =
      Workspaces.create_default_workspace(user_id, "Plugin Replaced Terminal Audit")

    insert_runtime_workspace_key_directory!(workspace.id, user_id, account)

    %{updated: application, bundle: old_bundle, consent: consent} =
      create_runtime_application(workspace.id, user_id, device)

    {:ok, _updated, _new_bundle} =
      promote_runtime_bundle(
        application,
        workspace.id,
        user_id,
        device,
        "1.0.1",
        2,
        application.state_head_hash
      )

    path = "/api/workspaces/#{workspace.id}/plugin-runtime-audit"

    revoked_body =
      runtime_audit_body(workspace.id, application, old_bundle, consent, %{
        "type" => "plugin.capability.revoked",
        "operation" => "plugin.capability.revoke",
        "action" => %{
          "operation" => "plugin.capability.revoke",
          "result" => "completed",
          "reason_code" => "application_changed"
        }
      })

    revoked_conn =
      post_runtime_audit(
        user_id,
        device,
        signing_private_key,
        path,
        revoked_body
      )

    assert json_response(revoked_conn, 200) == %{"ok" => true}

    assert Repo.get_by!(AuditEvent, type: "plugin.capability.revoked").resource["version_hash"] ==
             old_bundle.bundle_hash

    stale_loaded_body =
      runtime_audit_body(workspace.id, application, old_bundle, consent, %{
        "type" => "plugin.sandbox.loaded",
        "operation" => "plugin.sandbox.load",
        "action" => %{"operation" => "plugin.sandbox.load", "result" => "completed"}
      })

    stale_loaded_conn =
      post_runtime_audit(
        user_id,
        device,
        signing_private_key,
        path,
        stale_loaded_body
      )

    assert json_response(stale_loaded_conn, 403) == %{
             "error" => "plugin_runtime_audit_application_invalid"
           }

    forged_terminal_body =
      %{
        revoked_body
        | "bundle_hash" => hash("forged-bundle"),
          "manifest_hash" => hash("forged-manifest")
      }

    forged_terminal_conn =
      post_runtime_audit(
        user_id,
        device,
        signing_private_key,
        path,
        forged_terminal_body
      )

    assert json_response(forged_terminal_conn, 403) == %{
             "error" => "plugin_runtime_audit_application_invalid"
           }
  end

  defp assert_rejects_runtime_audit(
         conn,
         user_id,
         device,
         signing_private_key,
         path,
         body
       ) do
    rejected_conn =
      conn
      |> recycle()
      |> authed_conn(user_id, device)
      |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, body, "")
      |> post(path, test_json_body(body))

    assert json_response(rejected_conn, 422) == %{
             "error" => "plugin_runtime_audit_envelope_invalid"
           }
  end

  defp post_runtime_audit(user_id, device, signing_private_key, path, body) do
    Phoenix.ConnTest.build_conn()
    |> authed_conn(user_id, device)
    |> put_test_pop_headers(user_id, device, signing_private_key, "POST", path, body, "")
    |> post(path, test_json_body(body))
  end

  defp runtime_audit_body(workspace_id, application, bundle, consent, overrides) do
    type = Map.fetch!(overrides, "type")
    operation = Map.fetch!(overrides, "operation")
    action = Map.fetch!(overrides, "action")
    frame_generation = current_runtime_frame_generation!(application, bundle, consent)

    base = %{
      "type" => type,
      "plugin_id" => "com.example.runtime",
      "package_id" => application.package_id,
      "application_id" => application.id,
      "activation_id" => consent.activation_id,
      "owner_scope_kind" => "workspace",
      "capability_grant_id" => runtime_capability_grant_id(application, bundle, consent),
      "consent_epoch" => consent.consent_epoch,
      "frame_generation" => frame_generation,
      "workspace_id" => workspace_id,
      "bundle_hash" => bundle.bundle_hash,
      "manifest_hash" => bundle.manifest_hash,
      "capability_id" => "capability",
      "operation" => operation,
      "resource" => %{
        "kind" => "plugin",
        "id" => "com.example.runtime",
        "version_hash" => bundle.bundle_hash
      },
      "action" => action,
      "sensitivity" => %{
        "plaintext_scope_kind" => "none",
        "plaintext_bytes" => 0,
        "egress_bytes" => 0,
        "storage_bytes" => 0
      },
      "correlation" => %{
        "request_id" => "request-1",
        "capability_id" => "capability",
        "execution_context_id" => "execution-context-1",
        "authority_event_ref" => "authority-event-1"
      }
    }

    Map.merge(base, Map.drop(overrides, ["type", "operation", "action"]))
  end

  defp terminal_revoked_body(body, request_id) do
    body
    |> Map.put("type", "plugin.capability.revoked")
    |> Map.put("operation", "plugin.capability.revoke")
    |> Map.put("action", %{
      "operation" => "plugin.capability.revoke",
      "result" => "completed",
      "reason_code" => "runtime_destroyed"
    })
    |> put_in(["correlation", "request_id"], request_id)
  end

  defp runtime_capability_grant_id(application, bundle, consent) do
    activation = Repo.get!(PluginActivation, consent.activation_id)

    RuntimeDescriptors.capability_grant_id(
      application,
      bundle,
      activation,
      consent,
      consent.user_id,
      consent.device_id
    )
  end

  defp current_runtime_frame_generation!(application, bundle, consent) do
    activation = Repo.get!(PluginActivation, consent.activation_id)

    session =
      Plugins.create_sandbox_document_session(%{
        workspace_id: application.workspace_id,
        package_id: application.package_id,
        application_id: application.id,
        activation_id: activation.id,
        owner_scope_kind: runtime_owner_scope_kind(application),
        user_id: consent.user_id,
        device_id: consent.device_id,
        auth_session_id: "test-auth-session",
        bundle_id: bundle.id,
        bundle_hash: bundle.bundle_hash,
        manifest_hash: bundle.manifest_hash,
        resource_manifest_hash: bundle.resource_manifest_hash,
        state_head_hash: application.state_head_hash,
        consent_head_hash: consent.event_hash,
        consent_epoch: consent.consent_epoch,
        capability_grant_id: runtime_capability_grant_id(application, bundle, consent)
      })

    :ok = Plugins.mark_sandbox_document_served(session)
    true = Plugins.activate_sandbox_document_frame?(session)
    session.frame_generation
  end

  defp preload_runtime_frame_generation!(application, bundle, consent) do
    activation = Repo.get!(PluginActivation, consent.activation_id)

    session =
      Plugins.create_sandbox_document_session(%{
        workspace_id: application.workspace_id,
        package_id: application.package_id,
        application_id: application.id,
        activation_id: activation.id,
        owner_scope_kind: runtime_owner_scope_kind(application),
        user_id: consent.user_id,
        device_id: consent.device_id,
        auth_session_id: "test-auth-session",
        bundle_id: bundle.id,
        bundle_hash: bundle.bundle_hash,
        manifest_hash: bundle.manifest_hash,
        resource_manifest_hash: bundle.resource_manifest_hash,
        state_head_hash: application.state_head_hash,
        consent_head_hash: consent.event_hash,
        consent_epoch: consent.consent_epoch,
        capability_grant_id: runtime_capability_grant_id(application, bundle, consent)
      })

    session.frame_generation
  end

  defp served_runtime_frame_generation!(application, bundle, consent, frame_scope) do
    activation = Repo.get!(PluginActivation, consent.activation_id)

    session =
      Plugins.create_sandbox_document_session(%{
        workspace_id: application.workspace_id,
        package_id: application.package_id,
        application_id: application.id,
        activation_id: activation.id,
        owner_scope_kind: runtime_owner_scope_kind(application),
        user_id: consent.user_id,
        device_id: consent.device_id,
        auth_session_id: "test-auth-session",
        bundle_id: bundle.id,
        bundle_hash: bundle.bundle_hash,
        manifest_hash: bundle.manifest_hash,
        resource_manifest_hash: bundle.resource_manifest_hash,
        state_head_hash: application.state_head_hash,
        consent_head_hash: consent.event_hash,
        consent_epoch: consent.consent_epoch,
        capability_grant_id: runtime_capability_grant_id(application, bundle, consent),
        sandbox_document_frame_scope: frame_scope
      })

    :ok = Plugins.mark_sandbox_document_served(session)
    session.frame_generation
  end

  defp pending_runtime_frame_generation!(application, bundle, consent, frame_scope) do
    activation = Repo.get!(PluginActivation, consent.activation_id)

    session =
      Plugins.create_sandbox_document_session(%{
        workspace_id: application.workspace_id,
        package_id: application.package_id,
        application_id: application.id,
        activation_id: activation.id,
        owner_scope_kind: runtime_owner_scope_kind(application),
        user_id: consent.user_id,
        device_id: consent.device_id,
        auth_session_id: "test-auth-session",
        bundle_id: bundle.id,
        bundle_hash: bundle.bundle_hash,
        manifest_hash: bundle.manifest_hash,
        resource_manifest_hash: bundle.resource_manifest_hash,
        state_head_hash: application.state_head_hash,
        consent_head_hash: consent.event_hash,
        consent_epoch: consent.consent_epoch,
        capability_grant_id: runtime_capability_grant_id(application, bundle, consent),
        sandbox_document_frame_scope: frame_scope
      })

    session.frame_generation
  end

  defp runtime_owner_scope_kind(application) do
    application = Repo.preload(application, :package)
    application.package.owner_scope_kind
  end

  defp create_runtime_account do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: "plugin-runtime-controller-#{user_id}@example.com",
      name: "Plugin Runtime Controller"
    })

    device_id = Ecto.UUID.generate()
    material = TestCrypto.hybrid_device_material(device_id)
    Process.put({:plugin_runtime_controller_material, device_id}, material)
    {ecdh_public_key, _ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, ecdh_public_key)
    identity_material = TestCrypto.hybrid_signing_private_key_material("identity", user_id)
    {identity_x25519_public, _identity_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    identity_encryption =
      hybrid_encryption_public_key_material("identity", user_id, identity_x25519_public)

    client_nonce = :crypto.strong_rand_bytes(16)

    {:ok, device} =
      RefMD.Devices.create_device(%{
        id: device_id,
        user_id: user_id,
        name: "Browser",
        device_type: "browser",
        hybrid_encryption_public_key_material: encryption.public,
        encryption_key_id: encryption.encryption_key_id,
        hybrid_signing_public_key_material: material.public,
        signing_key_id: material.signing_key_id,
        approval_signature:
          genesis_device_bootstrap_signature(
            user_id,
            device_id,
            material.public,
            ecdh_public_key,
            encryption.public,
            client_nonce
          ),
        approval_signature_surface: "genesis_device_bootstrap",
        approval_proof:
          genesis_device_approval_proof(
            user_id,
            device_id,
            material.public,
            ecdh_public_key,
            encryption.public,
            client_nonce
          ),
        client_nonce: client_nonce
      })

    %{
      user_id: user_id,
      device: device,
      signing_private_key: material.private,
      device_private_material: material.private,
      device_encryption_public: encryption.public,
      identity_private_material: identity_material,
      identity_encryption_public: identity_encryption.public
    }
  end

  defp create_plugin_application(attrs) do
    attrs =
      if Map.get(attrs, :package_id) do
        attrs
      else
        package = create_workspace_package!(attrs)
        Map.put(attrs, :package_id, package.id)
      end

    Plugins.create_application(attrs)
  end

  defp create_workspace_package!(attrs) do
    plugin_id = Map.fetch!(attrs, :plugin_id)
    workspace_id = Map.fetch!(attrs, :workspace_id)

    {:ok, package} =
      Packages.create(%{
        plugin_id: plugin_id,
        version: Map.get(attrs, :version, "1.0.0"),
        owner_scope_kind: "workspace",
        owner_workspace_id: workspace_id,
        created_by_user_id: Map.fetch!(attrs, :created_by_user_id),
        bundle_hash: hash("package-bundle:#{plugin_id}:#{workspace_id}"),
        resource_manifest_hash: hash("package-resources:#{plugin_id}:#{workspace_id}"),
        state_head_hash: "GENESIS"
      })

    package
  end

  defp insert_runtime_workspace_key_directory!(workspace_id, user_id, account) do
    owner_role =
      Repo.get_by!(RefMD.Workspaces.WorkspaceRole,
        workspace_id: workspace_id,
        base_role: "owner"
      )

    TestCrypto.insert_test_workspace_key_directory!(
      workspace_id,
      user_id,
      owner_role.id,
      account.identity_private_material,
      account.identity_encryption_public,
      account.device_private_material,
      account.device_encryption_public
    )
  end

  defp add_workspace_member(workspace_id, user_id, base_role) do
    role =
      workspace_id
      |> Workspaces.list_workspace_roles()
      |> Enum.find(&(&1.base_role == base_role))

    Repo.insert!(%RefMD.Workspaces.WorkspaceMember{
      workspace_id: workspace_id,
      user_id: user_id,
      role_id: role.id,
      joined_at: DateTime.utc_now()
    })
  end

  defp authed_conn(conn, user_id, device) do
    {:ok, session, token} = Auth.create_session(user_id, %{device_id: device.id})

    conn
    |> put_req_header("cookie", "_refmd_session=#{Base.url_encode64(token, padding: false)}")
    |> put_private(:test_session, session)
  end

  defp same_auth_session_conn(conn) do
    [cookie] = get_req_header(conn, "cookie")

    Phoenix.ConnTest.build_conn()
    |> put_req_header("cookie", cookie)
    |> put_private(:test_session, conn.private.test_session)
  end

  defp create_runtime_application(workspace_id, user_id, device, manifest_json \\ nil) do
    entries = %{
      "manifest.json" =>
        manifest_json ||
          ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.runtime","name":"Runtime","version":"1.0.0","permissions":["storage:read:workspace"],"documentScopes":[]}),
      "main.js" => "export default {}"
    }

    create_runtime_application_with_entries(workspace_id, user_id, device, entries)
  end

  defp create_runtime_application_with_entries(workspace_id, user_id, device, entries) do
    {:ok, application} =
      create_plugin_application(%{
        workspace_id: workspace_id,
        plugin_id: "com.example.runtime",
        created_by_user_id: user_id,
        state_head_hash: "state-head"
      })

    archive_path = plugin_archive_path(entries)

    {:ok, candidate} =
      Plugins.create_local_bundle_candidate(archive_path, %{
        package_id: application.package_id,
        workspace_id: workspace_id,
        created_by_user_id: user_id,
        created_by_device_id: device.id
      })

    approval =
      approval_attrs(candidate, %{
        approver_user_id: user_id,
        approver_device_id: device.id,
        approval_epoch: 1,
        previous_approval_event_hash: "GENESIS"
      })

    {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

    {:ok, %{application: updated}} =
      Plugins.apply_package_to_workspace(workspace_id, package.id, user_id, device.id)

    {:ok, bundle} = Plugins.current_bundle_with_pin(updated.id, updated.state_head_hash)

    {:ok, consent} =
      Plugins.append_consent_event(
        consent_attrs(%{
          application_id: application.id,
          workspace_id: workspace_id,
          plugin_id: application.plugin_id,
          version: bundle.version,
          bundle_hash: bundle.bundle_hash,
          manifest_hash: bundle.manifest_hash,
          permissions_hash: bundle.permissions_hash,
          endpoint_hash: bundle.endpoint_hash,
          document_scope_hash: bundle.document_scope_hash,
          user_id: user_id,
          device_id: device.id,
          signer_user_id: user_id,
          signer_device_id: device.id
        })
      )

    %{application: updated, updated: updated, bundle: bundle, consent: consent}
  end

  defp create_user_runtime_application(workspace_id, user_id, device) do
    archive_path =
      plugin_archive_path(%{
        "manifest.json" =>
          ~s({"scope":{"supportedOwnerScopes":["user"],"defaultOwnerScope":"user","workspaceApplication":"optional"},"id":"com.example.runtime","name":"Runtime","version":"1.0.0","permissions":[],"documentScopes":[]}),
        "main.js" => "export default {}"
      })

    {:ok, candidate} =
      Plugins.create_local_bundle_candidate(archive_path, %{
        owner_scope_kind: "user",
        created_by_user_id: user_id,
        created_by_device_id: device.id
      })

    approval =
      approval_attrs(candidate, %{
        approver_user_id: user_id,
        approver_device_id: device.id,
        approval_epoch: 1,
        previous_approval_event_hash: "GENESIS"
      })

    {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

    {:ok, %{application: application}} =
      Plugins.apply_package_to_workspace(workspace_id, package.id, user_id, device.id)

    {:ok, bundle} = Plugins.current_bundle_with_pin(application.id, application.state_head_hash)

    {:ok, consent} =
      Plugins.append_consent_event(
        consent_attrs(%{
          application_id: application.id,
          workspace_id: workspace_id,
          plugin_id: application.plugin_id,
          version: bundle.version,
          bundle_hash: bundle.bundle_hash,
          manifest_hash: bundle.manifest_hash,
          permissions_hash: bundle.permissions_hash,
          endpoint_hash: bundle.endpoint_hash,
          document_scope_hash: bundle.document_scope_hash,
          owner_scope_kind: "user",
          user_id: user_id,
          device_id: device.id,
          signer_user_id: user_id,
          signer_device_id: device.id
        })
      )

    %{application: application, bundle: bundle, consent: consent}
  end

  defp promote_runtime_bundle(
         application,
         workspace_id,
         user_id,
         device,
         version,
         approval_epoch,
         previous_approval_event_hash
       ) do
    archive_path =
      plugin_archive_path(%{
        "manifest.json" =>
          ~s({"scope":{"supportedOwnerScopes":["workspace"],"defaultOwnerScope":"workspace","workspaceApplication":"required"},"id":"com.example.runtime","name":"Runtime","version":"#{version}","permissions":["storage:read:workspace"],"documentScopes":[]}),
        "main.js" => "export default {}"
      })

    {:ok, candidate} =
      Plugins.create_local_bundle_candidate(archive_path, %{
        package_id: application.package_id,
        workspace_id: workspace_id,
        created_by_user_id: user_id,
        created_by_device_id: device.id
      })

    approval =
      approval_attrs(candidate, %{
        approver_user_id: user_id,
        approver_device_id: device.id,
        approval_epoch: approval_epoch,
        previous_approval_event_hash: previous_approval_event_hash
      })

    {:ok, package} = Plugins.promote_bundle_candidate(candidate, approval)

    {:ok, %{application: updated}} =
      Plugins.apply_package_to_workspace(workspace_id, package.id, user_id, device.id)

    {:ok, bundle} = Plugins.current_bundle_with_pin(updated.id, updated.state_head_hash)
    {:ok, updated, bundle}
  end

  defp approval_attrs(candidate, attrs) do
    attrs =
      attrs
      |> Map.put_new(:workspace_id, candidate.workspace_id)
      |> Map.put_new(:created_at_ms, 1_775_000_000_000)

    attrs
    |> Map.put(
      :approval_event_hash,
      Plugins.plugin_bundle_approval_subject_hash(candidate, attrs)
    )
    |> Map.put(:hybrid_signature, approval_signature(candidate, attrs))
  end

  defp approval_signature(candidate, attrs) do
    material = device_material!(Map.fetch!(attrs, :approver_device_id))

    actor =
      approval_signing_actor(candidate, attrs)

    approval = Plugins.plugin_bundle_approval_subject(candidate, attrs)

    transcript =
      PluginSignature.build_plugin_bundle_approval_transcript!(%{
        actor: actor,
        approval: approval
      })

    Signature.__test_sign_hybrid_signature__(
      "plugin_bundle_approval",
      transcript,
      material.private,
      material.public
    )
  end

  defp consent_attrs(overrides) do
    attrs =
      Map.merge(
        %{
          decision: "allow",
          consent_epoch: 1,
          previous_event_hash: "GENESIS"
        },
        overrides
      )

    attrs
    |> Map.put(:event_hash, Plugins.consent_subject_hash(attrs))
    |> Map.put(:hybrid_signature, consent_signature(attrs))
  end

  defp consent_signature(attrs) do
    material = device_material!(Map.fetch!(attrs, :device_id))

    actor =
      signing_actor(
        Map.fetch!(attrs, :user_id),
        Map.fetch!(attrs, :device_id),
        Map.fetch!(attrs, :workspace_id)
      )

    transcript =
      PluginSignature.build_plugin_consent_event_transcript!(%{
        actor: actor,
        consent: Plugins.consent_subject(attrs)
      })

    Signature.__test_sign_hybrid_signature__(
      "plugin_consent_event",
      transcript,
      material.private,
      material.public
    )
  end

  defp approval_signing_actor(%{owner_scope_kind: "user"}, attrs) do
    signing_actor(
      Map.fetch!(attrs, :approver_user_id),
      Map.fetch!(attrs, :approver_device_id),
      Map.fetch!(attrs, :approver_user_id),
      "user"
    )
  end

  defp approval_signing_actor(_candidate, attrs) do
    signing_actor(
      Map.fetch!(attrs, :approver_user_id),
      Map.fetch!(attrs, :approver_device_id),
      Map.fetch!(attrs, :workspace_id),
      "workspace"
    )
  end

  defp signing_actor(user_id, device_id, scope_id, scope_kind \\ "workspace") do
    device = Repo.get!(Device, device_id)

    %{
      "device_id" => device_id,
      "key_checkpoint_hash" => device.key_checkpoint_hash,
      "key_checkpoint_sequence" => device.key_checkpoint_sequence,
      "key_scope_id" => scope_id,
      "key_scope_kind" => scope_kind,
      "signer_kind" => "device",
      "user_id" => user_id,
      "signing_key_id" => device_material!(device_id).signing_key_id
    }
  end

  defp device_material!(device_id) do
    Process.get({:plugin_runtime_controller_material, device_id}) ||
      raise "missing plugin runtime controller signing material"
  end

  defp plugin_archive_path(entries) do
    path =
      Path.join(
        System.tmp_dir!(),
        "refmd-plugin-runtime-controller-#{System.unique_integer([:positive, :monotonic])}.zip"
      )

    zip_entries = Enum.map(entries, fn {name, bytes} -> {String.to_charlist(name), bytes} end)
    {:ok, _filename} = :zip.create(String.to_charlist(path), zip_entries)
    path
  end

  defp put_iframe_fetch_headers(conn) do
    conn
    |> put_req_header("sec-fetch-dest", "iframe")
    |> put_req_header("sec-fetch-mode", "navigate")
    |> put_req_header("sec-fetch-site", "same-origin")
  end

  defp hash(value), do: Hash.blake3_base64url(value)
end
