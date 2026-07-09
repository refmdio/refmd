defmodule RefMDWeb.PluginNetworkExecutorControllerTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Auth
  alias RefMD.Crypto.Hash
  alias RefMD.Devices.Device
  alias RefMD.Plugins

  alias RefMD.Plugins.{
    PluginActivation,
    PluginApplication,
    PluginBundle,
    PluginBundleCandidate,
    PluginConsentEvent,
    PluginPackage
  }

  alias RefMD.Repo
  alias RefMD.Security.AuditEvent
  alias RefMD.Users.User
  alias RefMD.Workspaces

  test "mints and serves a runtime-bound constrained network executor document", %{conn: conn} do
    %{conn: session_conn, body: body} = runtime_bound_session(conn)

    conn =
      post(session_conn, "/api/plugin-network-executor-sessions", body)

    session_token = json_response(conn, 200)["session_token"]
    assert is_binary(session_token)

    conn =
      conn
      |> recycle()
      |> get("/plugin-network-executor?session_token=#{URI.encode_www_form(session_token)}")

    body = response(conn, 200)
    assert body =~ "refmd.plugin-network-executor"
    assert body =~ ~s(&quot;target_origin&quot;:&quot;https://proxy.example&quot;)

    assert body =~
             ~s(&quot;target_url&quot;:&quot;https://proxy.example/refmd&quot;)

    assert body =~ ~s(&quot;method&quot;:&quot;POST&quot;)
    assert body =~ ~s(&quot;route&quot;:&quot;proxy&quot;)
    assert body =~ "request.executorToken !== executorToken"
    assert body =~ "network executor token mismatch"
    assert body =~ "network target policy mismatch"
    assert body =~ "network executor method mismatch"
    assert body =~ "network executor header policy mismatch"
    assert body =~ "network executor body too large"

    [csp] = get_resp_header(conn, "content-security-policy")
    assert csp =~ "default-src 'none'"
    assert csp =~ "script-src 'sha256-"
    assert csp =~ "connect-src https://proxy.example"
    assert csp =~ "frame-ancestors 'self'"
    refute csp =~ "connect-src 'self'"
    assert get_resp_header(conn, "x-frame-options") == []
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "mints proxy executor document with proxy-origin CSP and endpoint-bound audit", %{
    conn: conn
  } do
    %{
      conn: session_conn,
      body: body,
      workspace: workspace,
      application: application,
      user_id: user_id,
      device_id: device_id
    } = runtime_bound_session(conn)

    set_workspace_proxy!(workspace)

    proxy_body =
      Map.merge(body, %{
        "target_url" => "https://proxy.example/refmd",
        "target_origin" => "https://proxy.example",
        "route" => "proxy",
        "proxy_id" => "workspace-proxy",
        "method" => "POST",
        "header_names" => ["content-type"],
        "body_schema" => "json",
        "max_request_bytes" => 4096,
        "network_target_url" => body["network_target_url"],
        "network_method" => body["method"],
        "network_header_names" => body["header_names"],
        "network_body_schema" => body["body_schema"],
        "request_id" => "request-proxy-one"
      })

    insert_network_audit!(application, proxy_body, user_id, device_id)

    conn =
      post(session_conn, "/api/plugin-network-executor-sessions", proxy_body)

    session_token = json_response(conn, 200)["session_token"]

    conn =
      conn
      |> recycle()
      |> get("/plugin-network-executor?session_token=#{URI.encode_www_form(session_token)}")

    body = response(conn, 200)
    assert body =~ ~s(&quot;target_origin&quot;:&quot;https://proxy.example&quot;)
    assert body =~ ~s(&quot;target_url&quot;:&quot;https://proxy.example/refmd&quot;)
    assert body =~ ~s(&quot;route&quot;:&quot;proxy&quot;)

    [csp] = get_resp_header(conn, "content-security-policy")
    assert csp =~ "connect-src https://proxy.example"
    refute csp =~ "connect-src 'self'"
  end

  test "rejects proxy executor sessions not bound to the configured proxy registration", %{
    conn: conn
  } do
    %{
      conn: session_conn,
      body: body,
      workspace: workspace,
      application: application,
      user_id: user_id,
      device_id: device_id
    } = runtime_bound_session(conn)

    set_workspace_proxy!(workspace)

    proxy_body =
      Map.merge(body, %{
        "target_url" => "https://proxy.example/refmd",
        "target_origin" => "https://proxy.example",
        "route" => "proxy",
        "proxy_id" => "workspace-proxy",
        "method" => "POST",
        "header_names" => ["content-type"],
        "body_schema" => "json",
        "max_request_bytes" => 4096,
        "network_target_url" => body["network_target_url"],
        "network_method" => body["method"],
        "network_header_names" => body["header_names"],
        "network_body_schema" => body["body_schema"],
        "request_id" => "request-proxy-binding"
      })

    for {attrs, request_id} <- [
          {Map.delete(proxy_body, "proxy_id"), "request-proxy-missing-id"},
          {Map.put(proxy_body, "proxy_id", "plugin-supplied-proxy"), "request-proxy-wrong-id"},
          {Map.put(proxy_body, "target_url", "https://evil-proxy.example/refmd")
           |> Map.put("target_origin", "https://evil-proxy.example"),
           "request-proxy-wrong-target"}
        ] do
      attrs = Map.put(attrs, "request_id", request_id)
      insert_network_audit!(application, attrs, user_id, device_id)

      conn =
        session_conn
        |> recycle()
        |> post("/api/plugin-network-executor-sessions", attrs)

      assert response(conn, 400) == "Bad Request"
    end

    {:ok, _workspace} =
      Workspaces.update_workspace(workspace, %{
        plugin_network_proxy: %{
          id: "workspace-proxy",
          label: "Workspace Proxy",
          base_url: "https://proxy.example/refmd",
          scope: "workspace",
          enabled: false
        }
      })

    disabled_body = Map.put(proxy_body, "request_id", "request-proxy-disabled")
    insert_network_audit!(application, disabled_body, user_id, device_id)

    conn =
      session_conn
      |> recycle()
      |> post("/api/plugin-network-executor-sessions", disabled_body)

    assert response(conn, 400) == "Bad Request"

    {:ok, _workspace} =
      Workspaces.update_workspace(workspace, %{
        plugin_network_proxy: %{
          id: "workspace-proxy",
          label: "Workspace Proxy",
          base_url: "https://proxy.example/refmd",
          scope: "workspace",
          enabled: true,
          operator_label: "Example NetOps",
          allowed_workspace_ids: ["00000000-0000-4000-8000-000000000099"],
          allowed_user_ids: [],
          verification_material: %{"response_signing_key" => "proxy-key-1"},
          revoked: false,
          policy: %{"max_response_size" => 65_536}
        }
      })

    wrong_scope_body = Map.put(proxy_body, "request_id", "request-proxy-wrong-scope")
    insert_network_audit!(application, wrong_scope_body, user_id, device_id)

    conn =
      session_conn
      |> recycle()
      |> post("/api/plugin-network-executor-sessions", wrong_scope_body)

    assert response(conn, 400) == "Bad Request"

    {:ok, _workspace} =
      Workspaces.update_workspace(workspace, %{
        plugin_network_proxy: %{
          id: "workspace-proxy",
          label: "Workspace Proxy",
          base_url: "https://proxy.example/refmd",
          scope: "workspace",
          enabled: true,
          operator_label: "Example NetOps",
          allowed_workspace_ids: [workspace.id],
          allowed_user_ids: [user_id],
          verification_material: %{"response_signing_key" => "proxy-key-1"},
          revoked: true,
          policy: %{"max_response_size" => 65_536}
        }
      })

    revoked_body = Map.put(proxy_body, "request_id", "request-proxy-revoked")
    insert_network_audit!(application, revoked_body, user_id, device_id)

    conn =
      session_conn
      |> recycle()
      |> post("/api/plugin-network-executor-sessions", revoked_body)

    assert response(conn, 400) == "Bad Request"
  end

  test "rejects proxy executor sessions denied by proxy registration policy", %{conn: conn} do
    %{
      conn: session_conn,
      body: body,
      workspace: workspace,
      application: application,
      user_id: user_id,
      device_id: device_id
    } = runtime_bound_session(conn)

    proxy_body =
      Map.merge(body, %{
        "target_url" => "https://proxy.example/refmd",
        "target_origin" => "https://proxy.example",
        "route" => "proxy",
        "proxy_id" => "workspace-proxy",
        "method" => "POST",
        "header_names" => ["content-type"],
        "body_schema" => "json",
        "max_request_bytes" => 4096,
        "network_target_url" => body["network_target_url"],
        "network_method" => body["method"],
        "network_header_names" => body["header_names"],
        "network_body_schema" => body["body_schema"]
      })

    for {policy, attrs, request_id} <- [
          {%{"denied_endpoint_ids" => ["github-rest"]}, %{}, "request-proxy-denied-endpoint"},
          {%{"allowed_endpoint_ids" => ["slack-rest"]}, %{}, "request-proxy-allowed-endpoint"},
          {%{"allowed_route_classes" => ["extension"]}, %{}, "request-proxy-route-class"},
          {%{"max_request_size" => 16}, %{"request_bytes" => 17}, "request-proxy-request-size"},
          {%{"max_response_size" => 1024}, %{}, "request-proxy-response-size"}
        ] do
      set_workspace_proxy!(workspace, policy)
      attrs = proxy_body |> Map.merge(attrs) |> Map.put("request_id", request_id)
      insert_network_audit!(application, attrs, user_id, device_id)

      conn =
        session_conn
        |> recycle()
        |> post("/api/plugin-network-executor-sessions", attrs)

      assert response(conn, 400) == "Bad Request"
    end
  end

  test "rejects standalone session minting without runtime binding", %{conn: conn} do
    conn =
      conn
      |> authed_conn()
      |> post("/api/plugin-network-executor-sessions", legacy_executor_session_body())

    assert response(conn, 400) == "Bad Request"
  end

  test "rejects legacy self-minted executor document parameters", %{conn: conn} do
    conn =
      get(
        conn,
        "/plugin-network-executor?target_origin=https%3A%2F%2Fapi.github.com&executor_token=#{String.duplicate("a", 32)}"
      )

    assert response(conn, 400) == "Bad Request"
  end

  test "rejects invalid or forbidden session policies", %{conn: conn} do
    %{conn: session_conn, body: body} = runtime_bound_session(conn)

    for attrs <- [
          %{"target_url" => "http://api.github.com/repos/refmdio/refmd/issues"},
          %{"target_url" => "https://localhost/repos/refmdio/refmd/issues"},
          %{"target_url" => "https://127.0.0.1/repos/refmdio/refmd/issues"},
          %{"target_url" => "https://metadata.google.internal/computeMetadata/v1"},
          %{"target_origin" => "https://example.com"},
          %{"route" => "direct"},
          %{"route" => "auto"},
          %{"route" => "extension"},
          %{"method" => "GE T"},
          %{"header_names" => ["accept", "cookie"]},
          %{"body_schema" => "form"},
          %{"max_request_bytes" => 1_048_577},
          %{"proxy_id" => "other-proxy"},
          %{"proxy_id" => nil},
          %{"capability_grant_id" => "capability-grant-mismatch"},
          %{"owner_scope_kind" => "user"},
          %{"user_id" => Ecto.UUID.generate()},
          %{"device_id" => Ecto.UUID.generate()},
          %{"consent_epoch" => body["consent_epoch"] + 1}
        ] do
      conn =
        session_conn
        |> recycle()
        |> post("/api/plugin-network-executor-sessions", Map.merge(body, attrs))

      assert response(conn, 400) == "Bad Request"
    end
  end

  test "rejects executor sessions targeting the app origin", %{conn: conn} do
    %{conn: session_conn, body: body} = runtime_bound_session(conn)

    app_origin_conn = %{session_conn | scheme: :https, host: "app.refmd.example", port: 443}

    for attrs <- [
          %{
            "target_origin" => "https://app.refmd.example",
            "target_url" => "https://app.refmd.example/api/documents"
          },
          %{
            "target_origin" => "https://app.refmd.example",
            "target_url" => "https://App.RefMD.Example./api/documents"
          },
          %{
            "route" => "proxy",
            "target_origin" => "https://proxy.example",
            "target_url" => "https://proxy.example/refmd",
            "proxy_id" => "workspace-proxy",
            "network_target_url" => "https://app.refmd.example/api/documents"
          },
          %{
            "route" => "proxy",
            "target_origin" => "https://proxy.example",
            "target_url" => "https://proxy.example/refmd",
            "proxy_id" => "workspace-proxy",
            "network_target_url" => "https://APP.REFMD.EXAMPLE./api/documents"
          }
        ] do
      conn =
        app_origin_conn
        |> recycle()
        |> post("/api/plugin-network-executor-sessions", Map.merge(body, attrs))

      assert response(conn, 400) == "Bad Request"
    end
  end

  test "rejects stale positive runtime frame generation", %{conn: conn} do
    %{
      conn: session_conn,
      body: body,
      application: application,
      bundle: bundle,
      consent: consent,
      user_id: user_id,
      device_id: device_id
    } = runtime_bound_session(conn)

    _newer_frame_generation =
      current_runtime_frame_generation!(
        application,
        bundle,
        consent,
        user_id,
        device_id,
        body["capability_grant_id"]
      )

    conn =
      session_conn
      |> recycle()
      |> post("/api/plugin-network-executor-sessions", body)

    assert response(conn, 400) == "Bad Request"
  end

  test "rejects unauthenticated session minting and invalid session tokens", %{conn: conn} do
    assert conn
           |> post("/api/plugin-network-executor-sessions", legacy_executor_session_body())
           |> response(401)

    for token <- [nil, "", "invalid"] do
      path =
        case token do
          nil -> "/plugin-network-executor"
          value -> "/plugin-network-executor?session_token=#{URI.encode_www_form(value)}"
        end

      conn =
        conn
        |> recycle()
        |> get(path)

      assert response(conn, 400) == "Bad Request"
    end
  end

  defp legacy_executor_session_body do
    %{
      "executor_token" => String.duplicate("a", 32),
      "target_origin" => "https://proxy.example",
      "target_url" => "https://proxy.example/refmd",
      "network_target_url" => "https://api.github.com/repos/refmdio/refmd/issues",
      "proxy_id" => "workspace-proxy",
      "route" => "proxy",
      "method" => "POST",
      "network_method" => "POST",
      "header_names" => ["accept", "content-type"],
      "network_header_names" => ["accept", "content-type"],
      "body_schema" => "json",
      "network_body_schema" => "json",
      "max_request_bytes" => 1024,
      "max_response_bytes" => 2048
    }
  end

  defp runtime_bound_session(conn) do
    user_id = Ecto.UUID.generate()
    device_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: "plugin-network-executor-#{user_id}@example.com",
      name: "Plugin Network Executor",
      account_type: "registered"
    })

    insert_device!(user_id, device_id)
    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Plugin Network Executor")
    set_workspace_proxy!(workspace)

    %{application: application, bundle: bundle, consent: consent} =
      insert_runtime_plugin!(workspace.id, user_id, device_id)

    body =
      legacy_executor_session_body()
      |> Map.merge(%{
        "workspace_id" => workspace.id,
        "plugin_id" => application.plugin_id,
        "package_id" => application.package_id,
        "application_id" => application.id,
        "activation_id" => consent.activation_id,
        "owner_scope_kind" => consent.owner_scope_kind,
        "user_id" => user_id,
        "device_id" => device_id,
        "endpoint_id" => "github-rest",
        "state_head_hash" => application.state_head_hash,
        "consent_head_hash" => consent.event_hash,
        "bundle_hash" => bundle.bundle_hash,
        "manifest_hash" => bundle.manifest_hash,
        "consent_epoch" => consent.consent_epoch,
        "capability_grant_id" => "capability-grant-one",
        "request_id" => "request-proxy-one",
        "credential_audience" => "api.github.com",
        "credential_handle_used" => false,
        "request_bytes" => 0
      })

    frame_generation =
      current_runtime_frame_generation!(
        application,
        bundle,
        consent,
        user_id,
        device_id,
        body["capability_grant_id"]
      )

    body = Map.put(body, "frame_generation", frame_generation)

    insert_network_audit!(application, body, user_id, device_id)

    %{
      conn: authed_conn(conn, user_id, device_id),
      body: body,
      application: application,
      bundle: bundle,
      consent: consent,
      workspace: workspace,
      user_id: user_id,
      device_id: device_id
    }
  end

  defp authed_conn(conn) do
    user_id = Ecto.UUID.generate()
    device_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: "plugin-network-executor-standalone-#{user_id}@example.com",
      name: "Plugin Network Executor",
      account_type: "registered"
    })

    insert_device!(user_id, device_id)
    authed_conn(conn, user_id, device_id)
  end

  defp authed_conn(conn, user_id, device_id) do
    {:ok, _session, token} = Auth.create_session(user_id, %{device_id: device_id})

    put_req_header(
      conn,
      "cookie",
      "__Host-refmd-session=#{Base.url_encode64(token, padding: false)}"
    )
  end

  defp insert_device!(user_id, device_id) do
    now = DateTime.utc_now()

    Repo.insert!(%Device{
      id: device_id,
      user_id: user_id,
      name: "Browser",
      device_type: "browser",
      hybrid_encryption_public_key_material: %{},
      encryption_key_id: "encryption-#{device_id}",
      hybrid_signing_public_key_material: %{},
      signing_key_id: "signing-#{device_id}",
      approval_signature: %{"sig" => "ok"},
      approval_signature_surface: "genesis_device_bootstrap",
      approval_proof: %{},
      key_checkpoint_sequence: 0,
      key_checkpoint_hash: hash("checkpoint:#{device_id}"),
      client_nonce: <<0::128>>,
      last_seen_at: now,
      created_at: now
    })
  end

  defp insert_runtime_plugin!(workspace_id, user_id, device_id) do
    manifest = %{
      "id" => "com.example.network",
      "version" => "1.0.0",
      "scope" => %{
        "supportedOwnerScopes" => ["workspace"],
        "defaultOwnerScope" => "workspace",
        "workspaceApplication" => "required"
      },
      "permissions" => [],
      "documentScopes" => [],
      "network" => %{
        "endpoints" => [
          %{
            "id" => "github-rest",
            "url" => "https://api.github.com/repos/refmdio/refmd/issues",
            "methods" => ["GET", "POST"],
            "routes" => ["proxy"],
            "headers" => ["accept", "content-type"],
            "bodySchema" => "json",
            "maxRequestBytes" => 1024,
            "maxResponseBytes" => 2048,
            "credentialAudience" => "api.github.com"
          }
        ]
      }
    }

    manifest_json = Jason.encode!(manifest)
    approval_event_hash = hash("approval-event")
    bundle_hash = hash("bundle")
    resource_manifest_hash = hash(Jason.encode!([]))

    package =
      %PluginPackage{}
      |> PluginPackage.changeset(%{
        plugin_id: "com.example.network",
        version: "1.0.0",
        owner_scope_kind: "workspace",
        owner_workspace_id: workspace_id,
        created_by_user_id: user_id,
        bundle_hash: bundle_hash,
        resource_manifest_hash: resource_manifest_hash,
        state_head_hash: approval_event_hash
      })
      |> Repo.insert!()

    application =
      %PluginApplication{}
      |> PluginApplication.changeset(%{
        workspace_id: workspace_id,
        package_id: package.id,
        plugin_id: package.plugin_id,
        created_by_user_id: user_id,
        application_scope_kind: "workspace",
        application_mode: "workspace_shared",
        workspace_policy_result: "allowed",
        enabled: true,
        consent_epoch: 0,
        state_head_hash: approval_event_hash
      })
      |> Repo.insert!()

    common = %{
      package_id: package.id,
      workspace_id: workspace_id,
      application_id: application.id,
      plugin_id: package.plugin_id,
      version: package.version,
      source_kind: "local_upload",
      source_url_hash: "NO_SOURCE_URL",
      archive_hash: hash("archive"),
      manifest_json: manifest,
      manifest_json_bytes: manifest_json,
      main_js: "export default {};",
      styles_css: "",
      manifest_hash: hash(manifest_json),
      main_js_hash: hash("export default {};"),
      styles_css_hash: hash(""),
      resource_manifest: [],
      resource_manifest_hash: resource_manifest_hash,
      bundle_hash: bundle_hash,
      permissions_hash: hash(Jason.encode!([])),
      endpoint_hash: hash(Jason.encode!(get_in(manifest, ["network", "endpoints"]))),
      renderer_slots_hash: hash(Jason.encode!([])),
      document_scope_hash: hash(Jason.encode!([])),
      validation_status: "valid",
      validation_errors: [],
      created_by_user_id: user_id,
      created_by_device_id: device_id
    }

    candidate =
      %PluginBundleCandidate{}
      |> PluginBundleCandidate.changeset(
        common
        |> Map.put(:owner_scope_kind, "workspace")
        |> Map.put(:owner_workspace_id, workspace_id)
      )
      |> Repo.insert!()

    bundle =
      %PluginBundle{}
      |> PluginBundle.changeset(
        Map.merge(common, %{
          candidate_id: candidate.id,
          approval_epoch: 1,
          approval_authority_event_head_sequence: 0,
          approval_authority_event_head_hash: hash("approval-authority-event"),
          approval_authority_checkpoint_sequence: 1,
          approval_authority_checkpoint_hash: hash("approval-authority-checkpoint"),
          previous_approval_event_hash: "GENESIS",
          approval_event_hash: approval_event_hash,
          hybrid_signature: %{"sig" => "ok"},
          approved_by_user_id: user_id,
          approved_by_device_id: device_id,
          approved_at_ms: 1_775_000_000_000
        })
      )
      |> Repo.insert!()

    application =
      application
      |> PluginApplication.changeset(%{current_bundle_id: bundle.id})
      |> Repo.update!()

    activation =
      %PluginActivation{}
      |> PluginActivation.changeset(%{
        application_id: application.id,
        user_id: user_id,
        device_id: device_id,
        activation_scope_kind: "device",
        enabled: true
      })
      |> Repo.insert!()

    consent =
      %PluginConsentEvent{}
      |> PluginConsentEvent.changeset(%{
        package_id: package.id,
        application_id: application.id,
        activation_id: activation.id,
        workspace_id: workspace_id,
        plugin_id: application.plugin_id,
        owner_scope_kind: "workspace",
        application_scope_kind: application.application_scope_kind,
        version: bundle.version,
        bundle_hash: bundle.bundle_hash,
        manifest_hash: bundle.manifest_hash,
        resource_manifest_hash: bundle.resource_manifest_hash,
        permissions_hash: bundle.permissions_hash,
        endpoint_hash: bundle.endpoint_hash,
        document_scope_hash: bundle.document_scope_hash,
        signer_user_id: user_id,
        signer_device_id: device_id,
        user_id: user_id,
        device_id: device_id,
        decision: "allow",
        consent_epoch: 1,
        previous_event_hash: "GENESIS",
        event_hash: hash("consent-event"),
        hybrid_signature: %{"sig" => "ok"}
      })
      |> Repo.insert!()

    %{application: application, bundle: bundle, consent: consent}
  end

  defp insert_network_audit!(application, body, user_id, device_id) do
    target_url = body["network_target_url"] || body["target_url"]
    target_uri = URI.parse(target_url)
    route = body["route"]
    method = body["network_method"] || body["method"]
    proxy_id = if route == "proxy", do: body["proxy_id"] || "workspace-proxy", else: "none"
    proxy_action = if route == "proxy", do: %{"proxy_id" => proxy_id}, else: %{}

    %AuditEvent{}
    |> AuditEvent.changeset(%{
      class: "security_runtime",
      type: "plugin.network.requested",
      actor: %{"user_id" => user_id, "device_id" => device_id},
      scope: %{
        "workspace_id" => application.workspace_id,
        "document_id" => nil,
        "share_id" => nil
      },
      resource: %{
        "kind" => "network_endpoint",
        "id" => body["endpoint_id"],
        "version_hash" => target_url <> "|route=#{route}|credential=no|proxy=#{proxy_id}"
      },
      action:
        Map.merge(
          %{
            "operation" => "app.network.fetch:#{method}:#{route}",
            "result" => "allowed",
            "reason_code" => nil,
            "endpoint_id" => body["endpoint_id"],
            "route" => route,
            "method" => method,
            "target_origin" => "#{target_uri.scheme}://#{target_uri.host}",
            "target_path" => target_uri.path,
            "request_bytes" => body["request_bytes"],
            "credential_handle_used" => body["credential_handle_used"]
          },
          proxy_action
        ),
      sensitivity: %{
        "plaintext_scope_kind" => "none",
        "plaintext_bytes" => 0,
        "egress_bytes" => 0,
        "storage_bytes" => 0
      },
      correlation: %{
        "request_id" => body["request_id"],
        "capability_id" => "capability-one",
        "capability_grant_id" => body["capability_grant_id"],
        "frame_generation" => body["frame_generation"],
        "execution_context_id" => nil,
        "authority_event_ref" => nil
      }
    })
    |> Repo.insert!()
  end

  defp set_workspace_proxy!(workspace, policy \\ %{"max_response_size" => 65_536}) do
    {:ok, workspace} =
      Workspaces.update_workspace(workspace, %{
        plugin_network_proxy: %{
          id: "workspace-proxy",
          label: "Workspace Proxy",
          base_url: "https://proxy.example/refmd",
          scope: "workspace",
          enabled: true,
          operator_label: "Example NetOps",
          allowed_workspace_ids: [workspace.id],
          allowed_user_ids: [],
          verification_material: %{"response_signing_key" => "proxy-key-1"},
          revoked: false,
          policy: policy
        }
      })

    workspace
  end

  defp current_runtime_frame_generation!(
         application,
         bundle,
         consent,
         user_id,
         device_id,
         capability_grant_id
       ) do
    session =
      Plugins.create_sandbox_document_session(%{
        workspace_id: application.workspace_id,
        package_id: application.package_id,
        application_id: application.id,
        activation_id: consent.activation_id,
        owner_scope_kind: "workspace",
        user_id: user_id,
        device_id: device_id,
        auth_session_id: "test-auth-session",
        bundle_id: bundle.id,
        bundle_hash: bundle.bundle_hash,
        manifest_hash: bundle.manifest_hash,
        resource_manifest_hash: bundle.resource_manifest_hash,
        state_head_hash: application.state_head_hash,
        consent_head_hash: consent.event_hash,
        consent_epoch: consent.consent_epoch,
        capability_grant_id: capability_grant_id
      })

    :ok = Plugins.mark_sandbox_document_served(session)
    true = Plugins.activate_sandbox_document_frame?(session)
    session.frame_generation
  end

  defp hash(value), do: Hash.blake3_base64url(value)
end
