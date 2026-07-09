defmodule RefMDWeb.PluginStorageControllerTest do
  use RefMDWeb.ConnCase, async: false

  alias RefMD.Auth
  alias RefMD.Crypto.Hash
  alias RefMD.Documents
  alias RefMD.Plugins
  alias RefMD.Plugins.Packages

  alias RefMD.Plugins.{
    PluginActivation,
    PluginBundle,
    PluginBundleCandidate,
    PluginConsentEvent,
    RuntimeDescriptors
  }

  alias RefMD.Repo
  alias RefMD.Security.AuditEvent
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

  defp with_rrp_headers(
         conn,
         user_id,
         device,
         signing_private_key,
         method,
         path,
         body,
         query
       ) do
    put_test_rrp_headers(conn, user_id, device, signing_private_key, method, path, body, query)
  end

  setup do
    :ets.delete_all_objects(RefMDWeb.Plugs.RateLimit.Storage)

    owner_id = create_user("owner-plugin-storage-controller@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Plugin Storage Controller")
    owner_device = create_device(owner_id)

    {:ok, application} =
      create_plugin_application(%{
        workspace_id: workspace.id,
        plugin_id: "com.example.storage",
        created_by_user_id: owner_id,
        state_head_hash: "state-head"
      })

    %{application: application, consent: consent} =
      pin_storage_plugin_runtime!(application, owner_id, owner_device.device, [
        %{"kind" => "workspace"}
      ])

    %{
      consent: consent,
      application: application,
      owner_device: owner_device,
      owner_id: owner_id,
      workspace: workspace
    }
  end

  test "stores, reads, and deletes encrypted workspace plugin storage", %{
    consent: consent,
    conn: conn,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/storage/workspace"
    query = storage_query(application, consent, %{"key" => "settings"})
    request_path = path <> "?" <> query

    body = %{
      "plugin_id" => application.plugin_id,
      "ciphertext" => Base.url_encode64(<<1, 2, 3>>, padding: false),
      "nonce" => Base.url_encode64(<<4, 5, 6>>, padding: false),
      "key_version" => 1
    }

    put_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PUT",
        path,
        body,
        query
      )
      |> put(request_path, test_json_body(body))

    assert %{"ciphertext" => ciphertext, "key_version" => 1, "surface" => "workspace"} =
             json_response(put_conn, 200)

    assert json_response(put_conn, 200)["activation_id"] == consent.activation_id
    refute ciphertext == ""

    assert %AuditEvent{correlation: correlation, sensitivity: sensitivity} =
             Repo.get_by(AuditEvent, type: "plugin.storage.written")

    assert correlation == %{
             "request_id" => nil,
             "capability_id" => nil,
             "execution_context_id" => nil,
             "authority_event_ref" => consent.event_hash,
             "package_id" => application.package_id,
             "application_id" => application.id,
             "activation_id" => consent.activation_id,
             "owner_scope_kind" => "workspace",
             "capability_grant_id" => URI.decode_query(query)["capability_grant_id"],
             "frame_generation" =>
               URI.decode_query(query)["frame_generation"] |> String.to_integer()
           }

    assert is_binary(correlation["authority_event_ref"])
    assert sensitivity["storage_bytes"] == 3

    get_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "GET",
        path,
        "",
        query
      )
      |> get(request_path)

    assert %{"ciphertext" => ^ciphertext, "key" => "settings", "activation_id" => activation_id} =
             json_response(get_conn, 200)

    assert activation_id == consent.activation_id

    delete_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "DELETE",
        path,
        "",
        query
      )
      |> delete(request_path)

    assert json_response(delete_conn, 200) == %{"ok" => true}

    missing_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "GET",
        path,
        "",
        query
      )
      |> get(request_path)

    assert json_response(missing_conn, 200) == nil
  end

  test "shares workspace plugin storage across activations for the same application", %{
    consent: consent,
    conn: conn,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/storage/workspace"
    write_query = storage_query(application, consent, %{"key" => "settings"})

    body = %{
      "plugin_id" => application.plugin_id,
      "ciphertext" => Base.url_encode64(<<1, 2, 3>>, padding: false),
      "nonce" => Base.url_encode64(<<4, 5, 6>>, padding: false),
      "key_version" => 1
    }

    write_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PUT",
        path,
        body,
        write_query
      )
      |> put(path <> "?" <> write_query, test_json_body(body))

    assert %{"ciphertext" => ciphertext, "key" => "settings", "activation_id" => activation_id} =
             json_response(write_conn, 200)

    assert activation_id == consent.activation_id

    second_consent = create_storage_consent!(application, owner_id, owner_device.device, "second")
    read_query = storage_query(application, second_consent, %{"key" => "settings"})

    read_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "GET",
        path,
        "",
        read_query
      )
      |> get(path <> "?" <> read_query)

    assert %{"ciphertext" => ^ciphertext, "key" => "settings", "activation_id" => activation_id} =
             json_response(read_conn, 200)

    assert activation_id == consent.activation_id

    delete_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "DELETE",
        path,
        "",
        read_query
      )
      |> delete(path <> "?" <> read_query)

    assert json_response(delete_conn, 200) == %{"ok" => true}

    missing_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "GET",
        path,
        "",
        read_query
      )
      |> get(path <> "?" <> read_query)

    assert json_response(missing_conn, 200) == nil
  end

  test "rejects oversized encrypted workspace plugin storage", %{
    consent: consent,
    conn: conn,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/storage/workspace"
    query = storage_query(application, consent, %{"key" => "settings"})

    body = %{
      "plugin_id" => application.plugin_id,
      "ciphertext" => :crypto.strong_rand_bytes(65 * 1024) |> Base.url_encode64(padding: false),
      "nonce" => Base.url_encode64(<<4, 5, 6>>, padding: false),
      "key_version" => 1
    }

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PUT",
        path,
        body,
        query
      )
      |> put(path <> "?" <> query, test_json_body(body))

    assert json_response(conn, 413) == %{"error" => "plugin_storage_payload_too_large"}
    refute Repo.get_by(AuditEvent, type: "plugin.storage.written")
  end

  test "rate limits repeated encrypted workspace plugin storage writes", %{
    consent: consent,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/storage/workspace"
    query = storage_query(application, consent, %{"key" => "settings"})
    request_path = path <> "?" <> query

    body = %{
      "plugin_id" => application.plugin_id,
      "ciphertext" => Base.url_encode64(<<1, 2, 3>>, padding: false),
      "nonce" => Base.url_encode64(<<4, 5, 6>>, padding: false),
      "key_version" => 1
    }

    conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PUT",
        path,
        body,
        query
      )
      |> put(request_path, test_json_body(body))

    assert json_response(conn, 200)["key"] == "settings"

    counter_base =
      {:plugin_storage_write, application.id, consent.activation_id, "workspace", workspace.id,
       owner_id}

    current_window = System.system_time(:millisecond) |> div(60_000)

    for window <- [current_window, current_window + 1] do
      :ets.insert(RefMDWeb.Plugs.RateLimit.Storage, {{counter_base, window}, 60})
    end

    limited_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PUT",
        path,
        body,
        query
      )
      |> put(request_path, test_json_body(body))

    assert json_response(limited_conn, 429) == %{"error" => "plugin_storage_rate_limited"}
  end

  test "rejects workspace plugin storage reads with stale runtime freshness", %{
    consent: consent,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/storage/workspace"

    {:ok, _entry} =
      Plugins.put_kv(%{
        application_id: application.id,
        package_id: application.package_id,
        activation_id: consent.activation_id,
        workspace_id: workspace.id,
        plugin_id: application.plugin_id,
        scope: "workspace",
        scope_id: workspace.id,
        key: "settings",
        ciphertext: <<1, 2, 3>>,
        nonce: <<4, 5, 6>>,
        key_version: 1
      })

    for stale_context <- [
          %{"capability_grant_id" => Ecto.UUID.generate()},
          %{"consent_epoch" => consent.consent_epoch + 1},
          %{"frame_generation" => 0}
        ] do
      query = storage_query(application, consent, Map.put(stale_context, "key", "settings"))

      conn =
        Phoenix.ConnTest.build_conn()
        |> authed_conn(owner_id, owner_device.device)
        |> with_rrp_headers(
          owner_id,
          owner_device.device,
          owner_device.signing_private_key,
          "GET",
          path,
          "",
          query
        )
        |> get(path <> "?" <> query)

      assert json_response(conn, 403) == %{"error" => "plugin_storage_context_invalid"}
    end

    stale_query = storage_query(application, consent, %{"key" => "settings"})
    _newer_query = storage_query(application, consent, %{"key" => "settings"})

    stale_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "GET",
        path,
        "",
        stale_query
      )
      |> get(path <> "?" <> stale_query)

    assert json_response(stale_conn, 403) == %{"error" => "plugin_storage_context_invalid"}
  end

  test "rejects workspace plugin storage reads before sandbox load activation", %{
    consent: consent,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/storage/workspace"

    {:ok, _entry} =
      Plugins.put_kv(%{
        application_id: application.id,
        package_id: application.package_id,
        activation_id: consent.activation_id,
        workspace_id: workspace.id,
        plugin_id: application.plugin_id,
        scope: "workspace",
        scope_id: workspace.id,
        key: "settings",
        ciphertext: <<1, 2, 3>>,
        nonce: <<4, 5, 6>>,
        key_version: 1
      })

    query = storage_query(application, consent, %{"key" => "settings"}, :created)

    conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "GET",
        path,
        "",
        query
      )
      |> get(path <> "?" <> query)

    assert json_response(conn, 403) == %{"error" => "plugin_storage_context_invalid"}
  end

  test "rejects plugin storage writes for a mismatched plugin id", %{
    consent: consent,
    conn: conn,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/storage/workspace"

    query =
      storage_query(application, consent, %{
        "key" => "settings",
        "plugin_id" => "com.example.other"
      })

    request_path = path <> "?" <> query

    body = %{
      "plugin_id" => "com.example.other",
      "ciphertext" => Base.url_encode64(<<1, 2, 3>>, padding: false),
      "nonce" => Base.url_encode64(<<4, 5, 6>>, padding: false),
      "key_version" => 1
    }

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PUT",
        path,
        body,
        query
      )
      |> put(request_path, test_json_body(body))

    assert json_response(conn, 403) == %{"error" => "application_mismatch"}
  end

  test "rejects plugin storage writes without pinned runtime context", %{
    conn: conn,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/storage/workspace"
    query = URI.encode_query(%{"key" => "settings", "plugin_id" => application.plugin_id})
    request_path = path <> "?" <> query

    body = %{
      "plugin_id" => application.plugin_id,
      "ciphertext" => Base.url_encode64(<<1, 2, 3>>, padding: false),
      "nonce" => Base.url_encode64(<<4, 5, 6>>, padding: false),
      "key_version" => 1
    }

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PUT",
        path,
        body,
        query
      )
      |> put(request_path, test_json_body(body))

    assert json_response(conn, 422)["error"] == "invalid_request_schema"
  end

  test "creates, reads, and deletes encrypted workspace plugin records", %{
    consent: consent,
    conn: conn,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/records/workspace"
    query = storage_query(application, consent)

    body = %{
      "id" => "10000000-0000-4000-8000-000000000001",
      "plugin_id" => application.plugin_id,
      "kind" => "annotation",
      "encrypted_data" => Base.url_encode64(<<9, 8, 7>>, padding: false),
      "nonce" => Base.url_encode64(<<6, 5, 4>>, padding: false),
      "key_version" => 2
    }

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "POST",
        path,
        body,
        query
      )
      |> post(path <> "?" <> query, test_json_body(body))

    assert %{
             "id" => "10000000-0000-4000-8000-000000000001",
             "kind" => "annotation",
             "encrypted_data" => encrypted_data,
             "surface" => "workspace",
             "activation_id" => activation_id,
             "key_version" => 2
           } = json_response(create_conn, 200)

    assert activation_id == consent.activation_id
    record_id = "10000000-0000-4000-8000-000000000001"
    refute encrypted_data == ""

    missing_id_body = Map.delete(body, "id")

    missing_id_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "POST",
        path,
        missing_id_body,
        query
      )
      |> post(path <> "?" <> query, test_json_body(missing_id_body))

    assert json_response(missing_id_conn, 422)["error"] == "invalid_request_schema"

    invalid_id_body = %{body | "id" => "not-a-uuid"}

    invalid_id_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "POST",
        path,
        invalid_id_body,
        query
      )
      |> post(path <> "?" <> query, test_json_body(invalid_id_body))

    assert json_response(invalid_id_conn, 422)["error"] == "invalid_request_schema"

    get_path = "#{path}/#{record_id}"
    query = storage_query(application, consent)

    get_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "GET",
        get_path,
        "",
        query
      )
      |> get(get_path <> "?" <> query)

    assert %{
             "encrypted_data" => ^encrypted_data,
             "kind" => "annotation",
             "activation_id" => activation_id
           } =
             json_response(get_conn, 200)

    assert activation_id == consent.activation_id

    delete_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "DELETE",
        get_path,
        "",
        query
      )
      |> delete(get_path <> "?" <> query)

    assert json_response(delete_conn, 200) == %{"ok" => true}

    missing_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "GET",
        get_path,
        "",
        query
      )
      |> get(get_path <> "?" <> query)

    assert json_response(missing_conn, 200) == nil
  end

  test "shares workspace plugin records across activations for the same application", %{
    consent: consent,
    conn: conn,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/records/workspace"
    write_query = storage_query(application, consent)

    body = %{
      "id" => "10000000-0000-4000-8000-000000000011",
      "plugin_id" => application.plugin_id,
      "kind" => "annotation",
      "encrypted_data" => Base.url_encode64(<<9, 8, 7>>, padding: false),
      "nonce" => Base.url_encode64(<<6, 5, 4>>, padding: false),
      "key_version" => 2
    }

    create_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "POST",
        path,
        body,
        write_query
      )
      |> post(path <> "?" <> write_query, test_json_body(body))

    assert %{
             "encrypted_data" => encrypted_data,
             "kind" => "annotation",
             "activation_id" => activation_id
           } =
             json_response(create_conn, 200)

    assert activation_id == consent.activation_id

    second_consent =
      create_storage_consent!(application, owner_id, owner_device.device, "record-second")

    read_query = storage_query(application, second_consent)

    get_path = "#{path}/#{body["id"]}"

    read_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "GET",
        get_path,
        "",
        read_query
      )
      |> get(get_path <> "?" <> read_query)

    assert %{
             "encrypted_data" => ^encrypted_data,
             "kind" => "annotation",
             "activation_id" => activation_id
           } =
             json_response(read_conn, 200)

    assert activation_id == consent.activation_id
  end

  test "rejects oversized encrypted workspace plugin records", %{
    consent: consent,
    conn: conn,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/records/workspace"
    query = storage_query(application, consent)

    body = %{
      "id" => "10000000-0000-4000-8000-000000000003",
      "plugin_id" => application.plugin_id,
      "kind" => "annotation",
      "encrypted_data" =>
        :crypto.strong_rand_bytes(65 * 1024) |> Base.url_encode64(padding: false),
      "nonce" => Base.url_encode64(<<6, 5, 4>>, padding: false),
      "key_version" => 2
    }

    conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "POST",
        path,
        body,
        query
      )
      |> post(path <> "?" <> query, test_json_body(body))

    assert json_response(conn, 413) == %{"error" => "plugin_storage_payload_too_large"}
    refute Repo.get_by(AuditEvent, type: "plugin.storage.written")
  end

  test "rejects workspace plugin record reads with stale runtime freshness", %{
    consent: consent,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    record_id = "10000000-0000-4000-8000-000000000002"
    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/records/workspace"
    get_path = "#{path}/#{record_id}"

    {:ok, _record} =
      Plugins.put_record(%{
        id: record_id,
        application_id: application.id,
        package_id: application.package_id,
        activation_id: consent.activation_id,
        workspace_id: workspace.id,
        plugin_id: application.plugin_id,
        scope: "workspace",
        scope_id: workspace.id,
        kind: "annotation",
        encrypted_data: <<9, 8, 7>>,
        nonce: <<6, 5, 4>>,
        key_version: 1
      })

    for stale_context <- [
          %{"capability_grant_id" => Ecto.UUID.generate()},
          %{"consent_epoch" => consent.consent_epoch + 1},
          %{"frame_generation" => 0}
        ] do
      query = storage_query(application, consent, stale_context)

      conn =
        Phoenix.ConnTest.build_conn()
        |> authed_conn(owner_id, owner_device.device)
        |> with_rrp_headers(
          owner_id,
          owner_device.device,
          owner_device.signing_private_key,
          "GET",
          get_path,
          "",
          query
        )
        |> get(get_path <> "?" <> query)

      assert json_response(conn, 403) == %{"error" => "plugin_storage_context_invalid"}
    end

    stale_query = storage_query(application, consent)
    _newer_query = storage_query(application, consent)

    stale_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "GET",
        get_path,
        "",
        stale_query
      )
      |> get(get_path <> "?" <> stale_query)

    assert json_response(stale_conn, 403) == %{"error" => "plugin_storage_context_invalid"}
  end

  test "rejects document plugin storage outside the workspace document scope", %{
    consent: consent,
    conn: conn,
    application: application,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    {:ok, document} =
      Documents.create_document(%{
        "workspace_id" => workspace.id,
        "slug" => "plugin-storage-doc",
        "title" => "Plugin Storage Doc",
        "doc_type" => "document",
        "is_encrypted" => true
      })

    other_owner_id = create_user("other-plugin-storage-controller@example.com")
    {:ok, other_workspace} = Workspaces.create_default_workspace(other_owner_id, "Other")

    {:ok, other_document} =
      Documents.create_document(%{
        "workspace_id" => other_workspace.id,
        "slug" => "other-plugin-storage-doc",
        "title" => "Other Plugin Storage Doc",
        "doc_type" => "document",
        "is_encrypted" => true
      })

    path = "/api/workspaces/#{workspace.id}/plugin-runtime/#{application.id}/storage/document"

    valid_query =
      storage_query(application, consent, %{"key" => "settings", "document_id" => document.id})

    body = %{
      "plugin_id" => application.plugin_id,
      "ciphertext" => Base.url_encode64(<<1, 2, 3>>, padding: false),
      "nonce" => Base.url_encode64(<<4, 5, 6>>, padding: false),
      "key_version" => 1
    }

    valid_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PUT",
        path,
        body,
        valid_query
      )
      |> put(path <> "?" <> valid_query, test_json_body(body))

    assert %{"surface" => "document", "scope_id" => document_id} = json_response(valid_conn, 200)
    assert document_id == document.id

    invalid_query =
      storage_query(application, consent, %{
        "key" => "settings",
        "document_id" => other_document.id
      })

    invalid_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PUT",
        path,
        body,
        invalid_query
      )
      |> put(path <> "?" <> invalid_query, test_json_body(body))

    assert json_response(invalid_conn, 403) == %{"error" => "document_scope_denied"}
  end

  test "rejects document plugin storage outside signed document scope", %{
    conn: conn,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    {:ok, scoped_application} =
      create_plugin_application(%{
        workspace_id: workspace.id,
        plugin_id: "com.example.storage.scoped",
        created_by_user_id: owner_id,
        state_head_hash: "state-head-scoped"
      })

    {:ok, allowed_document} =
      Documents.create_document(%{
        "workspace_id" => workspace.id,
        "slug" => "allowed-plugin-storage-doc",
        "title" => "Allowed Plugin Storage Doc",
        "doc_type" => "document",
        "is_encrypted" => true
      })

    {:ok, denied_document} =
      Documents.create_document(%{
        "workspace_id" => workspace.id,
        "slug" => "denied-plugin-storage-doc",
        "title" => "Denied Plugin Storage Doc",
        "doc_type" => "document",
        "is_encrypted" => true
      })

    %{application: scoped_application, consent: scoped_consent} =
      pin_storage_plugin_runtime!(scoped_application, owner_id, owner_device.device, [
        %{"kind" => "document", "document_id" => allowed_document.id}
      ])

    path =
      "/api/workspaces/#{workspace.id}/plugin-runtime/#{scoped_application.id}/storage/document"

    denied_query =
      storage_query(scoped_application, scoped_consent, %{
        "key" => "settings",
        "document_id" => denied_document.id
      })

    body = %{
      "plugin_id" => scoped_application.plugin_id,
      "ciphertext" => Base.url_encode64(<<1, 2, 3>>, padding: false),
      "nonce" => Base.url_encode64(<<4, 5, 6>>, padding: false),
      "key_version" => 1
    }

    denied_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PUT",
        path,
        body,
        denied_query
      )
      |> put(path <> "?" <> denied_query, test_json_body(body))

    assert json_response(denied_conn, 403) == %{"error" => "document_scope_denied"}

    allowed_query =
      storage_query(scoped_application, scoped_consent, %{
        "key" => "settings",
        "document_id" => allowed_document.id
      })

    allowed_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "PUT",
        path,
        body,
        allowed_query
      )
      |> put(path <> "?" <> allowed_query, test_json_body(body))

    assert %{"scope_id" => allowed_document_id, "surface" => "document"} =
             json_response(allowed_conn, 200)

    assert allowed_document_id == allowed_document.id
  end

  test "rejects document plugin records outside signed document scope", %{
    conn: conn,
    owner_device: owner_device,
    owner_id: owner_id,
    workspace: workspace
  } do
    {:ok, scoped_application} =
      create_plugin_application(%{
        workspace_id: workspace.id,
        plugin_id: "com.example.storage.records.scoped",
        created_by_user_id: owner_id,
        state_head_hash: "state-head-record-scoped"
      })

    {:ok, allowed_document} =
      Documents.create_document(%{
        "workspace_id" => workspace.id,
        "slug" => "allowed-plugin-record-doc",
        "title" => "Allowed Plugin Record Doc",
        "doc_type" => "document",
        "is_encrypted" => true
      })

    {:ok, denied_document} =
      Documents.create_document(%{
        "workspace_id" => workspace.id,
        "slug" => "denied-plugin-record-doc",
        "title" => "Denied Plugin Record Doc",
        "doc_type" => "document",
        "is_encrypted" => true
      })

    %{application: scoped_application, consent: scoped_consent} =
      pin_storage_plugin_runtime!(scoped_application, owner_id, owner_device.device, [
        %{"kind" => "allowed_documents", "documentIds" => [allowed_document.id]}
      ])

    path =
      "/api/workspaces/#{workspace.id}/plugin-runtime/#{scoped_application.id}/records/document"

    denied_query =
      storage_query(scoped_application, scoped_consent, %{
        "document_id" => denied_document.id
      })

    body = %{
      "id" => "10000000-0000-4000-8000-000000000002",
      "plugin_id" => scoped_application.plugin_id,
      "kind" => "annotation",
      "encrypted_data" => Base.url_encode64(<<9, 8, 7>>, padding: false),
      "nonce" => Base.url_encode64(<<6, 5, 4>>, padding: false),
      "key_version" => 2
    }

    denied_conn =
      conn
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "POST",
        path,
        body,
        denied_query
      )
      |> post(path <> "?" <> denied_query, test_json_body(body))

    assert json_response(denied_conn, 403) == %{"error" => "document_scope_denied"}

    allowed_query =
      storage_query(scoped_application, scoped_consent, %{
        "document_id" => allowed_document.id
      })

    allowed_conn =
      Phoenix.ConnTest.build_conn()
      |> authed_conn(owner_id, owner_device.device)
      |> with_rrp_headers(
        owner_id,
        owner_device.device,
        owner_device.signing_private_key,
        "POST",
        path,
        body,
        allowed_query
      )
      |> post(path <> "?" <> allowed_query, test_json_body(body))

    assert %{"scope_id" => allowed_document_id, "surface" => "document"} =
             json_response(allowed_conn, 200)

    assert allowed_document_id == allowed_document.id
  end

  defp pin_storage_plugin_runtime!(application, user_id, device, document_scopes) do
    manifest = %{
      "scope" => %{
        "supportedOwnerScopes" => ["workspace"],
        "defaultOwnerScope" => "workspace",
        "workspaceApplication" => "required"
      },
      "id" => application.plugin_id,
      "version" => "1.0.0",
      "permissions" => [
        "storage:read:workspace",
        "storage:write:workspace",
        "storage:read:document",
        "storage:write:document"
      ],
      "network" => %{"endpoints" => []},
      "rendererSlots" => [],
      "documentScopes" => document_scopes
    }

    manifest_json_bytes = Jason.encode!(manifest)

    attrs = %{
      application_id: application.id,
      package_id: application.package_id,
      workspace_id: application.workspace_id,
      plugin_id: application.plugin_id,
      version: "1.0.0",
      source_kind: "local_upload",
      source_url_hash: "NO_SOURCE_URL",
      archive_hash: hash("archive"),
      manifest_json: manifest,
      manifest_json_bytes: manifest_json_bytes,
      main_js: "export default {};",
      styles_css: "",
      manifest_hash: hash(manifest_json_bytes),
      main_js_hash: hash("export default {};"),
      styles_css_hash: hash(""),
      bundle_hash: hash("bundle"),
      permissions_hash: hash("permissions"),
      endpoint_hash: hash("endpoint"),
      renderer_slots_hash: hash("renderer-slots"),
      document_scope_hash: hash(Jason.encode!(document_scopes)),
      validation_status: "valid",
      validation_errors: [],
      created_by_user_id: user_id,
      created_by_device_id: device.id
    }

    candidate =
      %PluginBundleCandidate{}
      |> PluginBundleCandidate.changeset(attrs)
      |> Repo.insert!()

    approval_event_hash = hash("approval-event")

    bundle =
      %PluginBundle{}
      |> PluginBundle.changeset(
        Map.merge(attrs, %{
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
          approved_by_device_id: device.id,
          approved_at_ms: 1_775_000_000_000
        })
      )
      |> Repo.insert!()

    {:ok, application} = Plugins.pin_current_bundle(application, bundle)

    {:ok, activation} =
      Plugins.create_activation(%{
        application_id: application.id,
        user_id: user_id,
        activation_scope_kind: "user",
        enabled: true
      })

    consent =
      %PluginConsentEvent{}
      |> PluginConsentEvent.changeset(%{
        package_id: application.package_id,
        application_id: application.id,
        activation_id: activation.id,
        workspace_id: application.workspace_id,
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
        signer_device_id: device.id,
        user_id: user_id,
        device_id: device.id,
        decision: "allow",
        consent_epoch: 1,
        previous_event_hash: "GENESIS",
        event_hash: hash("consent-event"),
        hybrid_signature: %{"sig" => "ok"}
      })
      |> Repo.insert!()

    %{application: application, consent: consent}
  end

  defp create_storage_consent!(application, user_id, device, suffix) do
    {:ok, bundle} = Plugins.current_bundle_with_pin(application.id, application.state_head_hash)

    {:ok, activation} =
      Plugins.create_activation(%{
        application_id: application.id,
        user_id: user_id,
        device_id: device.id,
        activation_scope_kind: "device",
        enabled: true
      })

    %PluginConsentEvent{}
    |> PluginConsentEvent.changeset(%{
      package_id: application.package_id,
      application_id: application.id,
      activation_id: activation.id,
      workspace_id: application.workspace_id,
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
      signer_device_id: device.id,
      user_id: user_id,
      device_id: device.id,
      decision: "allow",
      consent_epoch: 2,
      previous_event_hash: hash("consent-event"),
      event_hash: hash("consent-event:#{suffix}"),
      hybrid_signature: %{"sig" => "ok"}
    })
    |> Repo.insert!()
  end

  defp storage_query(application, consent, extra \\ %{}, lifecycle \\ :active) do
    {:ok, bundle} = Plugins.current_bundle_with_pin(application.id, application.state_head_hash)
    activation = Repo.get!(PluginActivation, consent.activation_id)

    capability_grant_id =
      RuntimeDescriptors.capability_grant_id(
        application,
        bundle,
        activation,
        consent,
        consent.user_id,
        consent.device_id
      )

    session =
      Plugins.create_sandbox_document_session(%{
        workspace_id: application.workspace_id,
        package_id: application.package_id,
        application_id: application.id,
        activation_id: activation.id,
        owner_scope_kind: "workspace",
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
        capability_grant_id: capability_grant_id
      })

    case lifecycle do
      :active ->
        :ok = Plugins.mark_sandbox_document_served(session)
        true = Plugins.activate_sandbox_document_frame?(session)

      :created ->
        :ok
    end

    frame_generation = session.frame_generation

    %{
      "plugin_id" => application.plugin_id,
      "state_head_hash" => application.state_head_hash,
      "consent_head_hash" => consent.event_hash,
      "capability_grant_id" => capability_grant_id,
      "consent_epoch" => consent.consent_epoch,
      "frame_generation" => frame_generation
    }
    |> Map.merge(extra)
    |> URI.encode_query()
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

  defp hash(value), do: Hash.blake3_base64url(value)
end
