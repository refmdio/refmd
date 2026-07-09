defmodule RefMDWeb.KeyDirectoryControllerTest do
  use RefMDWeb.ConnCase, async: true

  alias Plug.Conn.Query
  alias RefMD.{Auth, Repo, Workspaces}
  alias RefMD.Crypto.{Hash, JCS, Signature, Suite}
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Users.User

  import RefMD.TestCrypto

  test "latest returns ancestry sliced from the client checkpoint anchor", %{conn: conn} do
    owner_id = create_user("owner-key-directory-latest@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "Key Directory Latest")
    device = create_device(owner_id)
    insert_initial_workspace_key_directory!(workspace, owner_id, device)
    first = KeyDirectory.current_checkpoint("workspace", workspace.id)

    second = append_suite_policy_event!(workspace.id, owner_id, device)
    third = append_suite_policy_event!(workspace.id, owner_id, device)

    path = "/api/workspaces/#{workspace.id}/key-directory/latest"

    query = %{
      "checkpoint_sequence" => second.sequence,
      "checkpoint_hash" => second.checkpoint_hash,
      "event_head_sequence" => second.covered_event_head_sequence,
      "event_head_hash" => second.covered_event_head_hash
    }

    query_string = Query.encode(query)

    conn =
      conn
      |> authed_conn(owner_id, device.device)
      |> with_rrp_headers(
        owner_id,
        device.device,
        device.signing_private_key,
        "GET",
        path,
        "",
        query_string
      )
      |> get(path, query)

    body = json_response(conn, 200)
    assert get_in(body, ["checkpoint", "payload", "sequence"]) == third.sequence
    assert get_in(body, ["pin", "checkpoint_sequence"]) == third.sequence

    assert [%{"payload" => %{"sequence" => sequence}}] = body["checkpoint_ancestry"]
    assert sequence == second.sequence

    refute Enum.any?(
             body["checkpoint_ancestry"],
             &(get_in(&1, ["payload", "sequence"]) == first.sequence)
           )

    assert [%{"payload" => %{"sequence" => event_sequence}}] = body["event_ancestry"]
    assert event_sequence == third.covered_event_head_sequence
    assert body["events"] == body["event_ancestry"]
  end

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

  defp insert_initial_workspace_key_directory!(workspace, owner_id, device) do
    identity_private = hybrid_signing_private_key_material("identity", owner_id)
    {identity_ecdh_public_key, _identity_ecdh_private_key} = :crypto.generate_key(:ecdh, :x25519)

    identity_encryption =
      hybrid_encryption_public_key_material("identity", owner_id, identity_ecdh_public_key)

    bootstrap =
      initial_key_directory_bootstrap(
        owner_id,
        workspace.id,
        owner_role_id(workspace.id),
        identity_private,
        identity_encryption.public,
        device.signing_private_key,
        device.device.hybrid_encryption_public_key_material
      )

    KeyDirectory.insert_signed_initial_scope!(
      "workspace",
      workspace.id,
      bootstrap.workspace_events,
      bootstrap.workspace_checkpoint,
      checkpoint_signer_kind: "device"
    )
  end

  defp append_suite_policy_event!(workspace_id, user_id, device) do
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    policy = Suite.current_suite_policy()
    public_material = hybrid_signing_public_key_material(device.signing_private_key)
    signing_key_id = Signature.compute_signing_key_id!(public_material)
    actor = device_actor(user_id, device.device.id, signing_key_id)

    event =
      key_directory_event_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => pin.event_head_sequence + 1,
        "event_type" => "suite_policy_changed",
        "actor" => actor,
        "previous_event_hash" => pin.event_head_hash,
        "body" => %{
          "suite_policy_version" => policy["suite_policy_version"],
          "min_suite_rank" => policy["min_suite_rank"],
          "allowed_suite_ids" => policy["allowed_suite_ids"]
        }
      })

    checkpoint_payload =
      checkpoint.payload
      |> Map.put("sequence", checkpoint.sequence + 1)
      |> Map.put(
        "issued_at",
        DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
      )
      |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
      |> Map.put("covered_event_head", key_directory_event_head(event))
      |> key_directory_checkpoint_payload!()

    %{checkpoint: appended} =
      KeyDirectory.append_signed_scope!(
        "workspace",
        workspace_id,
        [signed_key_directory_event_envelope(event, device.signing_private_key)],
        signed_key_directory_checkpoint_envelope(
          checkpoint_payload,
          "workspace_authorized",
          device.signing_private_key,
          user_id
        ),
        checkpoint_signer_kind: "device"
      )

    appended
  end

  defp owner_role_id(workspace_id) do
    workspace_id
    |> Workspaces.list_workspace_roles()
    |> Enum.find(&(&1.base_role == "owner"))
    |> Map.fetch!(:id)
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

  defp device_actor(user_id, device_id, signing_key_id) do
    %{
      "signer_kind" => "device",
      "user_id" => user_id,
      "device_id" => device_id,
      "signing_key_id" => signing_key_id
    }
  end

  defp key_directory_event_payload!(attrs) do
    attrs
    |> put_initial_event_actor_authority()
    |> Map.put_new("authority_boundary", key_directory_event_authority_boundary(attrs))
    |> KeyDirectory.build_event_payload!()
  end

  defp put_initial_event_actor_authority(
         %{
           "actor" => actor,
           "sequence" => sequence,
           "scope_kind" => scope_kind,
           "scope_id" => scope_id
         } =
           attrs
       )
       when is_map(actor) and is_integer(sequence) and sequence > 1 do
    if Map.has_key?(actor, "key_checkpoint_sequence") and
         Map.has_key?(actor, "key_checkpoint_hash") do
      attrs
    else
      Map.put(
        attrs,
        "actor",
        Map.merge(actor, initial_event_actor_authority(scope_kind, scope_id))
      )
    end
  end

  defp put_initial_event_actor_authority(attrs), do: attrs

  defp initial_event_actor_authority(scope_kind, scope_id) do
    %{
      "key_scope_kind" => scope_kind,
      "key_scope_id" => scope_id,
      "key_checkpoint_sequence" => 1,
      "key_checkpoint_hash" =>
        Hash.blake3_base64url(
          JCS.canonical_bytes!(%{
            "protocol" => "refmd.initial-key-directory-authority",
            "version" => 1,
            "scope_kind" => scope_kind,
            "scope_id" => scope_id
          })
        )
    }
  end

  defp key_directory_event_authority_boundary(attrs) do
    %{
      "scope_kind" => Map.fetch!(attrs, "scope_kind"),
      "scope_id" => Map.fetch!(attrs, "scope_id"),
      "checkpoint_sequence" =>
        Map.get(attrs, "checkpoint_sequence", Map.fetch!(attrs, "sequence")),
      "checkpoint_hash" =>
        Map.get(attrs, "checkpoint_hash", Hash.blake3_base64url("test-checkpoint")),
      "required_authority" => "event_type_authorized_actor"
    }
  end

  defp key_directory_checkpoint_payload!(attrs) do
    attrs
    |> Map.put("authority_boundary", key_directory_checkpoint_authority_boundary(attrs))
    |> KeyDirectory.build_checkpoint_payload!()
  end

  defp key_directory_checkpoint_authority_boundary(%{"sequence" => 1}) do
    %{"required_authority" => "tofu_root"}
  end

  defp key_directory_checkpoint_authority_boundary(_attrs) do
    %{"required_authority" => "checkpoint_authorized"}
  end
end
