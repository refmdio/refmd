defmodule RefMDWeb.Channels.Document.EnvelopeTest do
  use RefMD.DataCase, async: true

  alias RefMD.Crypto.Hash
  alias RefMD.Documents.DocumentUpdate
  alias RefMDWeb.Channels.Document.Envelope

  defp socket(assigns) do
    %Phoenix.Socket{assigns: Map.new(assigns)}
  end

  defp snapshot_payload(events) do
    document_id = Ecto.UUID.generate()
    workspace_id = Ecto.UUID.generate()
    device_id = Ecto.UUID.generate()
    signing_key_id = "signing-key"
    checkpoint_hash = Hash.blake3_base64url("checkpoint")

    payload = %{
      "ciphertext" => Base.url_encode64(<<1, 2, 3>>, padding: false),
      "nonce" => Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false),
      "signature" => %{"alg" => "test", "sig" => "test"},
      "publicData" => %{
        "docId" => document_id,
        "signingKeyId" => signing_key_id,
        "snapshotId" => Ecto.UUID.generate(),
        "keyVersion" => 1,
        "parentSnapshotId" => "GENESIS",
        "parentProofHash" => "GENESIS",
        "parentSnapshotUpdateClocks" => %{},
        "ownerKind" => "device",
        "ownerId" => device_id,
        "authorityKind" => "workspace_device",
        "authorityId" => workspace_id,
        "authorityContextKey" => signing_key_id,
        "authorityScopeId" => workspace_id,
        "authorityPermissionVersion" => 1,
        "keyCheckpointSequence" => 1,
        "keyCheckpointHash" => checkpoint_hash
      },
      "admission" => %{
        "workspaceKeyDirectoryEvents" => events,
        "workspaceKeyDirectoryCheckpointAncestry" => [],
        "workspaceKeyDirectoryEventAncestry" => [],
        "workspaceKeyDirectoryCheckpoint" => %{
          "payload" => %{"sequence" => 2, "previous_checkpoint_hash" => checkpoint_hash},
          "signatures" => [%{}]
        }
      }
    }

    {payload,
     socket(
       document_id: document_id,
       document: %{workspace_id: workspace_id},
       device_id: device_id,
       device_signing_key_id: signing_key_id
     )}
  end

  test "snapshot envelope accepts multiple workspace admission events" do
    events = [
      %{
        "payload" => %{
          "body" => %{"previous_workspace_event_sequence" => 1},
          "event_type" => "document_write_session_admitted"
        }
      },
      %{"payload" => %{"event_type" => "document_snapshot_accepted"}}
    ]

    {payload, socket} = snapshot_payload(events)

    assert {:ok, parsed} = Envelope.parse_snapshot_envelope(payload, socket)
    assert parsed.admission["workspaceKeyDirectoryEvents"] == events
  end

  test "snapshot envelope rejects empty and non-map admission event lists" do
    {payload, socket} = snapshot_payload([])

    assert {:error, "invalid_workspaceKeyDirectoryEvents"} =
             Envelope.parse_snapshot_envelope(payload, socket)

    {payload, socket} = snapshot_payload([%{"payload" => %{}}, "bad"])

    assert {:error, "invalid_workspaceKeyDirectoryEvents"} =
             Envelope.parse_snapshot_envelope(payload, socket)
  end

  test "update formatter fails closed without hybrid signature" do
    update = %DocumentUpdate{
      document_id: Ecto.UUID.generate(),
      snapshot_id: Ecto.UUID.generate(),
      clock: 1,
      version: 2,
      signing_key_id: "signing-key",
      update_data: <<1, 2, 3>>,
      nonce: :crypto.strong_rand_bytes(24),
      key_version: 1,
      update_hash: "update-hash",
      hybrid_signature: nil,
      timestamp: System.system_time(:millisecond)
    }

    # Keep this intentional invalid-input call from becoming an Elixir 1.20 type warning.
    format_update = Map.fetch!(%{format_update: &Envelope.format_update/1}, :format_update)

    assert_raise ArgumentError, "hybrid_signature_required", fn ->
      format_update.(update)
    end

    assert_raise ArgumentError, "document_required", fn ->
      format_update.(%{
        update
        | hybrid_signature: %{"protocol" => "refmd.hybrid-signature"}
      })
    end
  end
end
