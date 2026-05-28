defmodule RefMD.Documents.AdmissionReplayTest do
  use RefMD.DataCase, async: true

  alias RefMD.Documents
  alias RefMD.Documents.Admission
  alias RefMD.Repo
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

  defp create_document(workspace_id, user_id, doc_type, parent_id \\ nil) do
    {:ok, document} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => doc_type,
        "parent_id" => parent_id,
        "title" => "Doc",
        "encrypted_title" => <<1, 2, 3>>,
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1,
        "created_by" => user_id
      })

    document
  end

  test "folder share scope removal invalidates descendant document write sessions" do
    user_id = create_user("admission-replay-folder-scope@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Replay Scope Workspace")
    folder = create_document(workspace.id, user_id, "folder")
    child = create_document(workspace.id, user_id, "document", folder.id)
    sibling = create_document(workspace.id, user_id, "document")
    share_id = Ecto.UUID.generate()

    event = %{
      event_type: "share_key_scope_removed",
      payload: %{
        "body" => %{
          "workspace_id" => workspace.id,
          "share_id" => share_id,
          "scope_kind" => "folder",
          "scope_id" => folder.id
        }
      }
    }

    attrs = %{public_data: %{"ownerKind" => "share_participant_device"}}
    session_payload = %{"actor" => %{"share_id" => share_id}}

    assert Admission.__test_write_session_invalidating_event?(
             event,
             child,
             attrs,
             session_payload
           )

    refute Admission.__test_write_session_invalidating_event?(
             event,
             sibling,
             attrs,
             session_payload
           )

    refute Admission.__test_write_session_invalidating_event?(
             event,
             child,
             attrs,
             %{"actor" => %{"share_id" => Ecto.UUID.generate()}}
           )
  end

  test "guest revocations invalidate matching share participant write sessions" do
    user_id = create_user("admission-replay-guest-revocation@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(user_id, "Replay Guest Workspace")
    folder = create_document(workspace.id, user_id, "folder")
    child = create_document(workspace.id, user_id, "document", folder.id)
    sibling = create_document(workspace.id, user_id, "document")
    share_id = Ecto.UUID.generate()
    guest_user_id = Ecto.UUID.generate()
    guest_device_id = Ecto.UUID.generate()
    signing_key_id = "guest-signing-key"

    attrs = %{public_data: %{"ownerKind" => "share_participant_device"}}

    session_payload = %{
      "actor" => %{
        "share_id" => share_id,
        "share_participant_principal_id" => guest_user_id,
        "share_participant_device_id" => guest_device_id,
        "signing_key_id" => signing_key_id
      }
    }

    grant_revoked =
      guest_grant_revoked_event(%{
        "workspace_id" => workspace.id,
        "guest_user_id" => guest_user_id,
        "scope_kind" => "folder",
        "scope_id" => folder.id
      })

    assert Admission.__test_write_session_invalidating_event?(
             grant_revoked,
             child,
             attrs,
             session_payload
           )

    refute Admission.__test_write_session_invalidating_event?(
             grant_revoked,
             sibling,
             attrs,
             session_payload
           )

    device_revoked =
      guest_device_revoked_event(%{
        "workspace_id" => workspace.id,
        "guest_user_id" => guest_user_id,
        "guest_device_id" => guest_device_id,
        "guest_signing_key_id" => signing_key_id
      })

    assert Admission.__test_write_session_invalidating_event?(
             device_revoked,
             child,
             attrs,
             session_payload
           )

    unrelated_device_revoked =
      guest_device_revoked_event(%{
        "workspace_id" => workspace.id,
        "guest_user_id" => guest_user_id,
        "guest_device_id" => Ecto.UUID.generate(),
        "guest_signing_key_id" => "other-key"
      })

    refute Admission.__test_write_session_invalidating_event?(
             unrelated_device_revoked,
             child,
             attrs,
             session_payload
           )
  end

  defp guest_grant_revoked_event(body) do
    %{
      event_type: "guest_grant_revoked",
      payload: %{
        "body" =>
          Map.merge(
            %{
              "guest_grant_id" => Ecto.UUID.generate(),
              "revoked_at_event_sequence" => 11,
              "reason" => "manual"
            },
            body
          )
      }
    }
  end

  defp guest_device_revoked_event(body) do
    %{
      event_type: "guest_device_revoked",
      payload: %{
        "body" =>
          Map.merge(
            %{
              "revoked_at_event_sequence" => 11,
              "reason" => "manual",
              "guest_encryption_key_id" => "guest-encryption-key"
            },
            body
          )
      }
    }
  end
end
