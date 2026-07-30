defmodule RefMD.Encryption.KeyDirectory.AuthorityAuditCheckpointTest do
  use RefMD.DataCase, async: true

  alias RefMD.Encryption.KeyDirectory.{Authority, Event}
  alias RefMD.Repo

  test "uses the member authority at the referenced event head" do
    workspace_id = Ecto.UUID.generate()
    user_id = Ecto.UUID.generate()

    insert_authority_event!(workspace_id, 1, "member_added", %{
      "user_id" => user_id,
      "base_role" => "owner"
    })

    insert_authority_event!(workspace_id, 2, "member_role_changed", %{
      "user_id" => user_id,
      "previous_base_role" => "owner",
      "new_base_role" => "viewer"
    })

    actor = %{
      "signer_kind" => "device",
      "user_id" => user_id,
      "device_id" => Ecto.UUID.generate()
    }

    assert :ok =
             Authority.assert_audit_checkpoint_authority!(
               workspace_id,
               1,
               "workspace.member.added",
               actor
             )

    assert_raise ArgumentError, "audit_checkpoint_authority_unverified", fn ->
      Authority.assert_audit_checkpoint_authority!(
        workspace_id,
        2,
        "workspace.member.added",
        actor
      )
    end

    assert :ok =
             Authority.assert_audit_checkpoint_authority!(
               workspace_id,
               2,
               "workspace.identity_self_envelope_rewrap.completed",
               actor
             )
  end

  defp insert_authority_event!(workspace_id, sequence, event_type, body) do
    now = DateTime.utc_now()

    Repo.insert_all(Event, [
      %{
        id: Ecto.UUID.generate(),
        scope_kind: "workspace",
        scope_id: workspace_id,
        sequence: sequence,
        event_type: event_type,
        event_hash: "event-hash-#{sequence}",
        event_body_hash: "event-body-hash-#{sequence}",
        previous_event_hash: if(sequence == 1, do: nil, else: "event-hash-#{sequence - 1}"),
        payload: %{
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "sequence" => sequence,
          "event_type" => event_type,
          "actor" => %{"signer_kind" => "device", "user_id" => Ecto.UUID.generate()},
          "body" => body
        },
        signatures: [%{"test" => true}],
        inserted_at: now,
        updated_at: now
      }
    ])
  end
end
