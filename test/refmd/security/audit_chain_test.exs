defmodule RefMD.Security.AuditChainTest do
  use RefMD.DataCase, async: false

  import Ecto.Query

  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.{AuditChainEvent, AuditEvent, SignedAuditCheckpoint}
  alias RefMD.TestCrypto
  alias RefMD.Users.User
  alias RefMD.Workspaces

  test "default workspace creation seeds a verifiable workspace audit genesis" do
    user =
      Repo.insert!(%User{
        id: Ecto.UUID.generate(),
        email: "workspace-audit-genesis-#{System.unique_integer([:positive])}@example.com",
        name: "Workspace Audit Genesis"
      })

    assert {:ok, workspace} = Workspaces.create_default_workspace(user.id, "Audit Genesis")
    chain_scope = "workspace:#{workspace.id}"

    assert {:ok, %{sequence: 1, event_hash: event_hash}} =
             Security.verify_audit_chain(chain_scope)

    assert %{sequence: 1, event_hash: ^event_hash} =
             Security.current_verified_audit_event_head!(chain_scope)

    assert [%AuditEvent{type: "workspace.created", sequence: 1}] =
             Repo.all(from(e in AuditEvent, where: e.chain_scope == ^chain_scope))
  end

  test "appends a verifiable user chain and exposes its checkpoint head" do
    user_id = Ecto.UUID.generate()

    assert {:ok, %{audit_event: first}} =
             Security.record_audit_event(audit_attrs(user_id, "recovery.started"))

    assert {:ok, %{audit_event: second}} =
             Security.record_audit_event(audit_attrs(user_id, "recovery.completed"))

    assert first.chain_scope == "user:#{user_id}"
    assert first.sequence == 1
    assert first.previous_event_hash == "GENESIS"
    assert second.sequence == 2
    assert second.previous_event_hash == first.event_hash

    assert first.event_hash ==
             first
             |> Map.from_struct()
             |> AuditChainEvent.build!()
             |> AuditChainEvent.hash!()

    assert {:ok, %{sequence: 2, event_hash: event_hash}} =
             Security.verify_audit_chain(first.chain_scope)

    assert %{sequence: 2, event_hash: ^event_hash} =
             Security.current_verified_audit_event_head(first.chain_scope)
  end

  test "serializes concurrent appends within one workspace scope" do
    workspace_id = Ecto.UUID.generate()

    1..8
    |> Task.async_stream(
      fn index -> Security.record_audit_event(workspace_audit_attrs(workspace_id, index)) end,
      max_concurrency: 8,
      ordered: false,
      timeout: 10_000
    )
    |> Enum.each(fn result -> assert {:ok, {:ok, %{audit_event: %AuditEvent{}}}} = result end)

    events =
      Repo.all(
        from(e in AuditEvent,
          where: e.chain_scope == ^"workspace:#{workspace_id}",
          order_by: [asc: e.sequence]
        )
      )

    assert Enum.map(events, & &1.sequence) == Enum.to_list(1..8)
    assert {:ok, %{sequence: 8}} = Security.verify_audit_chain("workspace:#{workspace_id}")
  end

  test "detects persisted event tampering" do
    user_id = Ecto.UUID.generate()

    {:ok, %{audit_event: event}} =
      Security.record_audit_event(audit_attrs(user_id, "device.approved"))

    Repo.update_all(from(e in AuditEvent, where: e.id == ^event.id),
      set: [type: "device.rejected"]
    )

    assert {:error, :audit_chain_invalid} = Security.verify_audit_chain(event.chain_scope)

    assert {:error, :audit_chain_invalid} =
             Security.record_audit_event(audit_attrs(user_id, "device.revoked"))

    assert Repo.aggregate(
             from(e in AuditEvent, where: e.chain_scope == ^event.chain_scope),
             :count
           ) == 1

    assert_raise RuntimeError, "security audit chain verification failed", fn ->
      Security.current_verified_audit_event_head!(event.chain_scope)
    end
  end

  test "notification payload binds the verified audit checkpoint and fails closed on tampering" do
    user_id = Ecto.UUID.generate()

    %{signed_checkpoint: signed_checkpoint} =
      TestCrypto.install_signed_audit_genesis!("user", user_id, user_id)

    assert {:ok, %{audit_event: event, notifications: [notification]}} =
             Security.record_audit_event(audit_attrs(user_id, "device.approved"), [
               %{
                 recipient_kind: "user",
                 recipient_id: user_id,
                 type: "device.approved",
                 severity: "info",
                 action_ref: %{device_id: Ecto.UUID.generate()},
                 dedupe_key: "device.approved:#{user_id}"
               }
             ])

    assert %{audit_checkpoint: checkpoint} = Security.notification_payload(notification)
    assert checkpoint.signed_checkpoint == SignedAuditCheckpoint.envelope(signed_checkpoint)

    assert checkpoint.current_event_head == %{
             sequence: event.sequence,
             event_hash: event.event_hash
           }

    assert [%{"sequence" => sequence, "event_hash" => event_hash}] = checkpoint.unsigned_tail
    assert sequence == event.sequence
    assert event_hash == event.event_hash

    Repo.update_all(from(e in AuditEvent, where: e.id == ^event.id),
      set: [type: "device.rejected"]
    )

    assert_raise ArgumentError, fn ->
      Security.notification_payload(notification)
    end
  end

  test "required pending registration notification marking rolls back the terminal audit" do
    user_id = Ecto.UUID.generate()
    registration_id = Ecto.UUID.generate()

    assert {:error, :pending_registration_notification_missing} =
             Security.record_registration_approved(user_id, registration_id,
               require_pending_notification: true
             )

    refute Repo.get_by(AuditEvent,
             chain_scope: "user:#{user_id}",
             type: "device.registration.approved"
           )

    refute Repo.get_by(RefMD.Security.Notification,
             recipient_kind: "pending_registration",
             recipient_id: registration_id,
             type: "device.registration_approved"
           )
  end

  test "rejects metadata outside the sensitive-data-free audit schema" do
    attrs = audit_attrs(Ecto.UUID.generate(), "recovery.started")

    assert {:error, changeset} =
             Security.record_audit_event(put_in(attrs, [:action, "recovery_phrase"], "secret"))

    assert "contains unsupported metadata fields" in errors_on(changeset).action
  end

  defp audit_attrs(user_id, type) do
    %{
      class: "authority",
      type: type,
      actor: %{
        "user_id" => user_id,
        "device_id" => Ecto.UUID.generate(),
        "session_id" => nil,
        "principal_kind" => "user",
        "principal_id" => user_id
      },
      scope: %{"workspace_id" => nil, "document_id" => nil, "share_id" => nil},
      resource: %{"kind" => "credential", "id" => user_id, "version_hash" => nil},
      action: %{"operation" => type, "result" => "completed", "reason_code" => nil},
      sensitivity: Security.empty_sensitivity(),
      correlation: %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => nil
      }
    }
  end

  defp workspace_audit_attrs(workspace_id, index) do
    audit_attrs(Ecto.UUID.generate(), "workspace.event.#{index}")
    |> put_in([:scope, "workspace_id"], workspace_id)
    |> put_in([:resource, "kind"], "workspace")
    |> put_in([:resource, "id"], workspace_id)
  end
end
