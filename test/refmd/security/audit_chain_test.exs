defmodule RefMD.Security.AuditChainTest do
  use RefMD.DataCase, async: false

  import Ecto.Query

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.AuditEvent
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

    assert %{chain_scope: ^chain_scope, sequence: 1, event_hash: ^event_hash} =
             Security.current_audit_checkpoint!(chain_scope)

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
    assert is_nil(first.previous_event_hash)
    assert second.sequence == 2
    assert second.previous_event_hash == first.event_hash

    assert first.event_hash ==
             Hash.blake3_base64url(
               JCS.canonical_bytes!(
                 compact(%{
                   "protocol" => "refmd.security-audit-chain",
                   "version" => 1,
                   "chain_scope" => first.chain_scope,
                   "sequence" => 1,
                   "class" => first.class,
                   "type" => first.type,
                   "actor" => first.actor,
                   "scope" => first.scope,
                   "resource" => first.resource,
                   "action" => first.action,
                   "sensitivity" => first.sensitivity,
                   "correlation" => first.correlation
                 })
               )
             )

    assert {:ok, %{sequence: 2, event_hash: event_hash}} =
             Security.verify_audit_chain(first.chain_scope)

    assert %{
             chain_scope: first_chain_scope,
             sequence: 2,
             event_hash: ^event_hash,
             authority_checkpoint: nil
           } = Security.current_audit_checkpoint(first.chain_scope)

    assert first_chain_scope == first.chain_scope

    assert [first_ancestor, second_ancestor] =
             Security.current_audit_checkpoint(first.chain_scope).ancestry

    assert first_ancestor.protocol == "refmd.security-audit-chain"
    assert first_ancestor.version == 1
    assert first_ancestor.event_hash == first.event_hash
    assert second_ancestor.protocol == "refmd.security-audit-chain"
    assert second_ancestor.version == 1
    assert second_ancestor.event_hash == second.event_hash
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
      Security.current_audit_checkpoint!(event.chain_scope)
    end
  end

  test "notification payload binds the verified audit checkpoint and fails closed on tampering" do
    user_id = Ecto.UUID.generate()

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
    assert checkpoint.chain_scope == event.chain_scope
    assert checkpoint.sequence == event.sequence
    assert checkpoint.event_hash == event.event_hash

    Repo.update_all(from(e in AuditEvent, where: e.id == ^event.id),
      set: [type: "device.rejected"]
    )

    assert_raise RuntimeError, "security audit chain verification failed", fn ->
      Security.notification_payload(notification)
    end
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
      resource: %{"kind" => "user", "id" => user_id, "version_hash" => nil},
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

  defp compact(%{} = value) do
    value
    |> Enum.reject(fn {_key, nested} -> is_nil(nested) end)
    |> Map.new(fn {key, nested} -> {key, compact(nested)} end)
  end

  defp compact(value) when is_list(value), do: Enum.map(value, &compact/1)
  defp compact(value), do: value
end
