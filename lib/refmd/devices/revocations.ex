defmodule RefMD.Devices.Revocations do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Devices.{Device, DeviceRevocationEvent}
  alias RefMD.Repo

  @spec revoke_device(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          String.t(),
          binary(),
          integer()
        ) ::
          {:ok, map()} | {:error, atom() | {atom(), Ecto.Changeset.t()}}
  def revoke_device(
        user_id,
        device_id,
        revoked_by_device_id,
        revocation_mode,
        identity_signature,
        revoked_at_ms
      ) do
    now = DateTime.utc_now()

    with_serializable_retry(fn ->
      check_retire_preconditions!(user_id, revocation_mode)
      mark_device_revoked(user_id, device_id, now)
      cleanup_sessions(user_id, device_id, revocation_mode)
      invalidate_transient_state(device_id)

      insert_revocation_event(
        user_id,
        device_id,
        revoked_by_device_id,
        revocation_mode,
        identity_signature,
        revoked_at_ms,
        now
      )

      workspaces_for_rotation = handle_security_rotation(user_id, revocation_mode)

      %{workspaces_needing_kek_rotation: workspaces_for_rotation}
    end)
    |> case do
      {:ok, result} ->
        disconnect_ws(user_id, device_id, revocation_mode)
        {:ok, result}

      error ->
        error
    end
  end

  @spec verify_revocation_signature(
          Ecto.UUID.t(),
          Ecto.UUID.t(),
          String.t(),
          Ecto.UUID.t(),
          integer(),
          binary()
        ) ::
          boolean() | {:error, :identity_key_not_found}
  def verify_revocation_signature(
        user_id,
        device_id,
        revocation_mode,
        revoked_by_device_id,
        revoked_at_ms,
        identity_signature
      ) do
    with {:ok, signing_pub} <- get_identity_signing_public_key(user_id) do
      message =
        build_revocation_signature_message(
          user_id,
          device_id,
          revocation_mode,
          revoked_at_ms,
          revoked_by_device_id
        )

      RefMD.Crypto.verify_ed25519_signature(message, identity_signature, signing_pub)
    end
  end

  # ── Private Helpers ─────────────────────────────

  @serializable_max_retries 3

  defp with_serializable_retry(fun, attempt \\ 1) do
    Repo.transaction(fn ->
      Repo.query!("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
      fun.()
    end)
  rescue
    e in Postgrex.Error ->
      serializable_error? =
        e.postgres != nil and e.postgres.code in ["40001", "40P01"]

      if serializable_error? and attempt < @serializable_max_retries do
        Process.sleep(Enum.random(5..25))
        with_serializable_retry(fun, attempt + 1)
      else
        if serializable_error? do
          {:error, :serialization_conflict}
        else
          reraise e, __STACKTRACE__
        end
      end
  end

  defp mark_device_revoked(user_id, device_id, now) do
    case from(d in Device,
           where: d.id == ^device_id and d.user_id == ^user_id and is_nil(d.revoked_at)
         )
         |> Repo.update_all(set: [revoked_at: now]) do
      {1, _} -> :ok
      {0, _} -> Repo.rollback(:already_revoked)
    end
  end

  defp check_retire_preconditions!(user_id, "retire") do
    if RefMD.Auth.has_unbound_sessions?(user_id) do
      Repo.rollback(:retire_blocked_by_unbound_sessions)
    end
  end

  defp check_retire_preconditions!(_user_id, _mode), do: :ok

  defp cleanup_sessions(user_id, device_id, "security") do
    RefMD.Auth.delete_device_and_unbound_sessions(user_id, device_id)
  end

  defp cleanup_sessions(_user_id, device_id, _mode) do
    RefMD.Auth.delete_device_sessions(device_id)
  end

  defp invalidate_transient_state(device_id) do
    RefMD.Auth.delete_device_pop_challenges(device_id)
    RefMD.Auth.delete_device_trust_transfer_data(device_id)
  end

  defp disconnect_ws(user_id, _device_id, "security") do
    RefMDWeb.Endpoint.broadcast("user_socket:#{user_id}", "disconnect", %{})
  end

  defp disconnect_ws(user_id, device_id, _mode) do
    Phoenix.PubSub.broadcast(
      RefMD.PubSub,
      "device_revocation:#{user_id}",
      {:device_revoked, device_id}
    )
  end

  defp insert_revocation_event(
         user_id,
         device_id,
         revoked_by_device_id,
         revocation_mode,
         identity_signature,
         revoked_at_ms,
         now
       ) do
    case %DeviceRevocationEvent{created_at: now}
         |> DeviceRevocationEvent.changeset(%{
           user_id: user_id,
           device_id: device_id,
           revoked_by_device_id: revoked_by_device_id,
           revocation_mode: revocation_mode,
           signature: identity_signature,
           revoked_at: revoked_at_ms
         })
         |> Repo.insert() do
      {:ok, event} -> event
      {:error, changeset} -> Repo.rollback({:event_insert_failed, changeset})
    end
  end

  defp handle_security_rotation(user_id, "security") do
    ws_with_versions = RefMD.Workspaces.get_user_workspace_ids_with_kek_version(user_id)
    ws_ids = Enum.map(ws_with_versions, &elem(&1, 0))

    RefMD.Workspaces.revoke_all_active_invitations(ws_ids)
    RefMD.Workspaces.mark_kek_rotation_needed(ws_ids, user_id)
    RefMD.Workspaces.mark_dek_rotation_needed(ws_ids)

    Enum.map(ws_with_versions, fn {id, version} ->
      %{workspace_id: id, current_kek_version: version}
    end)
  end

  defp handle_security_rotation(_user_id, _revocation_mode), do: []

  defp get_identity_signing_public_key(user_id) do
    case RefMD.Encryption.get_user_identity_public_key(user_id) do
      nil -> {:error, :identity_key_not_found}
      key -> {:ok, key.signing_public_key}
    end
  end

  defp build_revocation_signature_message(
         user_id,
         device_id,
         revocation_mode,
         revoked_at_ms,
         revoked_by_device_id
       ) do
    RefMD.Crypto.build_signature_message("device_revocation", %{
      "device_id" => device_id,
      "revocation_mode" => revocation_mode,
      "revoked_at" => revoked_at_ms,
      "revoked_by_device_id" => revoked_by_device_id,
      "user_id" => user_id
    })
  end
end
