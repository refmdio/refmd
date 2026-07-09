defmodule RefMD.Devices.Revocations do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.Signature
  alias RefMD.Devices.{Device, DeviceRevocationEvent}
  alias RefMD.Encryption
  alias RefMD.Repo

  @revocation_signature_ttl_ms 5 * 60 * 1000

  def revoke_device(
        user_id,
        device_id,
        revoked_by_device_id,
        revocation_mode,
        revocation_signature,
        revoked_at_ms,
        key_directory
      ) do
    with :ok <-
           verify_revocation_request(
             user_id,
             device_id,
             revocation_mode,
             revoked_by_device_id,
             revoked_at_ms,
             revocation_signature,
             key_directory
           ) do
      now = DateTime.utc_now()

      with_serializable_retry(fn ->
        check_retire_preconditions!(user_id, revocation_mode)
        device = get_active_target_device!(user_id, device_id)
        assert_revocation_signer_still_active!(user_id, revoked_by_device_id)
        append_revocation_key_directory!(user_id, device, revocation_mode, key_directory)
        mark_device_revoked(user_id, device_id, now)
        cleanup_sessions(user_id, device_id, revocation_mode)
        invalidate_transient_state(device_id)

        insert_revocation_event(
          user_id,
          device_id,
          revoked_by_device_id,
          revocation_mode,
          revocation_signature,
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
  end

  defp verify_revocation_request(
         user_id,
         device_id,
         revocation_mode,
         revoked_by_device_id,
         revoked_at_ms,
         revocation_signature,
         key_directory
       ) do
    case verify_revocation_signature(
           user_id,
           device_id,
           revocation_mode,
           revoked_by_device_id,
           revoked_at_ms,
           revocation_signature,
           key_directory
         ) do
      true -> :ok
      {:error, reason} -> {:error, reason}
      _ -> {:error, :invalid_signature}
    end
  end

  defp verify_revocation_signature(
         user_id,
         device_id,
         revocation_mode,
         revoked_by_device_id,
         revoked_at_ms,
         revocation_signature,
         key_directory
       ) do
    with true <- valid_revocation_timestamp?(revoked_at_ms),
         {:ok, signature} <- decode_hybrid_signature(revocation_signature),
         {:ok, signer} <- get_active_signer_device(user_id, revoked_by_device_id),
         signing_key_id <-
           Signature.compute_signing_key_id!(signer.hybrid_signing_public_key_material),
         :ok <-
           active_signer_in_key_directory?(
             key_directory,
             user_id,
             revoked_by_device_id,
             signing_key_id,
             signer.hybrid_signing_public_key_material
           ),
         target <- get_active_target_device!(user_id, device_id),
         transcript <-
           Signature.build_device_revocation_transcript!(
             user_id,
             revoked_by_device_id,
             signing_key_id,
             device_id,
             revocation_mode,
             revoked_at_ms
           ) do
      Signature.verify_hybrid_signature(
        "device_revocation",
        transcript,
        signature,
        signer.hybrid_signing_public_key_material,
        %{
          signer: %{
            id: signer.id,
            revoked_at: signer.revoked_at,
            signing_key_id: signing_key_id
          },
          target_device: %{
            id: target.id,
            signing_key_id: target.signing_key_id
          }
        }
      )
    else
      {:error, reason} -> {:error, reason}
      _ -> false
    end
  rescue
    ArgumentError -> false
  end

  # ── Private Helpers ─────────────────────────────

  defp get_active_target_device!(user_id, device_id) do
    case Repo.get(Device, device_id) do
      %{user_id: ^user_id, revoked_at: nil} = device -> device
      _ -> Repo.rollback(:already_revoked)
    end
  end

  defp valid_revocation_timestamp?(timestamp_ms) when is_integer(timestamp_ms) do
    abs(System.system_time(:millisecond) - timestamp_ms) <= @revocation_signature_ttl_ms
  end

  defp valid_revocation_timestamp?(_), do: false

  defp decode_hybrid_signature(signature) when is_map(signature), do: {:ok, signature}

  defp decode_hybrid_signature(_), do: {:error, :invalid_signature}

  defp get_active_signer_device(user_id, device_id) do
    case Repo.get(Device, device_id) do
      %{user_id: ^user_id, revoked_at: nil} = device -> {:ok, device}
      _ -> {:error, :invalid_signer_device}
    end
  end

  defp active_signer_in_key_directory?(
         _key_directory,
         user_id,
         device_id,
         signing_key_id,
         material
       ) do
    with {:ok, entry_material} <-
           Encryption.active_user_key_material_in_current_checkpoint(user_id, signing_key_id),
         true <- entry_material == material,
         true <- entry_material["owner_kind"] == "device",
         true <- entry_material["owner_id"] == device_id do
      :ok
    else
      _ -> {:error, :inactive_revocation_signer}
    end
  end

  defp assert_revocation_signer_still_active!(user_id, revoked_by_device_id) do
    with {:ok, signer} <- get_active_signer_device(user_id, revoked_by_device_id),
         signing_key_id <-
           Signature.compute_signing_key_id!(signer.hybrid_signing_public_key_material),
         :ok <-
           active_signer_in_key_directory?(
             %{},
             user_id,
             revoked_by_device_id,
             signing_key_id,
             signer.hybrid_signing_public_key_material
           ) do
      :ok
    else
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  @serializable_max_retries 3

  defp with_serializable_retry(fun, attempt \\ 1) do
    Repo.transaction(fn -> fun.() end, isolation: :serializable)
  rescue
    e in Postgrex.Error ->
      serializable_error? =
        e.postgres != nil and
          e.postgres.code in [
            "40001",
            "40P01",
            :serialization_failure,
            :deadlock_detected
          ]

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

  defp append_revocation_key_directory!(
         user_id,
         device,
         revocation_mode,
         %{
           user_events: user_events,
           user_checkpoint: user_checkpoint,
           workspace_appends: workspace_appends
         }
       )
       when is_list(user_events) and is_map(user_checkpoint) and is_list(workspace_appends) do
    assert_device_key_revoked_append!(
      user_events,
      device.signing_key_id,
      device.encryption_key_id,
      revocation_mode
    )

    Encryption.append_user_key_directory!(
      user_id,
      user_events,
      user_checkpoint,
      checkpoint_signer_kind: "identity"
    )

    expected_workspace_ids =
      user_id
      |> RefMD.Workspaces.get_user_workspace_ids()
      |> Enum.sort()

    actual_workspace_ids =
      workspace_appends
      |> Enum.map(&Map.get(&1, "workspace_id"))
      |> Enum.sort()

    if actual_workspace_ids != expected_workspace_ids do
      raise ArgumentError, "key_directory_workspace_append_set_mismatch"
    end

    Enum.each(workspace_appends, fn %{
                                      "workspace_id" => workspace_id,
                                      "events" => events,
                                      "checkpoint" => checkpoint
                                    } ->
      assert_device_key_revoked_append!(
        events,
        device.signing_key_id,
        device.encryption_key_id,
        revocation_mode
      )

      Encryption.append_workspace_key_directory!(
        workspace_id,
        events,
        checkpoint,
        checkpoint_signer_kind: "device"
      )
    end)
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  defp append_revocation_key_directory!(_, _, _, _), do: Repo.rollback(:missing_key_directory)

  defp assert_device_key_revoked_append!(
         [
           %{"payload" => %{"event_type" => first_type, "body" => first_body}},
           %{"payload" => %{"event_type" => second_type, "body" => second_body}}
         ],
         signing_key_id,
         encryption_key_id,
         revocation_mode
       ) do
    events =
      [
        {first_type, first_body},
        {second_type, second_body}
      ]
      |> Map.new()

    signing_body = Map.get(events, "signing_key_revoked")
    encryption_body = Map.get(events, "encryption_key_revoked")

    expected_signing = %{
      "key_id" => signing_key_id,
      "reason" => revocation_mode
    }

    expected_encryption = %{
      "key_id" => encryption_key_id,
      "reason" => revocation_mode
    }

    if body_matches_revocation?(signing_body, expected_signing) and
         body_matches_revocation?(encryption_body, expected_encryption) do
      :ok
    else
      raise ArgumentError, "key_directory_revocation_event_mismatch"
    end
  end

  defp assert_device_key_revoked_append!(_, _, _, _),
    do: raise(ArgumentError, "key_directory_revocation_event_mismatch")

  defp body_matches_revocation?(body, expected) when is_map(body) do
    Map.take(body, ["key_id", "reason"]) == expected
  end

  defp body_matches_revocation?(_, _), do: false

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
    RefMD.Auth.delete_device_rrp_challenges(device_id)
  end

  defp disconnect_ws(user_id, _device_id, "security") do
    Phoenix.PubSub.broadcast(
      RefMD.PubSub,
      "user_socket:#{user_id}",
      %Phoenix.Socket.Broadcast{
        topic: "user_socket:#{user_id}",
        event: "disconnect",
        payload: %{}
      }
    )
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
         revocation_signature,
         revoked_at_ms,
         now
       ) do
    case %DeviceRevocationEvent{created_at: now}
         |> DeviceRevocationEvent.changeset(%{
           user_id: user_id,
           device_id: device_id,
           revoked_by_device_id: revoked_by_device_id,
           revocation_mode: revocation_mode,
           signature: revocation_signature,
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

    RefMD.Workspaces.revoke_all_active_access_invitations(ws_ids)
    RefMD.Workspaces.mark_kek_rotation_needed(ws_ids, user_id)
    RefMD.Workspaces.mark_dek_rotation_needed(ws_ids)

    Enum.map(ws_with_versions, fn {id, version} ->
      %{workspace_id: id, current_kek_version: version}
    end)
  end

  defp handle_security_rotation(_user_id, _revocation_mode), do: []
end
