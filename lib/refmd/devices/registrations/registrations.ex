defmodule RefMD.Devices.Registrations do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Auth.Session
  alias RefMD.Crypto.{Encoding, Hash, JCS, Signature}
  alias RefMD.Devices.{Device, DeviceEncryptedUMK, DeviceRegistration}
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Security

  def user_owns_device_registration?(user_id, device_id) do
    now = DateTime.utc_now()

    from(dr in DeviceRegistration,
      where: dr.id == ^device_id and dr.user_id == ^user_id and dr.expires_at > ^now
    )
    |> Repo.exists?()
  end

  def create_device_registration(attrs) do
    now = DateTime.utc_now()
    expires_at = DateTime.add(now, 5 * 60, :second)

    Repo.transaction(fn ->
      reject_reused_device_id!(attrs.id)
      insert_device_registration!(attrs, now, expires_at)
    end)
    |> case do
      {:ok, registration} ->
        {:ok, registration}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:error, changeset}

      {:error, :device_id_reused} ->
        {:error, DeviceRegistration.changeset(%DeviceRegistration{}, Map.put(attrs, :id, nil))}
    end
  end

  defp reject_reused_device_id!(device_id) do
    if Repo.exists?(from(d in Device, where: d.id == ^device_id)) do
      Repo.rollback(:device_id_reused)
    end
  end

  defp insert_device_registration!(attrs, now, expires_at) do
    %DeviceRegistration{created_at: now, expires_at: expires_at}
    |> DeviceRegistration.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, registration} -> insert_initial_ake_prekey_sources!(registration, now)
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp insert_initial_ake_prekey_sources!(registration, now) do
    case insert_initial_ake_prekey_sources(registration, now) do
      :ok -> registration
      {:error, reason} -> Repo.rollback(reason)
    end
  end

  def get_valid_device_registration(id) do
    now = DateTime.utc_now()

    from(dr in DeviceRegistration,
      where: dr.id == ^id and dr.expires_at > ^now
    )
    |> Repo.one()
  end

  def get_user_device_registrations(user_id) do
    now = DateTime.utc_now()

    from(dr in DeviceRegistration,
      where: dr.user_id == ^user_id and dr.expires_at > ^now,
      order_by: [desc: :created_at]
    )
    |> Repo.all()
  end

  def get_device_registration_status(user_id, device_id) do
    case Repo.get(DeviceRegistration, device_id) do
      nil ->
        resolve_device_status(user_id, device_id)

      %{user_id: ^user_id} = dr ->
        if DateTime.compare(dr.expires_at, DateTime.utc_now()) == :gt do
          {:ok, "pending"}
        else
          {:ok, "expired"}
        end

      _ ->
        {:error, :not_found}
    end
  end

  def delete_device_registration(id) do
    from(dr in DeviceRegistration, where: dr.id == ^id)
    |> Repo.delete_all()
  end

  def replace_user_device_registration(user_id, session_id, attrs) do
    now = DateTime.utc_now()
    expires_at = DateTime.add(now, 5 * 60, :second)

    fn ->
      consume_registration_challenge_step!(session_id, attrs.pending_registration_challenge_hash)
      ensure_device_id_available_step!(attrs.id)
      removed_ids = replace_user_pending_registrations_step!(user_id, now)
      pending = insert_replacement_device_registration_step!(attrs, now, expires_at)
      insert_initial_ake_prekeys_step!(pending, now)
      RefMD.Auth.bind_device_registration_to_session(session_id, pending.id)

      %{removed_ids: removed_ids, pending: pending}
    end
    |> Repo.transaction()
    |> case do
      {:ok, result} ->
        {:ok, result}

      {:error, {step, reason}} ->
        {:error, step, reason, %{}}

      {:error, reason} ->
        {:error, :pending, reason, %{}}
    end
  end

  defp consume_registration_challenge_step!(session_id, challenge_hash) do
    case consume_registration_challenge!(session_id, challenge_hash) do
      {:ok, _} -> :ok
      {:error, reason} -> Repo.rollback({:registration_challenge, reason})
    end
  end

  defp ensure_device_id_available_step!(device_id) do
    if Repo.exists?(from(d in Device, where: d.id == ^device_id)) do
      Repo.rollback({:device_id_available, :device_id_reused})
    end
  end

  defp replace_user_pending_registrations_step!(user_id, now) do
    ids =
      from(dr in DeviceRegistration,
        where: dr.user_id == ^user_id and dr.expires_at > ^now,
        select: dr.id
      )
      |> Repo.all()

    if ids != [] do
      from(dr in DeviceRegistration, where: dr.id in ^ids)
      |> Repo.delete_all()
    end

    ids
  end

  defp insert_replacement_device_registration_step!(attrs, now, expires_at) do
    %DeviceRegistration{created_at: now, expires_at: expires_at}
    |> DeviceRegistration.changeset(attrs)
    |> Repo.insert()
    |> case do
      {:ok, pending} -> pending
      {:error, changeset} -> Repo.rollback({:pending, changeset})
    end
  end

  defp insert_initial_ake_prekeys_step!(pending, now) do
    case insert_initial_ake_prekey_sources(pending, now) do
      :ok -> :ok
      {:error, reason} -> Repo.rollback({:initial_ake_prekeys, reason})
    end
  end

  defp consume_registration_challenge!(session_id, challenge_hash)
       when is_binary(challenge_hash) do
    now = DateTime.utc_now()

    case lock_session_registration_challenge(session_id) do
      %Session{
        pending_registration_challenge_hash: ^challenge_hash,
        pending_registration_challenge_expires_at: expires_at,
        pending_registration_challenge_consumed_at: nil
      }
      when not is_nil(expires_at) ->
        if DateTime.compare(expires_at, now) == :gt do
          consume_registration_challenge_row(session_id, challenge_hash, now)
        else
          {:error, :invalid_registration_challenge}
        end

      _ ->
        {:error, :invalid_registration_challenge}
    end
  end

  defp consume_registration_challenge!(_, _), do: {:error, :invalid_registration_challenge}

  defp lock_session_registration_challenge(session_id) do
    from(s in Session,
      where: s.id == ^session_id,
      lock: "FOR UPDATE",
      limit: 1
    )
    |> Repo.one()
  end

  defp consume_registration_challenge_row(session_id, challenge_hash, now) do
    from(s in Session,
      where:
        s.id == ^session_id and
          s.pending_registration_challenge_hash == ^challenge_hash and
          is_nil(s.pending_registration_challenge_consumed_at)
    )
    |> Repo.update_all(set: [pending_registration_challenge_consumed_at: now])
    |> case do
      {1, _} -> {:ok, :consumed}
      _ -> {:error, :invalid_registration_challenge}
    end
  end

  def approve_device_registration(device_registration, approval_signature, opts \\ [])

  def approve_device_registration(device_registration, approval_signature, opts)
      when is_map(approval_signature) do
    with {:ok, approval_material} <-
           get_approval_public_material(device_registration.user_id, opts),
         :ok <-
           verify_device_approval_signature(
             device_registration,
             approval_signature,
             approval_material,
             opts
           ) do
      approve_verified_device_registration(
        device_registration,
        approval_signature,
        approval_material,
        opts
      )
    end
  end

  def approve_device_registration(_, _, _), do: {:error, :invalid_signature}

  defp approve_verified_device_registration(
         device_registration,
         approval_signature,
         approval_material,
         opts
       ) do
    if Keyword.get(opts, :is_recovery, false) do
      approve_recovery_device_registration(device_registration, approval_signature, opts)
    else
      persist_pending_delivery_approval(
        device_registration,
        approval_signature,
        Keyword.put(opts, :approval_public_material, approval_material)
      )
    end
  end

  defp approve_recovery_device_registration(device_registration, approval_signature, opts) do
    now = DateTime.utc_now()

    changeset =
      device_changeset_from_registration(device_registration, approval_signature, opts, now)

    key_directory =
      {:recovery_self_approval,
       Keyword.get(opts, :key_directory)
       |> normalize_recovery_key_directory()
       |> Map.put(:recovery_context, Keyword.fetch!(opts, :recovery_context))}

    insert_approved_device(device_registration, changeset, key_directory)
    |> case do
      {:ok, device} ->
        Security.record_device_registration_removed(device.user_id, device.id)
        {:ok, device}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def delete_expired_device_registrations do
    now = DateTime.utc_now()

    from(dr in DeviceRegistration, where: dr.expires_at < ^now)
    |> Repo.delete_all()
  end

  # ── Private Helpers ─────────────────────────────

  defp resolve_device_status(user_id, device_id) do
    case RefMD.Devices.get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} ->
        if RefMD.Devices.get_device_encrypted_umk(user_id, device_id) != nil do
          {:ok, "approved"}
        else
          {:ok, "pending"}
        end

      _ ->
        {:ok, "expired"}
    end
  end

  defp persist_pending_delivery_approval(device_registration, approval_signature, opts) do
    device_registration
    |> DeviceRegistration.changeset(%{
      approval_signature: approval_signature,
      approval_signature_surface: approval_signature_surface(opts),
      approval_proof: approval_proof(device_registration, opts),
      approval_delivery_commitments: approval_delivery_commitments(opts),
      approval_delivery_artifacts: approval_delivery_artifacts(opts),
      approval_key_directory: Keyword.get(opts, :key_directory)
    })
    |> Repo.update()
  end

  def finalize_pending_delivery(device_registration, umk_attrs, prekey_consumptions)
      when is_map(umk_attrs) and is_list(prekey_consumptions) do
    now = DateTime.utc_now()

    Repo.transaction(fn ->
      locked_registration =
        from(dr in DeviceRegistration,
          where: dr.id == ^device_registration.id and dr.expires_at > ^now,
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      if is_nil(locked_registration) do
        Repo.rollback(:invalid_device)
      end

      if is_nil(locked_registration.approval_signature) or
           is_nil(locked_registration.approval_key_directory) do
        Repo.rollback(:missing_pending_approval)
      end

      insert_pending_delivery_device!(locked_registration, umk_attrs, prekey_consumptions, now)
    end)
    |> case do
      {:ok, device} ->
        Security.record_device_registration_removed(device.user_id, device.id)
        {:ok, device}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def finalize_pending_delivery(_, _, _), do: {:error, :invalid_device}

  defp insert_pending_delivery_device!(locked_registration, umk_attrs, prekey_consumptions, now) do
    locked_registration
    |> pending_delivery_device_changeset(umk_attrs, now)
    |> Repo.insert()
    |> case do
      {:ok, device} ->
        finalize_pending_delivery_umk!(
          locked_registration,
          device,
          umk_attrs,
          prekey_consumptions,
          now
        )

      {:error, changeset} ->
        Repo.rollback(changeset)
    end
  end

  defp pending_delivery_device_changeset(locked_registration, umk_attrs, now) do
    device_changeset_from_registration(
      locked_registration,
      locked_registration.approval_signature,
      [
        is_recovery: false,
        approver_device_id: locked_registration.approval_proof["approving_owner_id"],
        approval_commitments: locked_registration.approval_delivery_commitments,
        approval_artifacts: approval_delivery_artifacts_from_umk_attrs(umk_attrs),
        approval_proof_override: locked_registration.approval_proof
      ],
      now
    )
  end

  defp approval_delivery_artifacts_from_umk_attrs(umk_attrs) do
    %{
      "umk_distribution_initial_delivery" => %{
        "initial_ake" => umk_attrs.initial_ake,
        "initial_key_delivery" => umk_attrs.initial_key_delivery
      },
      "trust_transfer_initial_delivery" => umk_attrs.device_state_delivery,
      "device_approval_kek_initial_deliveries" => umk_attrs.initial_kek_deliveries
    }
  end

  defp finalize_pending_delivery_umk!(
         locked_registration,
         device,
         umk_attrs,
         prekey_consumptions,
         now
       ) do
    insert_initial_ake_prekey_consumptions!(locked_registration, prekey_consumptions, now)

    append_approval_key_directory!(
      locked_registration,
      normalize_key_directory(locked_registration.approval_key_directory)
    )

    locked_registration
    |> pending_delivery_umk_attrs(umk_attrs)
    |> insert_pending_delivery_umk!(now)

    Repo.delete!(locked_registration)
    device
  end

  defp pending_delivery_umk_attrs(locked_registration, umk_attrs) do
    umk_attrs
    |> Map.put(:user_id, locked_registration.user_id)
    |> Map.put(:device_id, locked_registration.id)
  end

  defp insert_pending_delivery_umk!(umk_attrs, now) do
    %DeviceEncryptedUMK{created_at: now}
    |> DeviceEncryptedUMK.changeset(umk_attrs)
    |> Repo.insert()
    |> case do
      {:ok, _umk} -> :ok
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp insert_initial_ake_prekey_consumptions!(locked_registration, prekey_consumptions, now) do
    prekey_ids = Enum.map(prekey_consumptions, & &1.prekey_id)

    current_user_event_sequence =
      case current_user_event_sequence(locked_registration.user_id) do
        {:ok, sequence} -> sequence
        :error -> Repo.rollback(:key_directory_checkpoint_required)
      end

    {source_count, _} =
      from(p in "initial_ake_prekeys",
        where:
          p.prekey_id in ^prekey_ids and
            p.device_registration_id == ^dump_uuid!(locked_registration.id) and
            is_nil(p.consumed_at) and
            p.expires_event_sequence > ^current_user_event_sequence
      )
      |> Repo.update_all(set: [consumed_at: now])

    if source_count != length(prekey_consumptions) do
      Repo.rollback(:initial_ake_prekey_reused)
    end

    prekey_rows =
      Enum.map(prekey_consumptions, fn row ->
        row
        |> Map.put(:user_id, dump_uuid!(locked_registration.user_id))
        |> Map.put(:device_id, dump_uuid!(locked_registration.id))
        |> Map.put(:consumed_at, now)
      end)

    case Repo.insert_all("initial_ake_prekey_consumptions", prekey_rows, on_conflict: :nothing) do
      {count, _} when count == length(prekey_rows) ->
        :ok

      _ ->
        Repo.rollback(:initial_ake_prekey_reused)
    end
  end

  defp insert_initial_ake_prekey_sources(registration, now) do
    rows =
      registration
      |> initial_ake_prekey_source_rows(now)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq_by(&{&1.purpose, &1.prekey_id, &1.operation_id})

    if rows == [] do
      :ok
    else
      case Repo.insert_all("initial_ake_prekeys", rows, on_conflict: :nothing) do
        {count, _} when count == length(rows) -> :ok
        _ -> {:error, :invalid_initial_ake_prekey}
      end
    end
  end

  defp initial_ake_prekey_source_rows(registration, now) do
    (registration.ake_responder_prekeys || %{})
    |> Map.values()
    |> Enum.map(&Map.get(&1, "payload"))
    |> Enum.map(fn payload ->
      if is_map(payload) do
        %{
          prekey_id: payload["prekey_id"],
          operation_id: payload["operation_id"],
          purpose: payload["purpose"],
          user_id: dump_uuid!(registration.user_id),
          device_registration_id: dump_uuid!(registration.id),
          issued_at_event_sequence: payload["issued_at_event_sequence"],
          expires_event_sequence: payload["expires_event_sequence"],
          payload: payload,
          created_at: now
        }
      end
    end)
  end

  defp current_user_event_sequence(user_id) do
    case Encryption.current_user_key_directory_pin(user_id) do
      %{event_head_sequence: sequence} when is_integer(sequence) -> {:ok, sequence}
      _ -> :error
    end
  end

  defp dump_uuid!(value) when is_binary(value), do: Ecto.UUID.dump!(value)

  defp device_changeset_from_registration(device_registration, approval_signature, opts, now) do
    Device.changeset(%Device{last_seen_at: now, created_at: now}, %{
      id: device_registration.id,
      user_id: device_registration.user_id,
      name: device_registration.name,
      device_type: device_registration.device_type,
      hybrid_encryption_public_key_material:
        device_registration.hybrid_encryption_public_key_material,
      encryption_key_id: device_registration.encryption_key_id,
      hybrid_signing_public_key_material: device_registration.hybrid_signing_public_key_material,
      signing_key_id: device_registration.signing_key_id,
      client_nonce: device_registration.client_nonce,
      approval_signature: approval_signature,
      approval_signature_surface: approval_signature_surface(opts),
      approval_proof: approval_proof(device_registration, opts),
      approval_delivery_commitments: approval_delivery_commitments(opts),
      approval_delivery_artifacts: approval_delivery_artifacts(opts)
    })
  end

  defp insert_approved_device(device_registration, changeset, key_directory) do
    Repo.transaction(fn ->
      Repo.delete!(device_registration)

      case Repo.insert(changeset) do
        {:ok, device} ->
          append_approval_key_directory!(device_registration, key_directory)
          device

        {:error, changeset} ->
          Repo.rollback(changeset)
      end
    end)
  end

  defp append_approval_key_directory!(
         device_registration,
         %{
           user_events: user_events,
           user_checkpoint: user_checkpoint,
           workspace_appends: workspace_appends
         }
       )
       when is_list(user_events) and is_map(user_checkpoint) and is_list(workspace_appends) do
    assert_device_key_added_append!(
      user_events,
      device_registration.user_id,
      device_registration.id,
      device_registration.signing_key_id,
      device_registration.encryption_key_id
    )

    Encryption.append_user_key_directory!(
      device_registration.user_id,
      user_events,
      user_checkpoint,
      checkpoint_signer_kind: "identity"
    )

    expected_workspace_ids =
      device_registration.user_id
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
      assert_device_key_added_append!(
        events,
        device_registration.user_id,
        device_registration.id,
        device_registration.signing_key_id,
        device_registration.encryption_key_id
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

  defp append_approval_key_directory!(
         device_registration,
         {:recovery_self_approval,
          %{
            user_events: user_events,
            user_checkpoint: user_checkpoint,
            workspace_appends: workspace_appends,
            recovery_context: recovery_context
          }}
       )
       when is_list(user_events) and is_map(user_checkpoint) and is_list(workspace_appends) do
    assert_device_key_added_append!(
      user_events,
      device_registration.user_id,
      device_registration.id,
      device_registration.signing_key_id,
      device_registration.encryption_key_id
    )

    assert_recovery_target_checkpoint!(user_checkpoint, recovery_context)

    Encryption.append_user_key_directory!(
      device_registration.user_id,
      user_events,
      user_checkpoint,
      checkpoint_signer_kind: "identity"
    )

    expected_workspace_ids =
      device_registration.user_id
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
      assert_device_key_added_append!(
        events,
        device_registration.user_id,
        device_registration.id,
        device_registration.signing_key_id,
        device_registration.encryption_key_id
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

  defp append_approval_key_directory!(_, {:recovery_self_approval, _}),
    do: Repo.rollback(:missing_key_directory)

  defp append_approval_key_directory!(_, _), do: Repo.rollback(:missing_key_directory)

  defp assert_recovery_target_checkpoint!(checkpoint, recovery_context) when is_map(checkpoint) do
    payload =
      case checkpoint do
        %{"payload" => payload} when is_map(payload) -> payload
        %{} = payload -> payload
      end

    unless Map.fetch!(payload, "sequence") ==
             Map.fetch!(recovery_context, :target_key_checkpoint_sequence) and
             key_directory_checkpoint_hash(payload) ==
               Map.fetch!(recovery_context, :target_key_checkpoint_hash) do
      raise ArgumentError, "recovery_target_checkpoint_mismatch"
    end
  end

  defp normalize_key_directory(%{
         "user_events" => user_events,
         "user_checkpoint" => user_checkpoint,
         "workspace_appends" => workspace_appends
       }) do
    %{
      user_events: user_events,
      user_checkpoint: user_checkpoint,
      workspace_appends: workspace_appends
    }
  end

  defp normalize_key_directory(key_directory), do: key_directory

  defp normalize_recovery_key_directory(%{
         "user_events" => user_events,
         "user_checkpoint" => user_checkpoint,
         "workspace_appends" => workspace_appends
       }) do
    %{
      user_events: user_events,
      user_checkpoint: user_checkpoint,
      workspace_appends: workspace_appends
    }
  end

  defp normalize_recovery_key_directory(%{
         user_events: user_events,
         user_checkpoint: user_checkpoint,
         workspace_appends: workspace_appends
       }) do
    %{
      user_events: user_events,
      user_checkpoint: user_checkpoint,
      workspace_appends: workspace_appends
    }
  end

  defp normalize_recovery_key_directory(_), do: nil

  defp assert_device_key_added_append!(
         [%{"payload" => %{"event_type" => "device_key_added", "body" => body}}],
         user_id,
         device_id,
         signing_key_id,
         encryption_key_id
       ) do
    expected = %{
      "user_id" => user_id,
      "device_id" => device_id,
      "signing_key_id" => signing_key_id,
      "encryption_key_id" => encryption_key_id
    }

    if body == expected,
      do: :ok,
      else: raise(ArgumentError, "key_directory_device_event_mismatch")
  end

  defp assert_device_key_added_append!(_, _, _, _, _),
    do: raise(ArgumentError, "key_directory_device_event_mismatch")

  defp get_identity_public_material(user_id) do
    from(k in RefMD.Encryption.UserIdentityPublicKey,
      where: k.user_id == ^user_id,
      select: k.hybrid_signing_public_key_material,
      limit: 1
    )
    |> Repo.one()
    |> case do
      material when is_map(material) ->
        key_id = Signature.compute_signing_key_id!(material)

        case Encryption.active_user_key_material_in_current_checkpoint(user_id, key_id) do
          {:ok, ^material} -> {:ok, material}
          _ -> {:error, :identity_key_not_active}
        end

      _ ->
        {:error, :identity_key_not_found}
    end
  end

  defp get_approval_public_material(user_id, opts) do
    if Keyword.get(opts, :is_recovery, false) do
      get_identity_public_material(user_id)
    else
      get_approver_device_public_material(user_id, Keyword.fetch!(opts, :approver_device_id))
    end
  end

  defp get_approver_device_public_material(user_id, device_id) do
    from(d in Device,
      where: d.user_id == ^user_id and d.id == ^device_id and is_nil(d.revoked_at),
      select: d.hybrid_signing_public_key_material,
      limit: 1
    )
    |> Repo.one()
    |> case do
      material when is_map(material) ->
        key_id = Signature.compute_signing_key_id!(material)

        case Encryption.active_user_key_material_in_current_checkpoint(user_id, key_id) do
          {:ok, ^material} -> {:ok, material}
          _ -> {:error, :device_key_not_active}
        end

      _ ->
        {:error, :approver_device_key_not_found}
    end
  end

  defp approval_signature_surface(opts) do
    if Keyword.get(opts, :is_recovery, false),
      do: "recovery_device_approval",
      else: "device_approval"
  end

  defp approval_proof(device_registration, opts) do
    case Keyword.get(opts, :approval_proof_override) do
      proof when is_map(proof) ->
        proof

      _ ->
        {_purpose, transcript} = approval_transcript(device_registration, opts)

        approval_proof_from_transcript(
          device_registration,
          approval_signature_surface(opts),
          transcript,
          opts
        )
    end
  end

  defp approval_proof_from_transcript(device_registration, "device_approval", transcript, opts) do
    commitments =
      opts
      |> Keyword.get(:approval_commitments, %{})
      |> Map.merge(approval_binding_context!(device_registration, opts))

    Signature.build_device_approval_proof!("device_approval", transcript, %{
      "kind" => "device_approval",
      "pending_registration_id" => device_registration.id,
      "pending_registration_challenge_hash" =>
        device_registration.pending_registration_challenge_hash,
      "trust_transfer_delivery_commitment" => commitments["trust_transfer_delivery_commitment"],
      "umk_distribution_delivery_commitment" =>
        commitments["umk_distribution_delivery_commitment"],
      "device_approval_kek_initial_delivery_commitments" =>
        commitments["device_approval_kek_initial_delivery_commitments"],
      "approving_device_key_directory_proof_hash" =>
        commitments["approving_device_key_directory_proof_hash"],
      "approved_device_registration_sas_hash" =>
        commitments["approved_device_registration_sas_hash"]
    })
  end

  defp approval_proof_from_transcript(
         device_registration,
         "recovery_device_approval",
         transcript,
         opts
       ) do
    recovery_context = Keyword.fetch!(opts, :recovery_context)

    Signature.build_device_approval_proof!("recovery_device_approval", transcript, %{
      "kind" => "recovery_device_approval",
      "pending_registration_id" => device_registration.id,
      "pending_registration_challenge_hash" =>
        device_registration.pending_registration_challenge_hash,
      "recovery_session_transcript_hash" =>
        Map.fetch!(recovery_context, :recovery_session_transcript_hash),
      "recovery_capability_hash" => Map.fetch!(recovery_context, :recovery_capability_hash),
      "pending_registration_binding_hash" =>
        Map.fetch!(recovery_context, :pending_registration_binding_hash)
    })
  end

  defp approval_delivery_commitments(opts) do
    if Keyword.get(opts, :is_recovery, false),
      do: nil,
      else: Keyword.get(opts, :approval_commitments, %{})
  end

  defp approval_delivery_artifacts(opts) do
    if Keyword.get(opts, :is_recovery, false),
      do: nil,
      else: Keyword.get(opts, :approval_artifacts, %{})
  end

  defp verify_device_approval_signature(device_registration, signature, approval_material, opts) do
    {purpose, transcript} =
      approval_transcript(
        device_registration,
        Keyword.put(opts, :approval_public_material, approval_material)
      )

    case Signature.verify_hybrid_signature_result(
           purpose,
           transcript,
           signature,
           approval_material,
           approval_semantic_context(device_registration, approval_material, opts)
         ) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    ArgumentError -> {:error, :invalid_signature}
  end

  defp approval_semantic_context(device_registration, approval_material, opts) do
    target_device = %{
      id: device_registration.id,
      signing_key_id:
        device_registration.signing_key_id ||
          Signature.compute_signing_key_id!(
            device_registration.hybrid_signing_public_key_material
          ),
      user_id: device_registration.user_id
    }

    if Keyword.get(opts, :is_recovery, false) do
      recovery_context = Keyword.fetch!(opts, :recovery_context)

      %{
        recovery_session: recovery_context,
        target_device: target_device
      }
    else
      approver_device_id = Keyword.fetch!(opts, :approver_device_id)

      %{
        approver: %{
          id: approver_device_id,
          revoked_at: nil,
          signing_key_id: Signature.compute_signing_key_id!(approval_material)
        },
        target_device: target_device
      }
    end
  end

  defp approval_transcript(device_registration, opts) do
    if Keyword.get(opts, :is_recovery, false) do
      recovery_context = Keyword.fetch!(opts, :recovery_context)

      {"recovery_device_approval",
       Signature.build_recovery_device_approval_transcript!(%{
         user_id: device_registration.user_id,
         approving_signing_key_id:
           Signature.compute_signing_key_id!(Keyword.fetch!(opts, :approval_public_material)),
         approving_key_checkpoint_sequence:
           Map.fetch!(recovery_context, :candidate_user_checkpoint_sequence),
         approving_key_checkpoint_hash:
           Map.fetch!(recovery_context, :candidate_user_checkpoint_hash),
         pending_registration_id: device_registration.id,
         pending_registration_challenge_hash:
           device_registration.pending_registration_challenge_hash,
         recovery_session_transcript_hash:
           Map.fetch!(recovery_context, :recovery_session_transcript_hash),
         recovery_capability_hash: Map.fetch!(recovery_context, :recovery_capability_hash),
         pending_registration_binding_hash:
           Map.fetch!(recovery_context, :pending_registration_binding_hash),
         approved_device_id: device_registration.id,
         approved_device_public_material: device_registration.hybrid_signing_public_key_material,
         approved_device_hybrid_encryption_public_key_material:
           device_registration.hybrid_encryption_public_key_material,
         client_nonce: Encoding.encode_base64url(device_registration.client_nonce),
         target_key_checkpoint_sequence:
           Map.fetch!(recovery_context, :target_key_checkpoint_sequence),
         target_key_checkpoint_hash: Map.fetch!(recovery_context, :target_key_checkpoint_hash)
       })}
    else
      {"device_approval",
       Signature.build_device_approval_transcript!(
         device_registration.user_id,
         Keyword.fetch!(opts, :approver_device_id),
         device_registration.id,
         device_registration.hybrid_signing_public_key_material,
         device_registration.hybrid_encryption_public_key_material,
         Encoding.encode_base64url(device_registration.client_nonce),
         opts
         |> Keyword.get(:approval_commitments, %{})
         |> Map.merge(approval_binding_context!(device_registration, opts))
       )}
    end
  end

  defp approval_binding_context!(device_registration, opts) do
    key_directory = Keyword.fetch!(opts, :key_directory)
    target_checkpoint = Map.fetch!(key_directory, :user_checkpoint)
    target_payload = Map.fetch!(target_checkpoint, "payload")
    approving_pin = Encryption.current_user_key_directory_pin(device_registration.user_id)
    approval_material = Keyword.fetch!(opts, :approval_public_material)
    approver_device_id = Keyword.fetch!(opts, :approver_device_id)
    approval_commitments = Keyword.get(opts, :approval_commitments, %{})
    approval_proof = Keyword.get(opts, :approval_proof_override, %{})

    approval_details =
      case Map.get(approval_proof, "surface_details") do
        %{} = details ->
          details

        _ ->
          approval_commitments
      end

    approval_details =
      case Map.get(approval_details, "surface_details") do
        %{} = details -> details
        _ -> approval_details
      end

    %{
      "approved_device_registration_sas_hash" =>
        Map.fetch!(approval_details, "approved_device_registration_sas_hash"),
      "pending_registration_id" => device_registration.id,
      "pending_registration_challenge_hash" =>
        device_registration.pending_registration_challenge_hash,
      "approving_owner_kind" => "device",
      "approving_owner_id" => approver_device_id,
      "approving_signing_key_id" => Signature.compute_signing_key_id!(approval_material),
      "approving_key_checkpoint_sequence" => approving_pin.checkpoint_sequence,
      "approving_key_checkpoint_hash" => approving_pin.checkpoint_hash,
      "approving_device_key_directory_proof_hash" => approving_pin.checkpoint_hash,
      "target_device_id" => device_registration.id,
      "target_device_signing_key_id" => device_registration.signing_key_id,
      "target_device_hybrid_signing_public_key_material_hash" =>
        Hash.blake3_base64url(
          JCS.canonical_bytes!(device_registration.hybrid_signing_public_key_material)
        ),
      "target_device_hybrid_encryption_public_key_material_hash" =>
        Hash.blake3_base64url(
          JCS.canonical_bytes!(device_registration.hybrid_encryption_public_key_material)
        ),
      "target_device_encryption_key_id" => device_registration.encryption_key_id,
      "target_device_client_nonce_hash" =>
        Hash.blake3_base64url(device_registration.client_nonce),
      "target_key_checkpoint_sequence" => Map.fetch!(target_payload, "sequence"),
      "target_key_checkpoint_hash" => key_directory_checkpoint_hash(target_payload)
    }
  end

  defp key_directory_checkpoint_hash(payload),
    do: Hash.blake3_base64url(JCS.canonical_bytes!(payload))
end
