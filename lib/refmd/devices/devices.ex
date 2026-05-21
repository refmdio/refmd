defmodule RefMD.Devices do
  @moduledoc """
  The Devices context. Manages device lifecycle.
  """

  import Ecto.Query

  alias RefMD.Auth.Session
  alias RefMD.Crypto.{Encoding, Hash, HybridEncryptionMaterial, JCS, Signature}
  alias RefMD.Devices.{Device, DeviceEncryptedUMK}
  alias RefMD.Encryption
  alias RefMD.Repo

  alias RefMD.Devices.Events, as: WEvents
  alias RefMD.Devices.Registrations, as: WRegistrations
  alias RefMD.Devices.Registrations.ApprovalDeliveryArtifacts
  alias RefMD.Devices.Registrations.DeviceInitialKeyDelivery
  alias RefMD.Devices.Registrations.Materials
  alias RefMD.Devices.Revocations, as: WRevocations

  @registration_challenge_ttl_seconds 300

  # ── Events (delegated to RefMD.Devices.Events) ──

  defdelegate subscribe_user(user_id), to: WEvents
  defdelegate subscribe_pending(user_id, device_id), to: WEvents
  defdelegate broadcast_device_registration_created(user_id, device_registration), to: WEvents
  defdelegate broadcast_registration_approved(user_id, device_id), to: WEvents
  defdelegate broadcast_device_registration_removed(user_id, device_id), to: WEvents
  defdelegate broadcast_registration_rejected(user_id, device_id), to: WEvents

  defdelegate broadcast_kek_rotation_needed(user_id, workspace_id, current_kek_version),
    to: WEvents

  # ── Registrations (delegated to RefMD.Devices.Registrations) ──

  defdelegate user_owns_device_registration?(user_id, device_id), to: WRegistrations
  defdelegate create_device_registration(attrs), to: WRegistrations
  defdelegate get_valid_device_registration(id), to: WRegistrations
  defdelegate get_user_device_registrations(user_id), to: WRegistrations
  defdelegate get_device_registration_status(user_id, device_id), to: WRegistrations
  defdelegate delete_device_registration(id), to: WRegistrations

  defdelegate replace_user_device_registration(user_id, session_id, attrs), to: WRegistrations

  @spec approve_device_registration(
          RefMD.Devices.DeviceRegistration.t(),
          map(),
          keyword()
        ) ::
          {:ok, Device.t() | RefMD.Devices.DeviceRegistration.t()}
          | {:error, atom() | Ecto.Changeset.t()}
  def approve_device_registration(device_registration, approval_signature, opts \\ []),
    do: WRegistrations.approve_device_registration(device_registration, approval_signature, opts)

  defdelegate finalize_pending_delivery(device_registration, umk_attrs, prekey_consumptions),
    to: WRegistrations

  defdelegate delete_expired_device_registrations(), to: WRegistrations

  @spec validate_bootstrap_device_registration(Ecto.UUID.t(), map()) :: :ok | {:error, atom()}
  def validate_bootstrap_device_registration(user_id, material) do
    with :ok <- Materials.validate_device_request_material(material) do
      Materials.validate_bootstrap_identity_material(user_id, material)
    end
  end

  @spec validate_device_registration(Ecto.UUID.t(), map()) :: :ok | {:error, atom()}
  def validate_device_registration(user_id, material) do
    with :ok <- Materials.validate_device_request_material(material) do
      Materials.validate_identity_signing_key_id(user_id, material.identity_signing_key_id)
    end
  end

  @spec prepare_device_approval_inputs(map(), boolean(), Device.t() | nil, map()) ::
          {:ok, map(), map() | nil} | {:error, atom()}
  def prepare_device_approval_inputs(params, is_recovery, approver_device, device_registration) do
    ApprovalDeliveryArtifacts.approval_inputs_from_params(
      params,
      is_recovery,
      approver_device,
      device_registration
    )
  end

  @spec finalize_pending_delivery_from_params(binary(), binary(), map(), map(), map()) ::
          {:ok, Device.t()} | {:error, atom() | Ecto.Changeset.t()}
  def finalize_pending_delivery_from_params(
        user_id,
        target_device_id,
        sender_device,
        target_device,
        params
      ) do
    with :ok <-
           DeviceInitialKeyDelivery.validate_bundle(
             user_id,
             target_device_id,
             sender_device,
             target_device,
             params
           ),
         {:ok, prekey_consumptions} <-
           DeviceInitialKeyDelivery.prekey_consumptions_from_params(params) do
      WRegistrations.finalize_pending_delivery(
        target_device,
        %{
          sender_device_id: sender_device.id,
          initial_ake: params["initial_ake"],
          initial_key_delivery: params["initial_key_delivery"],
          initial_kek_deliveries: params["initial_kek_deliveries"],
          device_state_delivery: params["device_state_delivery"]
        },
        prekey_consumptions
      )
    end
  end

  @spec issue_bootstrap_registration_challenge(Ecto.UUID.t(), Session.t()) ::
          {:ok, %{challenge: binary(), expires_in_seconds: pos_integer()}}
          | {:error, :already_has_devices | :session_not_found | :identity_key_not_found}
  def issue_bootstrap_registration_challenge(user_id, session) do
    if user_has_any_device_records?(user_id) do
      {:error, :already_has_devices}
    else
      with {:ok, challenge} <- issue_registration_challenge(user_id, session),
           :ok <- bind_bootstrap_challenge_to_identity!(user_id, challenge) do
        {:ok, challenge}
      end
    end
  end

  @spec issue_registration_challenge(Ecto.UUID.t(), Session.t()) ::
          {:ok, %{challenge: binary(), expires_in_seconds: pos_integer()}}
          | {:error, :session_not_found}
  def issue_registration_challenge(user_id, session) do
    {challenge, challenge_hash, expires_at} = new_registration_challenge()

    from(s in Session, where: s.id == ^session.id and s.user_id == ^user_id)
    |> Repo.update_all(
      set: [
        pending_registration_challenge_hash: challenge_hash,
        pending_registration_challenge_expires_at: expires_at,
        pending_registration_challenge_consumed_at: nil
      ]
    )
    |> case do
      {1, _} ->
        {:ok, %{challenge: challenge, expires_in_seconds: @registration_challenge_ttl_seconds}}

      _ ->
        {:error, :session_not_found}
    end
  end

  defp new_registration_challenge do
    challenge = :crypto.strong_rand_bytes(32)
    challenge_hash = Hash.blake3_base64url(challenge)
    expires_at = DateTime.add(DateTime.utc_now(), @registration_challenge_ttl_seconds, :second)
    {challenge, challenge_hash, expires_at}
  end

  defp bind_bootstrap_challenge_to_identity!(user_id, %{challenge: challenge}) do
    challenge_hash = Hash.blake3_base64url(challenge)

    from(k in RefMD.Encryption.UserIdentityPublicKey, where: k.user_id == ^user_id)
    |> Repo.update_all(set: [pending_registration_challenge_hash: challenge_hash])
    |> case do
      {1, _} -> :ok
      _ -> {:error, :identity_key_not_found}
    end
  end

  # ── Revocations (delegated to RefMD.Devices.Revocations) ──

  defdelegate revoke_device(
                user_id,
                device_id,
                revoked_by_device_id,
                revocation_mode,
                revocation_signature,
                revoked_at_ms,
                key_directory
              ),
              to: WRevocations

  # ── Device CRUD ─────────────────────────────────

  @spec touch_device(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def touch_device(device_id) do
    from(d in Device, where: d.id == ^device_id and is_nil(d.revoked_at))
    |> Repo.update_all(set: [last_seen_at: DateTime.utc_now()])
  end

  @spec get_device(Ecto.UUID.t()) :: Device.t() | nil
  def get_device(id), do: Repo.get(Device, id)

  @spec get_user_devices(Ecto.UUID.t(), keyword()) :: [Device.t()]
  def get_user_devices(user_id, opts \\ []) do
    include_revoked = Keyword.get(opts, :include_revoked, false)

    base = from(d in Device, where: d.user_id == ^user_id, order_by: [desc: :created_at])

    if include_revoked do
      base
    else
      from(d in base, where: is_nil(d.revoked_at))
    end
    |> Repo.all()
  end

  @spec create_device(map()) :: {:ok, Device.t()} | {:error, Ecto.Changeset.t()}
  def create_device(attrs) do
    now = DateTime.utc_now()

    changeset =
      %Device{last_seen_at: now, created_at: now}
      |> Device.changeset(attrs)

    with true <- changeset.valid?,
         :ok <- verify_device_changeset_approval_signature(changeset) do
      Repo.insert(changeset)
    else
      false ->
        {:error, changeset}

      {:error, _reason} ->
        {:error, Ecto.Changeset.add_error(changeset, :approval_signature, "is invalid")}
    end
  end

  @spec bootstrap_first_device(map(), map(), Ecto.UUID.t()) ::
          {:ok, Device.t()} | {:error, atom() | Ecto.Changeset.t()}
  def bootstrap_first_device(attrs, approval_signature, session_id)
      when is_map(attrs) and is_map(approval_signature) and is_binary(session_id) do
    Repo.transaction(fn ->
      lock_user!(attrs.user_id)

      if user_has_any_device_records?(attrs.user_id) do
        Repo.rollback(:already_has_devices)
      end

      with {:ok, identity_material} <- get_identity_public_material(attrs.user_id),
           :ok <-
             assert_identity_registration_challenge!(
               identity_material,
               attrs.pending_registration_challenge_hash
             ),
           :ok <-
             consume_genesis_challenge!(session_id, attrs.pending_registration_challenge_hash),
           :ok <-
             verify_genesis_device_signature(attrs, approval_signature, identity_material.signing),
           :ok <- validate_initial_key_directory_materials(attrs, identity_material),
           {:ok, device} <-
             attrs
             |> Map.put(:approval_signature, approval_signature)
             |> Map.put(:approval_signature_surface, "genesis_device_bootstrap")
             |> Map.put(
               :approval_proof,
               genesis_device_approval_proof!(attrs, identity_material.signing)
             )
             |> create_device() do
        insert_initial_key_directories!(attrs)
        device
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, device} -> {:ok, device}
      {:error, reason} -> {:error, reason}
    end
  end

  def bootstrap_first_device(_, _, _), do: {:error, :invalid_signature}

  @spec bootstrap_first_user_device(map(), map()) ::
          {:ok, Device.t()} | {:error, atom() | Ecto.Changeset.t()}
  def bootstrap_first_user_device(attrs, approval_signature)
      when is_map(attrs) and is_map(approval_signature) do
    Repo.transaction(fn ->
      lock_user!(attrs.user_id)

      if user_has_any_device_records?(attrs.user_id) do
        Repo.rollback(:already_has_devices)
      end

      with {:ok, identity_material} <- get_identity_public_material(attrs.user_id),
           :ok <-
             verify_genesis_device_signature(attrs, approval_signature, identity_material.signing),
           :ok <- validate_initial_user_key_directory_materials(attrs, identity_material),
           {:ok, device} <-
             attrs
             |> Map.put(:approval_signature, approval_signature)
             |> Map.put(:approval_signature_surface, "genesis_device_bootstrap")
             |> Map.put(
               :approval_proof,
               genesis_device_approval_proof!(attrs, identity_material.signing)
             )
             |> create_device() do
        insert_initial_user_key_directory!(attrs)
        device
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, device} -> {:ok, device}
      {:error, reason} -> {:error, reason}
    end
  end

  def bootstrap_first_user_device(_, _), do: {:error, :invalid_signature}

  @spec bootstrap_guest_device(map(), map(), map()) ::
          {:ok, Device.t()} | {:error, atom() | Ecto.Changeset.t()}
  def bootstrap_guest_device(attrs, approval_signature, workspace_key_directory_checkpoint)
      when is_map(attrs) and is_map(approval_signature) and
             is_map(workspace_key_directory_checkpoint) do
    Repo.transaction(fn ->
      lock_user!(attrs.user_id)

      if user_has_any_device_records?(attrs.user_id) do
        Repo.rollback(:already_has_devices)
      end

      with {:ok, identity_material} <- get_identity_public_material(attrs.user_id),
           :ok <-
             verify_genesis_device_signature(attrs, approval_signature, identity_material.signing),
           {:ok, device} <-
             attrs
             |> Map.put(:approval_signature, approval_signature)
             |> Map.put(:approval_signature_surface, "genesis_device_bootstrap")
             |> Map.put(
               :approval_proof,
               genesis_device_approval_proof!(
                 attrs,
                 identity_material.signing,
                 workspace_key_directory_checkpoint
               )
             )
             |> create_device() do
        device
      else
        {:error, reason} -> Repo.rollback(reason)
      end
    end)
    |> case do
      {:ok, device} -> {:ok, device}
      {:error, reason} -> {:error, reason}
    end
  end

  def bootstrap_guest_device(_, _, _), do: {:error, :invalid_signature}

  @spec user_has_devices?(Ecto.UUID.t()) :: boolean()
  def user_has_devices?(user_id) do
    from(d in Device, where: d.user_id == ^user_id and is_nil(d.revoked_at))
    |> Repo.exists?()
  end

  @spec user_has_any_device_records?(Ecto.UUID.t()) :: boolean()
  def user_has_any_device_records?(user_id) do
    from(d in Device, where: d.user_id == ^user_id)
    |> Repo.exists?()
  end

  @spec device_exists?(Ecto.UUID.t()) :: boolean()
  def device_exists?(device_id) do
    from(d in Device, where: d.id == ^device_id)
    |> Repo.exists?()
  end

  @spec user_owns_active_device?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def user_owns_active_device?(user_id, device_id) do
    from(d in Device,
      where: d.id == ^device_id and d.user_id == ^user_id and is_nil(d.revoked_at)
    )
    |> Repo.exists?()
  end

  @spec rename_device(Ecto.UUID.t(), Ecto.UUID.t(), String.t()) ::
          {:ok, Device.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def rename_device(user_id, device_id, name) do
    case from(d in Device,
           where: d.id == ^device_id and d.user_id == ^user_id and is_nil(d.revoked_at)
         )
         |> Repo.one() do
      nil -> {:error, :not_found}
      device -> device |> Ecto.Changeset.change(%{name: name}) |> Repo.update()
    end
  end

  # ── Device Encrypted UMK ──────────────────────

  @spec create_device_encrypted_umk(map()) ::
          {:ok, DeviceEncryptedUMK.t()} | {:error, Ecto.Changeset.t()}
  def create_device_encrypted_umk(attrs) do
    %DeviceEncryptedUMK{created_at: DateTime.utc_now()}
    |> DeviceEncryptedUMK.changeset(attrs)
    |> Repo.insert()
  end

  @spec create_device_encrypted_umk_with_prekey_consumption(map(), [map()]) ::
          {:ok, DeviceEncryptedUMK.t()} | {:error, Ecto.Changeset.t() | atom()}
  def create_device_encrypted_umk_with_prekey_consumption(attrs, prekey_consumptions)
      when is_list(prekey_consumptions) do
    now = DateTime.utc_now()

    Repo.transaction(fn ->
      prekey_consumptions
      |> prekey_consumption_rows(attrs, now)
      |> consume_initial_ake_prekeys!()

      insert_device_encrypted_umk!(attrs)
    end)
    |> case do
      {:ok, umk} -> {:ok, umk}
      {:error, reason} -> {:error, reason}
    end
  end

  def create_device_encrypted_umk_with_prekey_consumption(_, _),
    do: {:error, :invalid_initial_ake_prekey}

  defp dump_uuid!(value) when is_binary(value), do: Ecto.UUID.dump!(value)

  defp prekey_consumption_rows([], _attrs, _now), do: Repo.rollback(:invalid_initial_ake_prekey)

  defp prekey_consumption_rows(prekey_consumptions, attrs, now) do
    Enum.map(prekey_consumptions, fn row ->
      row
      |> Map.put(:user_id, dump_uuid!(attrs.user_id))
      |> Map.put(:device_id, dump_uuid!(attrs.device_id))
      |> Map.put(:consumed_at, now)
    end)
  end

  defp consume_initial_ake_prekeys!(rows) do
    case Repo.insert_all("initial_ake_prekey_consumptions", rows, on_conflict: :nothing) do
      {count, _} when count == length(rows) -> :ok
      _ -> Repo.rollback(:initial_ake_prekey_reused)
    end
  end

  defp insert_device_encrypted_umk!(attrs) do
    case create_device_encrypted_umk(attrs) do
      {:ok, umk} -> umk
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  @spec create_device_encrypted_umk_with_key_directory(map(), [map()], map()) ::
          {:ok, DeviceEncryptedUMK.t()} | {:error, Ecto.Changeset.t() | atom()}
  def create_device_encrypted_umk_with_key_directory(attrs, user_events, user_checkpoint)
      when is_list(user_events) and is_map(user_checkpoint) do
    Repo.transaction(fn ->
      assert_device_umk_operation_checkpoint_matches_current_pin!(attrs)

      append =
        Encryption.append_user_key_directory!(
          attrs.user_id,
          user_events,
          user_checkpoint,
          checkpoint_signer_kind: "identity"
        )

      assert_device_umk_operation_anchor!(attrs, append)

      case create_device_encrypted_umk(attrs) do
        {:ok, umk} -> umk
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
    |> case do
      {:ok, umk} -> {:ok, umk}
      {:error, reason} -> {:error, reason}
    end
  rescue
    _ -> {:error, :invalid_key_directory}
  end

  def create_device_encrypted_umk_with_key_directory(_, _, _),
    do: {:error, :missing_key_directory}

  defp assert_device_umk_operation_anchor!(attrs, %{events: [event], checkpoint: checkpoint}) do
    assert_device_umk_event_anchor!(attrs, event)
    assert_device_umk_checkpoint_anchor!(checkpoint)
  end

  defp assert_device_umk_operation_anchor!(_, _),
    do: raise(ArgumentError, "invalid_umk_operation_checkpoint")

  defp assert_device_umk_operation_checkpoint_matches_current_pin!(attrs) do
    pin = Encryption.current_user_key_directory_pin(attrs.user_id)
    if is_nil(pin), do: raise(ArgumentError, "key_directory_checkpoint_required")

    unless attrs.operation_checkpoint_sequence == pin.checkpoint_sequence and
             Encoding.encode_base64url(attrs.operation_checkpoint_hash) == pin.checkpoint_hash and
             attrs.operation_checkpoint_covered_head_sequence == pin.event_head_sequence and
             Encoding.encode_base64url(attrs.operation_checkpoint_covered_head_hash) ==
               pin.event_head_hash do
      raise ArgumentError, "invalid_umk_operation_checkpoint"
    end
  end

  defp assert_device_umk_event_anchor!(attrs, event) do
    unless event.event_type == "wrap_issued" and
             attrs.wrap_event_sequence == event.sequence and
             Encoding.encode_base64url(attrs.wrap_event_hash) == event.event_hash and
             Encoding.encode_base64url(attrs.wrap_event_body_hash) == event.event_body_hash do
      raise ArgumentError, "invalid_umk_key_directory_event"
    end
  end

  defp assert_device_umk_checkpoint_anchor!(%{sequence: sequence})
       when is_integer(sequence) and sequence > 0,
       do: :ok

  defp assert_device_umk_checkpoint_anchor!(_),
    do: raise(ArgumentError, "invalid_umk_operation_checkpoint")

  @spec get_device_encrypted_umk(Ecto.UUID.t(), Ecto.UUID.t()) :: DeviceEncryptedUMK.t() | nil
  def get_device_encrypted_umk(user_id, device_id) do
    from(d in DeviceEncryptedUMK,
      where: d.user_id == ^user_id and d.device_id == ^device_id
    )
    |> Repo.one()
  end

  defp get_identity_public_material(user_id) do
    from(k in RefMD.Encryption.UserIdentityPublicKey,
      where: k.user_id == ^user_id,
      select: %{
        signing: k.hybrid_signing_public_key_material,
        encryption: k.hybrid_encryption_public_key_material,
        pending_registration_challenge_hash: k.pending_registration_challenge_hash
      },
      lock: "FOR UPDATE",
      limit: 1
    )
    |> Repo.one()
    |> case do
      %{
        signing: signing,
        encryption: encryption,
        pending_registration_challenge_hash: pending_registration_challenge_hash
      }
      when is_map(signing) and is_map(encryption) ->
        {:ok,
         %{
           signing: signing,
           encryption: encryption,
           pending_registration_challenge_hash: pending_registration_challenge_hash
         }}

      _ ->
        {:error, :identity_key_not_found}
    end
  end

  defp assert_identity_registration_challenge!(
         %{pending_registration_challenge_hash: challenge_hash},
         challenge_hash
       )
       when is_binary(challenge_hash),
       do: :ok

  defp assert_identity_registration_challenge!(_, _),
    do: {:error, :identity_registration_challenge_mismatch}

  defp insert_initial_key_directories!(%{
         user_id: user_id,
         workspace_id: workspace_id,
         key_directory: %{
           user_events: user_events,
           user_checkpoint: user_checkpoint,
           workspace_events: workspace_events,
           workspace_checkpoint: workspace_checkpoint
         }
       })
       when is_binary(workspace_id) and is_list(user_events) and is_map(user_checkpoint) and
              is_list(workspace_events) and is_map(workspace_checkpoint) do
    Encryption.insert_initial_user_key_directory!(
      user_id,
      user_events,
      user_checkpoint,
      checkpoint_signer_kind: "identity"
    )

    Encryption.insert_initial_workspace_key_directory!(
      workspace_id,
      workspace_events,
      workspace_checkpoint,
      checkpoint_signer_kind: "device"
    )
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  defp insert_initial_key_directories!(_), do: Repo.rollback(:missing_key_directory)

  defp insert_initial_user_key_directory!(%{
         user_id: user_id,
         key_directory: %{user_events: user_events, user_checkpoint: user_checkpoint}
       })
       when is_list(user_events) and is_map(user_checkpoint) do
    Encryption.insert_initial_user_key_directory!(
      user_id,
      user_events,
      user_checkpoint,
      checkpoint_signer_kind: "identity"
    )
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  defp insert_initial_user_key_directory!(_), do: Repo.rollback(:missing_key_directory)

  defp validate_initial_user_key_directory_materials(
         %{
           key_directory: %{user_events: user_events, user_checkpoint: user_checkpoint},
           user_id: user_id,
           id: device_id,
           hybrid_signing_public_key_material: device_signing_material,
           hybrid_encryption_public_key_material: device_encryption_material
         },
         %{signing: identity_signing_material, encryption: identity_encryption_material}
       ) do
    assert_checkpoint_contains_material!(
      user_checkpoint,
      "identity_keys",
      identity_signing_material
    )

    assert_checkpoint_contains_material!(
      user_checkpoint,
      "identity_keys",
      identity_encryption_material
    )

    assert_checkpoint_contains_material!(user_checkpoint, "device_keys", device_signing_material)

    assert_checkpoint_contains_material!(
      user_checkpoint,
      "device_keys",
      device_encryption_material
    )

    assert_initial_user_key_directory_events!(
      user_events,
      %{user_id: user_id, device_id: device_id},
      %{
        identity_signing: identity_signing_material,
        device_signing: device_signing_material,
        device_encryption: device_encryption_material
      }
    )
  rescue
    _ -> {:error, :invalid_key_directory}
  end

  defp validate_initial_user_key_directory_materials(_, _), do: {:error, :missing_key_directory}

  defp validate_initial_key_directory_materials(
         %{
           key_directory: %{
             user_events: user_events,
             user_checkpoint: user_checkpoint,
             workspace_events: workspace_events,
             workspace_checkpoint: workspace_checkpoint
           },
           user_id: user_id,
           workspace_id: workspace_id,
           id: device_id,
           hybrid_signing_public_key_material: device_signing_material,
           hybrid_encryption_public_key_material: device_encryption_material
         },
         %{signing: identity_signing_material, encryption: identity_encryption_material}
       ) do
    assert_checkpoint_contains_material!(
      user_checkpoint,
      "identity_keys",
      identity_signing_material
    )

    assert_checkpoint_contains_material!(
      user_checkpoint,
      "identity_keys",
      identity_encryption_material
    )

    assert_checkpoint_contains_material!(user_checkpoint, "device_keys", device_signing_material)

    assert_checkpoint_contains_material!(
      user_checkpoint,
      "device_keys",
      device_encryption_material
    )

    assert_checkpoint_contains_material!(
      workspace_checkpoint,
      "identity_keys",
      identity_signing_material
    )

    assert_checkpoint_contains_material!(
      workspace_checkpoint,
      "identity_keys",
      identity_encryption_material
    )

    assert_checkpoint_contains_material!(
      workspace_checkpoint,
      "device_keys",
      device_signing_material
    )

    assert_checkpoint_contains_material!(
      workspace_checkpoint,
      "device_keys",
      device_encryption_material
    )

    assert_initial_key_directory_events!(
      user_events,
      workspace_events,
      %{workspace_id: workspace_id, user_id: user_id, device_id: device_id},
      %{
        identity_signing: identity_signing_material,
        identity_encryption: identity_encryption_material,
        device_signing: device_signing_material,
        device_encryption: device_encryption_material
      }
    )
  rescue
    _ -> {:error, :invalid_key_directory}
  end

  defp validate_initial_key_directory_materials(_, _), do: {:error, :missing_key_directory}

  defp assert_checkpoint_contains_material!(%{"payload" => payload}, key, material) do
    expected_key_id = key_material_id!(material)

    found? =
      payload
      |> Map.fetch!(key)
      |> Enum.any?(fn
        %{"key_id" => ^expected_key_id, "key_material" => ^material} -> true
        _ -> false
      end)

    if found?, do: :ok, else: raise(ArgumentError, "key_directory_material_missing")
  end

  defp key_material_id!(%{"protocol" => "refmd.hybrid-signing-key-material"} = material),
    do: Signature.compute_signing_key_id!(material)

  defp key_material_id!(%{"protocol" => "refmd.hybrid-encryption-key-material"} = material),
    do: HybridEncryptionMaterial.compute_key_id!(material)

  defp key_material_id!(_), do: raise(ArgumentError, "key_material_protocol_invalid")

  defp assert_initial_key_directory_events!(
         [
           %{"payload" => %{"event_type" => "identity_key_added", "body" => identity_body}},
           %{"payload" => %{"event_type" => "device_key_added", "body" => user_device_body}}
         ],
         [
           %{"payload" => %{"event_type" => "device_key_added", "body" => workspace_device_body}},
           %{
             "payload" => %{
               "event_type" => "identity_key_added",
               "body" => workspace_identity_signing_body
             }
           },
           %{
             "payload" => %{
               "event_type" => "identity_key_added",
               "body" => workspace_identity_encryption_body
             }
           },
           %{"payload" => %{"event_type" => "member_added", "body" => workspace_member_body}}
         ],
         %{workspace_id: workspace_id, user_id: user_id, device_id: device_id},
         %{
           identity_signing: identity_signing_material,
           identity_encryption: identity_encryption_material,
           device_signing: device_signing_material,
           device_encryption: device_encryption_material
         }
       ) do
    device_signing_key_id = key_material_id!(device_signing_material)

    device_encryption_key_id =
      key_material_id!(device_encryption_material)

    assert_identity_event_body!(identity_body, identity_signing_material)

    expected_device_body = %{
      "user_id" => user_id,
      "device_id" => device_id,
      "signing_key_id" => device_signing_key_id,
      "encryption_key_id" => device_encryption_key_id
    }

    if user_device_body != expected_device_body or workspace_device_body != expected_device_body do
      raise ArgumentError, "key_directory_device_event_mismatch"
    end

    assert_identity_event_body!(workspace_identity_signing_body, identity_signing_material)
    assert_identity_event_body!(workspace_identity_encryption_body, identity_encryption_material)

    {_, owner_role} = RefMD.Workspaces.get_member_with_role(workspace_id, user_id)

    expected_workspace_member_body = %{
      "workspace_id" => workspace_id,
      "user_id" => user_id,
      "role_id" => owner_role.id,
      "base_role" => "owner"
    }

    if workspace_member_body != expected_workspace_member_body do
      raise ArgumentError, "key_directory_member_event_mismatch"
    end

    :ok
  end

  defp assert_initial_key_directory_events!(_, _, _, _),
    do: raise(ArgumentError, "key_directory_initial_events_invalid")

  defp assert_initial_user_key_directory_events!(
         [
           %{"payload" => %{"event_type" => "identity_key_added", "body" => identity_body}},
           %{"payload" => %{"event_type" => "device_key_added", "body" => device_body}}
         ],
         %{user_id: user_id, device_id: device_id},
         %{
           identity_signing: identity_signing_material,
           device_signing: device_signing_material,
           device_encryption: device_encryption_material
         }
       ) do
    device_signing_key_id = key_material_id!(device_signing_material)

    device_encryption_key_id =
      key_material_id!(device_encryption_material)

    assert_identity_event_body!(identity_body, identity_signing_material)

    unless device_body["user_id"] == user_id and device_body["device_id"] == device_id and
             device_body["signing_key_id"] == device_signing_key_id and
             device_body["encryption_key_id"] == device_encryption_key_id do
      raise ArgumentError, "key_directory_device_event_mismatch"
    end

    :ok
  end

  defp assert_initial_user_key_directory_events!(_, _, _),
    do: raise(ArgumentError, "key_directory_initial_events_invalid")

  defp assert_identity_event_body!(body, material) do
    if body["key_id"] != key_material_id!(material) or
         body["key_material_hash"] != Hash.blake3_base64url(JCS.canonical_bytes!(material)) do
      raise ArgumentError, "key_directory_identity_event_mismatch"
    end
  end

  defp lock_user!(user_id) do
    from(u in RefMD.Users.User, where: u.id == ^user_id, lock: "FOR UPDATE")
    |> Repo.one()
    |> case do
      nil -> Repo.rollback(:user_not_found)
      user -> user
    end
  end

  defp verify_genesis_device_signature(attrs, signature, identity_material) do
    transcript = genesis_device_approval_transcript!(attrs)
    identity_signing_key_id = Signature.compute_signing_key_id!(identity_material)

    case Signature.verify_hybrid_signature_result(
           "genesis_device_bootstrap",
           transcript,
           signature,
           identity_material,
           %{
             active_device_records?: user_has_any_device_records?(attrs.user_id),
             identity_signing_key_id: identity_signing_key_id,
             target_device: target_device_semantic_context(attrs)
           }
         ) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  rescue
    ArgumentError -> {:error, :invalid_signature}
  end

  defp verify_device_changeset_approval_signature(changeset) do
    attrs = Ecto.Changeset.apply_changes(changeset)

    with {:ok, identity_material} <- get_identity_public_material(attrs.user_id),
         transcript <- device_approval_transcript_from_attrs!(attrs),
         public_material <- approval_public_material!(attrs, identity_material.signing),
         semantic_context <- approval_semantic_context(attrs, public_material) do
      case Signature.verify_hybrid_signature_result(
             attrs.approval_signature_surface,
             transcript,
             attrs.approval_signature,
             public_material,
             semantic_context
           ) do
        :ok -> :ok
        {:error, reason} -> {:error, reason}
      end
    end
  rescue
    ArgumentError -> {:error, :invalid_signature}
  end

  defp approval_semantic_context(
         %{approval_signature_surface: "device_approval"} = attrs,
         _public
       ) do
    approver = Repo.get!(Device, attrs.approval_proof["approving_owner_id"])

    %{
      approver: %{
        id: approver.id,
        revoked_at: approver.revoked_at,
        signing_key_id: approver.signing_key_id
      },
      target_device: target_device_semantic_context(attrs)
    }
  end

  defp approval_semantic_context(
         %{approval_signature_surface: "genesis_device_bootstrap"} = attrs,
         public
       ) do
    %{
      active_device_records?: user_has_any_device_records?(attrs.user_id),
      identity_signing_key_id: Signature.compute_signing_key_id!(public),
      target_device: target_device_semantic_context(attrs)
    }
  end

  defp approval_semantic_context(
         %{approval_signature_surface: "recovery_device_approval"} = attrs,
         _public
       ) do
    details = attrs.approval_proof["surface_details"] || %{}

    %{
      recovery_session: %{
        pending_registration_binding_hash: details["pending_registration_binding_hash"],
        recovery_capability_hash: details["recovery_capability_hash"],
        recovery_session_transcript_hash: details["recovery_session_transcript_hash"]
      },
      target_device: target_device_semantic_context(attrs)
    }
  end

  defp target_device_semantic_context(attrs) do
    %{
      id: Map.fetch!(attrs, :id),
      signing_key_id:
        Map.get(attrs, :signing_key_id) ||
          Signature.compute_signing_key_id!(
            Map.fetch!(attrs, :hybrid_signing_public_key_material)
          ),
      user_id: Map.fetch!(attrs, :user_id)
    }
  end

  defp approval_public_material!(
         %{approval_signature_surface: "device_approval"} = attrs,
         _identity
       ) do
    case Repo.get(Device, attrs.approval_proof["approving_owner_id"]) do
      %{user_id: user_id, hybrid_signing_public_key_material: material}
      when user_id == attrs.user_id ->
        if attrs.approval_proof["approving_signing_key_id"] !=
             Signature.compute_signing_key_id!(material) do
          raise ArgumentError, "approval_signing_key_id_mismatch"
        end

        material

      _ ->
        raise ArgumentError, "approval_public_material_missing"
    end
  end

  defp approval_public_material!(%{approval_signature_surface: surface} = attrs, identity)
       when surface in ["genesis_device_bootstrap", "recovery_device_approval"] do
    if attrs.approval_proof["approving_signing_key_id"] !=
         Signature.compute_signing_key_id!(identity) do
      raise ArgumentError, "approval_signing_key_id_mismatch"
    end

    identity
  end

  defp device_approval_transcript_from_attrs!(
         %{approval_signature_surface: "genesis_device_bootstrap"} = attrs
       ) do
    Signature.build_genesis_device_bootstrap_transcript!(%{
      user_id: attrs.user_id,
      device_id: attrs.id,
      device_public_material: attrs.hybrid_signing_public_key_material,
      device_hybrid_encryption_public_key_material: attrs.hybrid_encryption_public_key_material,
      client_nonce: Encoding.encode_base64url(attrs.client_nonce),
      registration_challenge_hash:
        attrs.approval_proof["surface_details"]["registration_challenge_hash"],
      identity_signing_key_id: attrs.approval_proof["approving_signing_key_id"],
      user_identity_public_key_hash:
        attrs.approval_proof["surface_details"]["user_identity_public_key_hash"]
    })
  end

  defp device_approval_transcript_from_attrs!(
         %{approval_signature_surface: "device_approval"} = attrs
       ) do
    Signature.build_device_approval_transcript!(
      attrs.user_id,
      attrs.approval_proof["approving_owner_id"],
      attrs.id,
      attrs.hybrid_signing_public_key_material,
      attrs.hybrid_encryption_public_key_material,
      Encoding.encode_base64url(attrs.client_nonce),
      device_approval_commitments_from_proof!(attrs.approval_proof)
    )
  end

  defp device_approval_transcript_from_attrs!(
         %{approval_signature_surface: "recovery_device_approval"} = attrs
       ) do
    proof = attrs.approval_proof
    details = proof["surface_details"]

    Signature.build_recovery_device_approval_transcript!(%{
      user_id: attrs.user_id,
      approving_signing_key_id: proof["approving_signing_key_id"],
      approving_key_checkpoint_sequence: proof["approving_key_checkpoint_sequence"],
      approving_key_checkpoint_hash: proof["approving_key_checkpoint_hash"],
      pending_registration_id: details["pending_registration_id"],
      pending_registration_challenge_hash: details["pending_registration_challenge_hash"],
      recovery_session_transcript_hash: details["recovery_session_transcript_hash"],
      recovery_capability_hash: details["recovery_capability_hash"],
      pending_registration_binding_hash: details["pending_registration_binding_hash"],
      approved_device_id: attrs.id,
      approved_device_public_material: attrs.hybrid_signing_public_key_material,
      approved_device_hybrid_encryption_public_key_material:
        attrs.hybrid_encryption_public_key_material,
      client_nonce: Encoding.encode_base64url(attrs.client_nonce),
      target_key_checkpoint_sequence: proof["target_key_checkpoint_sequence"],
      target_key_checkpoint_hash: proof["target_key_checkpoint_hash"]
    })
  end

  defp device_approval_commitments_from_proof!(proof) do
    details = proof["surface_details"]

    %{
      "approved_device_registration_sas_hash" => details["approved_device_registration_sas_hash"],
      "approving_device_key_directory_proof_hash" =>
        details["approving_device_key_directory_proof_hash"],
      "approving_key_checkpoint_hash" => proof["approving_key_checkpoint_hash"],
      "approving_key_checkpoint_sequence" => proof["approving_key_checkpoint_sequence"],
      "approving_owner_id" => proof["approving_owner_id"],
      "approving_owner_kind" => proof["approving_owner_kind"],
      "approving_signing_key_id" => proof["approving_signing_key_id"],
      "device_approval_kek_initial_delivery_commitments" =>
        details["device_approval_kek_initial_delivery_commitments"],
      "pending_registration_challenge_hash" => details["pending_registration_challenge_hash"],
      "pending_registration_id" => details["pending_registration_id"],
      "target_device_client_nonce_hash" => proof["target_device_client_nonce_hash"],
      "target_device_encryption_key_id" => proof["target_device_encryption_key_id"],
      "target_device_hybrid_encryption_public_key_material_hash" =>
        proof["target_device_hybrid_encryption_public_key_material_hash"],
      "target_device_hybrid_signing_public_key_material_hash" =>
        proof["target_device_hybrid_signing_public_key_material_hash"],
      "target_device_id" => proof["target_device_id"],
      "target_device_signing_key_id" => proof["target_device_signing_key_id"],
      "target_key_checkpoint_hash" => proof["target_key_checkpoint_hash"],
      "target_key_checkpoint_sequence" => proof["target_key_checkpoint_sequence"],
      "trust_transfer_delivery_commitment" => details["trust_transfer_delivery_commitment"],
      "umk_distribution_delivery_commitment" => details["umk_distribution_delivery_commitment"]
    }
  end

  defp consume_genesis_challenge!(session_id, challenge_hash)
       when is_binary(session_id) and is_binary(challenge_hash) do
    now = DateTime.utc_now()

    case lock_session_registration_challenge(session_id) do
      %Session{
        pending_registration_challenge_hash: ^challenge_hash,
        pending_registration_challenge_expires_at: expires_at,
        pending_registration_challenge_consumed_at: nil
      } ->
        if DateTime.compare(expires_at, now) == :gt do
          consume_genesis_challenge_row(session_id, challenge_hash, now)
        else
          {:error, :invalid_registration_challenge}
        end

      _ ->
        {:error, :invalid_registration_challenge}
    end
  end

  defp consume_genesis_challenge!(_, _), do: {:error, :invalid_registration_challenge}

  defp lock_session_registration_challenge(session_id) do
    from(s in Session,
      where: s.id == ^session_id,
      lock: "FOR UPDATE"
    )
    |> Repo.one()
  end

  defp consume_genesis_challenge_row(session_id, challenge_hash, now) do
    from(s in Session,
      where:
        s.id == ^session_id and
          s.pending_registration_challenge_hash == ^challenge_hash and
          is_nil(s.pending_registration_challenge_consumed_at)
    )
    |> Repo.update_all(set: [pending_registration_challenge_consumed_at: now])
    |> case do
      {1, _} -> :ok
      _ -> {:error, :invalid_registration_challenge}
    end
  end

  defp genesis_device_approval_transcript!(attrs) do
    Signature.build_genesis_device_bootstrap_transcript!(%{
      user_id: attrs.user_id,
      device_id: attrs.id,
      device_public_material: attrs.hybrid_signing_public_key_material,
      device_hybrid_encryption_public_key_material: attrs.hybrid_encryption_public_key_material,
      client_nonce: Encoding.encode_base64url(attrs.client_nonce),
      registration_challenge_hash: attrs.pending_registration_challenge_hash,
      identity_signing_key_id: identity_signing_key_id!(attrs.user_id),
      user_identity_public_key_hash: identity_public_material_hash!(attrs.user_id)
    })
  end

  defp genesis_device_approval_proof!(attrs, identity_public_material) do
    transcript = genesis_device_approval_transcript!(attrs)
    proof_context = genesis_device_approval_proof_context!(attrs)

    Signature.build_device_approval_proof!(
      "genesis_device_bootstrap",
      transcript,
      %{
        "kind" => "genesis_device_bootstrap",
        "registration_challenge_hash" => attrs.pending_registration_challenge_hash,
        "user_identity_public_key_hash" =>
          Hash.blake3_base64url(JCS.canonical_bytes!(identity_public_material))
      },
      proof_context
    )
  end

  defp genesis_device_approval_proof!(attrs, identity_public_material, key_directory_checkpoint) do
    transcript = genesis_device_approval_transcript!(attrs)
    proof_context = genesis_device_approval_proof_context!(attrs, key_directory_checkpoint)

    Signature.build_device_approval_proof!(
      "genesis_device_bootstrap",
      transcript,
      %{
        "kind" => "genesis_device_bootstrap",
        "registration_challenge_hash" => attrs.pending_registration_challenge_hash,
        "user_identity_public_key_hash" =>
          Hash.blake3_base64url(JCS.canonical_bytes!(identity_public_material))
      },
      proof_context
    )
  end

  defp genesis_device_approval_proof_context!(
         %{key_directory: %{user_checkpoint: envelope}} = attrs
       ) do
    genesis_device_approval_proof_context!(attrs, envelope)
  end

  defp genesis_device_approval_proof_context!(attrs, envelope) do
    payload =
      case envelope do
        %{"payload" => payload} when is_map(payload) -> payload
        %{} = payload -> payload
      end

    checkpoint_sequence = Map.fetch!(payload, "sequence")
    checkpoint_hash = Hash.blake3_base64url(JCS.canonical_bytes!(payload))

    %{
      "approving_signing_key_id" => identity_signing_key_id!(attrs.user_id),
      "approving_key_checkpoint_sequence" => checkpoint_sequence,
      "approving_key_checkpoint_hash" => checkpoint_hash,
      "target_device_id" => attrs.id,
      "target_device_signing_key_id" =>
        Signature.compute_signing_key_id!(Map.fetch!(attrs, :hybrid_signing_public_key_material)),
      "target_device_hybrid_signing_public_key_material_hash" =>
        Hash.blake3_base64url(
          JCS.canonical_bytes!(Map.fetch!(attrs, :hybrid_signing_public_key_material))
        ),
      "target_device_hybrid_encryption_public_key_material_hash" =>
        Hash.blake3_base64url(
          JCS.canonical_bytes!(Map.fetch!(attrs, :hybrid_encryption_public_key_material))
        ),
      "target_device_encryption_key_id" =>
        HybridEncryptionMaterial.compute_key_id!(
          Map.fetch!(attrs, :hybrid_encryption_public_key_material)
        ),
      "target_device_client_nonce_hash" => Hash.blake3_base64url(attrs.client_nonce),
      "target_key_checkpoint_sequence" => checkpoint_sequence,
      "target_key_checkpoint_hash" => checkpoint_hash
    }
  end

  defp identity_public_material_hash!(user_id) do
    {:ok, material} = get_identity_public_material(user_id)
    Hash.blake3_base64url(JCS.canonical_bytes!(material.signing))
  end

  defp identity_signing_key_id!(user_id) do
    {:ok, material} = get_identity_public_material(user_id)
    Signature.compute_signing_key_id!(material.signing)
  end
end
