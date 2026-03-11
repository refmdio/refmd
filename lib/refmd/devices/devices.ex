defmodule RefMD.Devices do
  @moduledoc """
  The Devices context. Manages device lifecycle.
  """

  import Ecto.Query

  alias RefMD.Devices.{Device, DeviceEncryptedUMK, DeviceRegistration, DeviceRevocationEvent}
  alias RefMD.Repo

  # ── Devices ────────────────────────────────────

  @spec touch_device(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def touch_device(device_id) do
    from(d in Device, where: d.id == ^device_id and is_nil(d.revoked_at))
    |> Repo.update_all(set: [last_seen_at: DateTime.utc_now()])
  end

  @spec get_device(Ecto.UUID.t()) :: Device.t() | nil
  def get_device(id), do: Repo.get(Device, id)

  @spec get_user_devices(Ecto.UUID.t()) :: [Device.t()]
  def get_user_devices(user_id) do
    from(d in Device,
      where: d.user_id == ^user_id and is_nil(d.revoked_at),
      order_by: [desc: :created_at]
    )
    |> Repo.all()
  end

  @spec create_device(map()) :: {:ok, Device.t()} | {:error, Ecto.Changeset.t()}
  def create_device(attrs) do
    now = DateTime.utc_now()

    %Device{last_seen_at: now, created_at: now}
    |> Device.changeset(attrs)
    |> Repo.insert()
  end

  @spec bootstrap_first_device(map(), binary()) ::
          {:ok, Device.t()} | {:error, atom() | Ecto.Changeset.t()}
  def bootstrap_first_device(attrs, identity_signature) do
    user_id = attrs.user_id

    with {:ok, signing_pub} <- get_identity_signing_public_key(user_id),
         message = build_device_signature_message("device_registration", attrs),
         true <- RefMD.Crypto.verify_ed25519_signature(message, identity_signature, signing_pub) do
      now = DateTime.utc_now()

      Repo.transaction(fn ->
        Repo.one!(from(u in RefMD.Users.User, where: u.id == ^user_id, lock: "FOR UPDATE"))
        reject_if_has_devices(user_id)
        insert_device_or_rollback(build_bootstrap_device(attrs, identity_signature, now))
      end)
    else
      false -> {:error, :invalid_signature}
      {:error, reason} -> {:error, reason}
    end
  end

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

  @spec get_device_encrypted_umk(Ecto.UUID.t(), Ecto.UUID.t()) :: DeviceEncryptedUMK.t() | nil
  def get_device_encrypted_umk(user_id, device_id) do
    from(d in DeviceEncryptedUMK,
      where: d.user_id == ^user_id and d.device_id == ^device_id
    )
    |> Repo.one()
  end

  # ── Device Registrations ────────────────────────

  @spec user_owns_device_registration?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def user_owns_device_registration?(user_id, device_id) do
    now = DateTime.utc_now()

    from(dr in DeviceRegistration,
      where: dr.id == ^device_id and dr.user_id == ^user_id and dr.expires_at > ^now
    )
    |> Repo.exists?()
  end

  @spec create_device_registration(map()) ::
          {:ok, DeviceRegistration.t()} | {:error, Ecto.Changeset.t()}
  def create_device_registration(attrs) do
    now = DateTime.utc_now()
    expires_at = DateTime.add(now, 5 * 60, :second)

    %DeviceRegistration{created_at: now, expires_at: expires_at}
    |> DeviceRegistration.changeset(attrs)
    |> Repo.insert()
  end

  @spec get_valid_device_registration(Ecto.UUID.t()) :: DeviceRegistration.t() | nil
  def get_valid_device_registration(id) do
    now = DateTime.utc_now()

    from(dr in DeviceRegistration,
      where: dr.id == ^id and dr.expires_at > ^now
    )
    |> Repo.one()
  end

  @spec get_user_device_registrations(Ecto.UUID.t()) :: [DeviceRegistration.t()]
  def get_user_device_registrations(user_id) do
    now = DateTime.utc_now()

    from(dr in DeviceRegistration,
      where: dr.user_id == ^user_id and dr.expires_at > ^now,
      order_by: [desc: :created_at]
    )
    |> Repo.all()
  end

  @spec get_device_registration_status(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, String.t()} | {:error, :not_found}
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

  defp resolve_device_status(user_id, device_id) do
    case get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} ->
        if get_device_encrypted_umk(user_id, device_id) != nil do
          {:ok, "approved"}
        else
          {:ok, "pending"}
        end

      _ ->
        {:ok, "expired"}
    end
  end

  @spec delete_device_registration(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def delete_device_registration(id) do
    from(dr in DeviceRegistration, where: dr.id == ^id)
    |> Repo.delete_all()
  end

  @dialyzer {:nowarn_function, replace_user_device_registration: 3}
  @spec replace_user_device_registration(Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, %{removed_ids: [Ecto.UUID.t()], pending: DeviceRegistration.t()}}
          | {:error, atom(), term(), map()}
  def replace_user_device_registration(user_id, session_id, attrs) do
    now = DateTime.utc_now()
    expires_at = DateTime.add(now, 5 * 60, :second)

    Ecto.Multi.new()
    |> Ecto.Multi.run(:removed_ids, fn repo, _changes ->
      ids =
        from(dr in DeviceRegistration,
          where: dr.user_id == ^user_id and dr.expires_at > ^now,
          select: dr.id
        )
        |> repo.all()

      if ids != [] do
        from(dr in DeviceRegistration, where: dr.id in ^ids)
        |> repo.delete_all()
      end

      {:ok, ids}
    end)
    |> Ecto.Multi.insert(
      :pending,
      %DeviceRegistration{created_at: now, expires_at: expires_at}
      |> DeviceRegistration.changeset(attrs)
    )
    |> Ecto.Multi.run(:bind_session, fn _repo, %{pending: pending} ->
      RefMD.Auth.bind_device_registration_to_session(session_id, pending.id)
      {:ok, :bound}
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{removed_ids: ids, pending: pending}} ->
        {:ok, %{removed_ids: ids, pending: pending}}

      {:error, step, changeset, changes} ->
        {:error, step, changeset, changes}
    end
  end

  @spec approve_device_registration(DeviceRegistration.t(), binary(), keyword()) ::
          {:ok, Device.t()} | {:error, atom() | Ecto.Changeset.t()}
  def approve_device_registration(device_registration, identity_signature, opts \\ []) do
    user_id = device_registration.user_id
    is_recovery = Keyword.get(opts, :is_recovery, false)
    first_device = Keyword.get(opts, :first_device, false)

    with {:ok, signing_pub} <- get_identity_signing_public_key(user_id),
         action = determine_signature_action(user_id, is_recovery),
         message = build_device_signature_message(action, device_registration),
         true <- RefMD.Crypto.verify_ed25519_signature(message, identity_signature, signing_pub) do
      execute_approve_device_registration(
        device_registration,
        identity_signature,
        user_id,
        first_device
      )
    else
      false -> {:error, :invalid_signature}
      {:error, reason} -> {:error, reason}
    end
  end

  defp execute_approve_device_registration(
         device_registration,
         identity_signature,
         user_id,
         first_device
       ) do
    Repo.transaction(fn ->
      if first_device, do: reject_if_has_devices(user_id, :not_first_device)

      device =
        insert_device_or_rollback(build_approved_device(device_registration, identity_signature))

      Repo.delete_all(from(dr in DeviceRegistration, where: dr.id == ^device_registration.id))
      device
    end)
  end

  # ── Device Revocation ─────────────────────────

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

    Repo.transaction(fn ->
      mark_device_revoked(user_id, device_id, now)
      invalidate_revoked_device_sessions(user_id, device_id, revocation_mode)

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

  defp invalidate_revoked_device_sessions(user_id, device_id, "security") do
    RefMD.Auth.delete_device_and_unbound_sessions(user_id, device_id)
  end

  defp invalidate_revoked_device_sessions(_user_id, device_id, _revocation_mode) do
    RefMD.Auth.delete_device_sessions(device_id)
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

    RefMD.Workspaces.mark_kek_rotation_needed(ws_ids, user_id)
    RefMD.Workspaces.mark_dek_rotation_needed(ws_ids)

    Enum.map(ws_with_versions, fn {id, version} ->
      %{workspace_id: id, current_kek_version: version}
    end)
  end

  defp handle_security_rotation(_user_id, _revocation_mode), do: []

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

  # ── Cleanup ───────────────────────────────────

  @spec delete_expired_device_registrations() :: {non_neg_integer(), nil}
  def delete_expired_device_registrations do
    now = DateTime.utc_now()

    from(dr in DeviceRegistration, where: dr.expires_at < ^now)
    |> Repo.delete_all()
  end

  # ── Private Helpers ─────────────────────────────

  defp get_identity_signing_public_key(user_id) do
    case RefMD.Encryption.get_user_identity_public_key(user_id) do
      nil -> {:error, :identity_key_not_found}
      key -> {:ok, key.signing_public_key}
    end
  end

  defp determine_signature_action(user_id, is_recovery) do
    cond do
      is_recovery -> "device_registration"
      user_has_devices?(user_id) -> "device_approval"
      true -> "device_registration"
    end
  end

  defp build_device_signature_message(action, device_data) do
    RefMD.Crypto.build_signature_message(action, %{
      "client_nonce" => Base.url_encode64(device_data.client_nonce, padding: false),
      "device_ecdh_public_key" => Base.url_encode64(device_data.ecdh_public_key, padding: false),
      "device_signing_public_key" =>
        Base.url_encode64(device_data.signing_public_key, padding: false)
    })
  end

  defp build_bootstrap_device(attrs, identity_signature, now) do
    %Device{
      id: Ecto.UUID.generate(),
      user_id: attrs.user_id,
      name: attrs.name,
      device_type: attrs.device_type,
      ecdh_public_key: attrs.ecdh_public_key,
      signing_public_key: attrs.signing_public_key,
      identity_signature: identity_signature,
      client_nonce: attrs.client_nonce,
      last_seen_at: now,
      created_at: now
    }
  end

  defp build_approved_device(device_registration, identity_signature) do
    now = DateTime.utc_now()

    %Device{
      id: device_registration.id,
      user_id: device_registration.user_id,
      name: device_registration.name,
      device_type: device_registration.device_type,
      ecdh_public_key: device_registration.ecdh_public_key,
      signing_public_key: device_registration.signing_public_key,
      identity_signature: identity_signature,
      client_nonce: device_registration.client_nonce,
      last_seen_at: now,
      created_at: now
    }
  end

  defp insert_device_or_rollback(device) do
    case Repo.insert(device) do
      {:ok, device} -> device
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp reject_if_has_devices(user_id, reason \\ :already_has_devices) do
    if user_has_any_device_records?(user_id), do: Repo.rollback(reason)
  end
end
