defmodule RefMD.Devices do
  @moduledoc """
  The Devices context. Manages device lifecycle.
  """

  import Ecto.Query

  alias RefMD.Devices.{Device, DeviceEncryptedUMK}
  alias RefMD.Repo

  alias RefMD.Devices.Registrations, as: WRegistrations
  alias RefMD.Devices.Revocations, as: WRevocations

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
          binary(),
          keyword()
        ) ::
          {:ok, Device.t()} | {:error, atom() | Ecto.Changeset.t()}
  def approve_device_registration(device_registration, identity_signature, opts \\ []),
    do: WRegistrations.approve_device_registration(device_registration, identity_signature, opts)

  defdelegate delete_expired_device_registrations(), to: WRegistrations

  # ── Revocations (delegated to RefMD.Devices.Revocations) ──

  defdelegate revoke_device(
                user_id,
                device_id,
                revoked_by_device_id,
                revocation_mode,
                identity_signature,
                revoked_at_ms
              ),
              to: WRevocations

  defdelegate verify_revocation_signature(
                user_id,
                device_id,
                revocation_mode,
                revoked_by_device_id,
                revoked_at_ms,
                identity_signature
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

  @spec get_device_id_by_signing_key(binary()) :: Ecto.UUID.t() | nil
  def get_device_id_by_signing_key(signing_public_key) do
    from(d in Device,
      where: d.signing_public_key == ^signing_public_key,
      select: d.id,
      limit: 1
    )
    |> Repo.one()
  end

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

  # ── Private Helpers ─────────────────────────────

  defp get_identity_signing_public_key(user_id) do
    case RefMD.Encryption.get_user_identity_public_key(user_id) do
      nil -> {:error, :identity_key_not_found}
      key -> {:ok, key.signing_public_key}
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
