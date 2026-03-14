defmodule RefMD.Devices.Registrations do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Devices.{Device, DeviceRegistration}
  alias RefMD.Repo

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

  @spec delete_expired_device_registrations() :: {non_neg_integer(), nil}
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

  defp determine_signature_action(user_id, is_recovery) do
    cond do
      is_recovery -> "device_registration"
      RefMD.Devices.user_has_devices?(user_id) -> "device_approval"
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

  defp get_identity_signing_public_key(user_id) do
    case RefMD.Encryption.get_user_identity_public_key(user_id) do
      nil -> {:error, :identity_key_not_found}
      key -> {:ok, key.signing_public_key}
    end
  end

  defp insert_device_or_rollback(device) do
    case Repo.insert(device) do
      {:ok, device} -> device
      {:error, changeset} -> Repo.rollback(changeset)
    end
  end

  defp reject_if_has_devices(user_id, reason) do
    if RefMD.Devices.user_has_any_device_records?(user_id), do: Repo.rollback(reason)
  end
end
