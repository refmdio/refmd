defmodule RefMD.Accounts do
  @moduledoc """
  The Accounts context. Manages users, sessions, and devices.
  """

  import Ecto.Query
  alias RefMD.Repo
  alias RefMD.Accounts.{User, UserSettings, Session, Device, PendingDevice}

  # ── Users ──────────────────────────────────────

  def get_user(id), do: Repo.get(User, id)

  def get_user_by_email(email) do
    Repo.get_by(User, email: email)
  end

  def create_user(attrs) do
    %User{}
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  def create_user_settings(user_id) do
    %UserSettings{user_id: user_id, updated_at: DateTime.utc_now()}
    |> Repo.insert()
  end

  def update_encryption_setup(user_id) do
    from(u in User, where: u.id == ^user_id)
    |> Repo.update_all(set: [encryption_setup_at: DateTime.utc_now()])
  end

  # ── Sessions ───────────────────────────────────

  @session_ttl_default 24 * 60 * 60
  @session_ttl_remember 30 * 24 * 60 * 60

  def create_session(user_id, attrs \\ %{}) do
    token = :crypto.strong_rand_bytes(32)
    token_hash = Base.url_encode64(:crypto.hash(:sha256, token), padding: false)
    remember_me = Map.get(attrs, :remember_me, false)
    ttl = if remember_me, do: @session_ttl_remember, else: @session_ttl_default
    now = DateTime.utc_now()

    session_attrs = %{
      user_id: user_id,
      device_id: Map.get(attrs, :device_id),
      token_hash: token_hash,
      remember_me: remember_me,
      is_recovery: Map.get(attrs, :is_recovery, false),
      ip_address: Map.get(attrs, :ip_address),
      user_agent: Map.get(attrs, :user_agent),
      expires_at: DateTime.add(now, ttl, :second),
      last_seen_at: now
    }

    case %Session{created_at: now}
         |> Session.changeset(session_attrs)
         |> Repo.insert() do
      {:ok, session} -> {:ok, session, token}
      {:error, changeset} -> {:error, changeset}
    end
  end

  def get_valid_session_by_token(raw_token) do
    token_hash = Base.url_encode64(:crypto.hash(:sha256, raw_token), padding: false)
    now = DateTime.utc_now()

    session =
      from(s in Session,
        where: s.token_hash == ^token_hash and s.expires_at > ^now
      )
      |> Repo.one()

    case session do
      nil -> {:error, :invalid_session}
      session -> {:ok, session}
    end
  end

  def get_valid_session_by_token_base64(token_base64) do
    case Base.url_decode64(token_base64, padding: false) do
      {:ok, raw_token} -> get_valid_session_by_token(raw_token)
      :error -> {:error, :invalid_token}
    end
  end

  def delete_session(session_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.delete_all()
  end

  def delete_other_sessions(user_id, current_session_id) do
    from(s in Session,
      where: s.user_id == ^user_id and s.id != ^current_session_id
    )
    |> Repo.delete_all()
  end

  def touch_session(session_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.update_all(set: [last_seen_at: DateTime.utc_now()])
  end

  def bind_session_to_device(session_id, device_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.update_all(set: [device_id: device_id])
  end

  # ── Devices ────────────────────────────────────

  def get_device(id), do: Repo.get(Device, id)

  def get_user_devices(user_id) do
    from(d in Device,
      where: d.user_id == ^user_id and is_nil(d.revoked_at),
      order_by: [desc: :created_at]
    )
    |> Repo.all()
  end

  def create_device(attrs) do
    now = DateTime.utc_now()

    %Device{last_seen_at: now, created_at: now}
    |> Device.changeset(attrs)
    |> Repo.insert()
  end

  def user_has_devices?(user_id) do
    from(d in Device, where: d.user_id == ^user_id and is_nil(d.revoked_at))
    |> Repo.exists?()
  end

  def user_owns_active_device?(user_id, device_id) do
    from(d in Device,
      where: d.id == ^device_id and d.user_id == ^user_id and is_nil(d.revoked_at)
    )
    |> Repo.exists?()
  end

  # ── Pending Devices ────────────────────────────

  def create_pending_device(attrs) do
    now = DateTime.utc_now()
    expires_at = DateTime.add(now, 10 * 60, :second)

    %PendingDevice{created_at: now, expires_at: expires_at}
    |> PendingDevice.changeset(attrs)
    |> Repo.insert()
  end

  def get_valid_pending_device(id) do
    now = DateTime.utc_now()

    from(pd in PendingDevice,
      where: pd.id == ^id and pd.expires_at > ^now
    )
    |> Repo.one()
  end

  def delete_pending_device(id) do
    from(pd in PendingDevice, where: pd.id == ^id)
    |> Repo.delete_all()
  end

  def approve_pending_device(pending_device, identity_signature, opts \\ []) do
    user_id = pending_device.user_id
    is_recovery = Keyword.get(opts, :is_recovery, false)

    with {:ok, signing_pub} <- get_identity_signing_public_key(user_id),
         action = determine_signature_action(user_id, is_recovery),
         message = build_device_signature_message(action, pending_device),
         true <- verify_ed25519_signature(message, identity_signature, signing_pub) do
      Repo.transaction(fn ->
        device =
          %Device{
            id: pending_device.id,
            user_id: user_id,
            name: pending_device.name,
            device_type: pending_device.device_type,
            ecdh_public_key: pending_device.ecdh_public_key,
            signing_public_key: pending_device.signing_public_key,
            identity_signature: identity_signature,
            client_nonce: pending_device.client_nonce,
            last_seen_at: DateTime.utc_now(),
            created_at: DateTime.utc_now()
          }
          |> Repo.insert!()

        Repo.delete_all(from(pd in PendingDevice, where: pd.id == ^pending_device.id))

        device
      end)
    else
      false -> {:error, :invalid_signature}
      {:error, reason} -> {:error, reason}
    end
  end

  defp get_identity_signing_public_key(user_id) do
    case Repo.get(RefMD.Encryption.UserIdentityPublicKey, user_id) do
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

  defp build_device_signature_message(action, pending_device) do
    fields = %{
      "action" => action,
      "client_nonce" => Base.url_encode64(pending_device.client_nonce, padding: false),
      "device_ecdh_public_key" => Base.url_encode64(pending_device.ecdh_public_key, padding: false),
      "device_signing_public_key" => Base.url_encode64(pending_device.signing_public_key, padding: false),
      "protocol" => "refmd",
      "version" => 1
    }

    # JCS canonicalization: sorted keys, no whitespace
    pairs =
      fields
      |> Enum.sort_by(fn {k, _} -> k end)
      |> Enum.map(fn {k, v} ->
        Jason.encode!(k) <> ":" <> encode_jcs_value(v)
      end)

    "{" <> Enum.join(pairs, ",") <> "}"
  end

  defp encode_jcs_value(v) when is_binary(v), do: Jason.encode!(v)
  defp encode_jcs_value(v) when is_integer(v), do: Integer.to_string(v)

  defp verify_ed25519_signature(message, signature, public_key) do
    :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
  end

  # ── Authentication Helpers ─────────────────────

  def get_salt_for_email(email) do
    case get_user_by_email(email) do
      nil ->
        {:ok, nil, generate_dummy_salt(email)}

      user ->
        case Repo.get(RefMD.Encryption.UserEncryptedMasterKey, user.id) do
          nil -> {:ok, nil, generate_dummy_salt(email)}
          master_key -> {:ok, master_key, master_key.salt}
        end
    end
  end

  defp generate_dummy_salt(email) do
    secret = dummy_salt_secret()

    :crypto.mac(:hmac, :sha256, secret, email)
    |> binary_part(0, 16)
  end

  defp dummy_salt_secret do
    case Application.get_env(:refmd, :dummy_salt_secret) do
      nil ->
        raise "DUMMY_SALT_SECRET is not configured. Set DUMMY_SALT_SECRET environment variable."

      secret when is_binary(secret) ->
        secret
    end
  end

  def verify_auth_key(email, auth_key) do
    case get_user_by_email(email) do
      nil ->
        Bcrypt.no_user_verify()
        {:error, :invalid_credentials}

      user ->
        case Repo.get(RefMD.Encryption.UserEncryptedMasterKey, user.id) do
          nil ->
            Bcrypt.no_user_verify()
            {:error, :invalid_credentials}

          master_key ->
            if Bcrypt.verify_pass(auth_key, master_key.auth_key_hash) do
              {:ok, user}
            else
              {:error, :invalid_credentials}
            end
        end
    end
  end
end
