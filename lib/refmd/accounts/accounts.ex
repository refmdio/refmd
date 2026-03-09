defmodule RefMD.Accounts do
  @moduledoc """
  The Accounts context. Manages users, sessions, and devices.
  """

  import Ecto.Query
  alias RefMD.Repo
  alias RefMD.Accounts.{
    User,
    UserSettings,
    Session,
    Device,
    PendingDevice,
    PopChallenge,
    TrustTransferNonce,
    TrustTransferState,
    DeviceRevocationEvent,
    RecoveryChallenge,
    PasswordResetToken
  }

  # ── Users ──────────────────────────────────────

  def get_user(id), do: Repo.get(User, id)

  def get_user_by_email(email) when is_binary(email) do
    Repo.get_by(User, email: String.downcase(email))
  end

  def create_user(attrs) do
    %User{}
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  def create_user_with_struct(%User{} = user_struct, attrs) do
    user_struct
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

  def get_session(session_id), do: Repo.get(Session, session_id)

  def delete_session(session_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.delete_all()
  end

  def bind_pending_device_to_session(session_id, pending_device_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.update_all(set: [pending_device_id: pending_device_id])
  end

  def delete_other_sessions(user_id, current_session_id) do
    from(s in Session,
      where: s.user_id == ^user_id and s.id != ^current_session_id
    )
    |> Repo.delete_all()
  end

  def delete_all_sessions(user_id) do
    from(s in Session, where: s.user_id == ^user_id)
    |> Repo.delete_all()
  end

  def touch_session(session_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.update_all(set: [last_seen_at: DateTime.utc_now()])
  end

  def touch_device(device_id) do
    from(d in Device, where: d.id == ^device_id and is_nil(d.revoked_at))
    |> Repo.update_all(set: [last_seen_at: DateTime.utc_now()])
  end

  def bind_session_to_device(session_id, device_id) do
    from(s in Session, where: s.id == ^session_id and is_nil(s.device_id))
    |> Repo.update_all(set: [device_id: device_id, is_recovery: false])
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

  def bootstrap_first_device(attrs, identity_signature) do
    user_id = attrs.user_id

    with {:ok, signing_pub} <- get_identity_signing_public_key(user_id),
         message = build_device_signature_message("device_registration", attrs),
         true <- verify_ed25519_signature(message, identity_signature, signing_pub) do
      now = DateTime.utc_now()

      Repo.transaction(fn ->
        # Lock user row to serialize concurrent bootstrap attempts
        Repo.one!(from(u in RefMD.Accounts.User, where: u.id == ^user_id, lock: "FOR UPDATE"))

        if user_has_any_device_records?(user_id) do
          Repo.rollback(:already_has_devices)
        end

        case %Device{
               id: Ecto.UUID.generate(),
               user_id: user_id,
               name: attrs.name,
               device_type: attrs.device_type,
               ecdh_public_key: attrs.ecdh_public_key,
               signing_public_key: attrs.signing_public_key,
               identity_signature: identity_signature,
               client_nonce: attrs.client_nonce,
               last_seen_at: now,
               created_at: now
             }
             |> Repo.insert() do
          {:ok, device} -> device
          {:error, changeset} -> Repo.rollback(changeset)
        end
      end)
    else
      false -> {:error, :invalid_signature}
      {:error, reason} -> {:error, reason}
    end
  end

  def user_has_devices?(user_id) do
    from(d in Device, where: d.user_id == ^user_id and is_nil(d.revoked_at))
    |> Repo.exists?()
  end

  def user_has_any_device_records?(user_id) do
    from(d in Device, where: d.user_id == ^user_id)
    |> Repo.exists?()
  end

  def device_exists?(device_id) do
    from(d in Device, where: d.id == ^device_id)
    |> Repo.exists?()
  end

  def user_owns_active_device?(user_id, device_id) do
    from(d in Device,
      where: d.id == ^device_id and d.user_id == ^user_id and is_nil(d.revoked_at)
    )
    |> Repo.exists?()
  end

  def user_owns_pending_device?(user_id, device_id) do
    now = DateTime.utc_now()

    from(pd in PendingDevice,
      where: pd.id == ^device_id and pd.user_id == ^user_id and pd.expires_at > ^now
    )
    |> Repo.exists?()
  end

  def rename_device(user_id, device_id, name) do
    case from(d in Device,
           where: d.id == ^device_id and d.user_id == ^user_id and is_nil(d.revoked_at)
         )
         |> Repo.one() do
      nil -> {:error, :not_found}
      device -> device |> Ecto.Changeset.change(%{name: name}) |> Repo.update()
    end
  end

  # ── Pending Devices ────────────────────────────

  def create_pending_device(attrs) do
    now = DateTime.utc_now()
    expires_at = DateTime.add(now, 5 * 60, :second)

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

  def get_user_pending_devices(user_id) do
    now = DateTime.utc_now()

    from(pd in PendingDevice,
      where: pd.user_id == ^user_id and pd.expires_at > ^now,
      order_by: [desc: :created_at]
    )
    |> Repo.all()
  end

  def get_pending_device_status(user_id, device_id) do
    case Repo.get(PendingDevice, device_id) do
      nil ->
        case get_device(device_id) do
          %{user_id: ^user_id} ->
            {:ok, "approved"}

          _ ->
            {:error, :not_found}
        end

      %{user_id: ^user_id} = pd ->
        if DateTime.compare(pd.expires_at, DateTime.utc_now()) == :gt do
          {:ok, "pending"}
        else
          {:ok, "expired"}
        end

      _ ->
        {:error, :not_found}
    end
  end

  def delete_pending_device(id) do
    from(pd in PendingDevice, where: pd.id == ^id)
    |> Repo.delete_all()
  end

  def approve_pending_device(pending_device, identity_signature, opts \\ []) do
    user_id = pending_device.user_id
    is_recovery = Keyword.get(opts, :is_recovery, false)

    first_device = Keyword.get(opts, :first_device, false)

    with {:ok, signing_pub} <- get_identity_signing_public_key(user_id),
         action = determine_signature_action(user_id, is_recovery),
         message = build_device_signature_message(action, pending_device),
         true <- verify_ed25519_signature(message, identity_signature, signing_pub) do
      Repo.transaction(fn ->
        # Re-check inside transaction to prevent race on first-device auto-approval
        if first_device and user_has_any_device_records?(user_id) do
          Repo.rollback(:not_first_device)
        end

        case %Device{
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
             |> Repo.insert() do
          {:ok, device} ->
            Repo.delete_all(from(pd in PendingDevice, where: pd.id == ^pending_device.id))
            device

          {:error, changeset} ->
            Repo.rollback(changeset)
        end
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

  # ── PoP Challenges ────────────────────────────

  @pop_challenge_ttl 5 * 60

  def create_pop_challenge(user_id, device_id) do
    challenge = :crypto.strong_rand_bytes(32)
    challenge_hash = :crypto.hash(:sha256, challenge)
    now = DateTime.utc_now()

    case %PopChallenge{created_at: now}
         |> PopChallenge.changeset(%{
           user_id: user_id,
           device_id: device_id,
           challenge_hash: challenge_hash,
           expires_at: DateTime.add(now, @pop_challenge_ttl, :second)
         })
         |> Repo.insert() do
      {:ok, _} -> {:ok, challenge}
      {:error, changeset} -> {:error, changeset}
    end
  end

  def consume_pop_challenge(challenge, user_id, device_id) do
    challenge_hash = :crypto.hash(:sha256, challenge)
    now = DateTime.utc_now()

    query =
      from(pc in PopChallenge,
        where:
          pc.challenge_hash == ^challenge_hash and
            pc.user_id == ^user_id and
            pc.device_id == ^device_id and
            pc.expires_at > ^now
      )

    case Repo.delete_all(query) do
      {1, _} -> :ok
      {0, _} -> {:error, :invalid_challenge}
    end
  end

  def cleanup_expired_pop_challenges do
    now = DateTime.utc_now()

    from(pc in PopChallenge, where: pc.expires_at <= ^now)
    |> Repo.delete_all()
  end

  # ── Trust Transfer ────────────────────────────

  @trust_transfer_nonce_ttl 5 * 60
  @trust_transfer_max_payload_bytes 1_048_576

  def create_trust_transfer_nonce(user_id, device_id) do
    nonce = :crypto.strong_rand_bytes(32)
    now = DateTime.utc_now()

    # Upsert: replace existing nonce for same (user, device)
    %TrustTransferNonce{created_at: now}
    |> TrustTransferNonce.changeset(%{
      user_id: user_id,
      device_id: device_id,
      nonce: nonce,
      expires_at: DateTime.add(now, @trust_transfer_nonce_ttl, :second)
    })
    |> Repo.insert(
      on_conflict: {:replace, [:nonce, :expires_at, :created_at]},
      conflict_target: [:user_id, :device_id]
    )
    |> case do
      {:ok, record} -> {:ok, record.nonce, record.expires_at}
      {:error, changeset} -> {:error, changeset}
    end
  end

  def consume_trust_transfer_nonce(user_id, device_id, transfer_nonce) do
    now = DateTime.utc_now()

    query =
      from(n in TrustTransferNonce,
        where:
          n.user_id == ^user_id and
            n.device_id == ^device_id and
            n.nonce == ^transfer_nonce and
            n.expires_at > ^now
      )

    case Repo.delete_all(query) do
      {1, _} -> :ok
      {0, _} -> {:error, :invalid_nonce}
    end
  end

  def trust_transfer_max_payload_bytes, do: @trust_transfer_max_payload_bytes

  def save_trust_transfer_state(attrs) do
    %TrustTransferState{created_at: DateTime.utc_now()}
    |> TrustTransferState.changeset(attrs)
    |> Repo.insert(
      on_conflict: {:replace, [:sender_device_id, :ciphertext, :nonce, :signature, :created_at]},
      conflict_target: [:user_id, :target_device_id]
    )
  end

  def consume_trust_transfer_state(user_id, device_id) do
    Repo.transaction(fn ->
      query =
        from(s in TrustTransferState,
          where: s.user_id == ^user_id and s.target_device_id == ^device_id,
          lock: "FOR UPDATE"
        )

      case Repo.one(query) do
        nil ->
          Repo.rollback(:not_found)

        state ->
          Repo.delete_all(
            from(s in TrustTransferState,
              where: s.user_id == ^user_id and s.target_device_id == ^device_id
            )
          )

          state
      end
    end)
  end

  # ── Device Revocation ─────────────────────────

  def revoke_device(user_id, device_id, revoked_by_device_id, revocation_mode, identity_signature, revoked_at_ms) do
    now = DateTime.utc_now()

    Repo.transaction(fn ->
      # Set revoked_at on the device
      case from(d in Device,
             where: d.id == ^device_id and d.user_id == ^user_id and is_nil(d.revoked_at)
           )
           |> Repo.update_all(set: [revoked_at: now]) do
        {1, _} -> :ok
        {0, _} -> Repo.rollback(:already_revoked)
      end

      # Invalidate all sessions for the revoked device.
      # For security mode: also delete unbound sessions (device_id IS NULL) for the user,
      # since we cannot determine which unbound session belongs to the compromised device.
      if revocation_mode == "security" do
        from(s in Session,
          where: s.user_id == ^user_id and (s.device_id == ^device_id or is_nil(s.device_id))
        )
        |> Repo.delete_all()
      else
        from(s in Session, where: s.device_id == ^device_id)
        |> Repo.delete_all()
      end

      # Store revocation event with identity signature (revoked_at in Unix ms for signature verification)
      _event =
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

      # For security mode, mark workspaces for KEK/DEK rotation
      workspaces_for_rotation =
        if revocation_mode == "security" do
          ws_with_versions = RefMD.Workspaces.get_user_workspace_ids_with_kek_version(user_id)
          ws_ids = Enum.map(ws_with_versions, &elem(&1, 0))

          RefMD.Workspaces.mark_kek_rotation_needed(ws_ids, user_id)
          RefMD.Workspaces.mark_dek_rotation_needed(ws_ids)

          Enum.map(ws_with_versions, fn {id, version} ->
            %{workspace_id: id, current_kek_version: version}
          end)
        else
          []
        end

      %{workspaces_needing_kek_rotation: workspaces_for_rotation}
    end)
  end

  def verify_revocation_signature(user_id, device_id, revocation_mode, revoked_by_device_id, revoked_at_ms, identity_signature) do
    with {:ok, signing_pub} <- get_identity_signing_public_key(user_id) do
      message = build_revocation_signature_message(
        user_id, device_id, revocation_mode, revoked_at_ms, revoked_by_device_id
      )

      verify_ed25519_signature(message, identity_signature, signing_pub)
    end
  end

  defp build_revocation_signature_message(user_id, device_id, revocation_mode, revoked_at_ms, revoked_by_device_id) do
    fields = %{
      "action" => "device_revocation",
      "device_id" => device_id,
      "protocol" => "refmd",
      "revocation_mode" => revocation_mode,
      "revoked_at" => revoked_at_ms,
      "revoked_by_device_id" => revoked_by_device_id,
      "user_id" => user_id,
      "version" => 1
    }

    pairs =
      fields
      |> Enum.sort_by(fn {k, _} -> k end)
      |> Enum.map(fn {k, v} ->
        Jason.encode!(k) <> ":" <> encode_jcs_value(v)
      end)

    "{" <> Enum.join(pairs, ",") <> "}"
  end

  # ── Recovery ──────────────────────────────────

  @recovery_challenge_ttl 5 * 60
  @recovery_timestamp_past_tolerance_ms 5 * 60 * 1000
  @recovery_timestamp_future_tolerance_ms 1 * 60 * 1000

  def create_recovery_challenge(user_id) do
    challenge = :crypto.strong_rand_bytes(32)
    challenge_hash = :crypto.hash(:sha256, challenge)
    now = DateTime.utc_now()

    case %RecoveryChallenge{created_at: now}
         |> RecoveryChallenge.changeset(%{
           user_id: user_id,
           challenge_hash: challenge_hash,
           expires_at: DateTime.add(now, @recovery_challenge_ttl, :second)
         })
         |> Repo.insert() do
      {:ok, _} -> {:ok, challenge}
      {:error, changeset} -> {:error, changeset}
    end
  end

  def verify_recovery_session(user_id, challenge, signature, timestamp) do
    challenge_hash = :crypto.hash(:sha256, challenge)
    now = DateTime.utc_now()

    lock_query =
      from(rc in RecoveryChallenge,
        where:
          rc.challenge_hash == ^challenge_hash and
            rc.user_id == ^user_id and
            rc.expires_at > ^now,
        lock: "FOR UPDATE"
      )

    Repo.transaction(fn ->
      with %RecoveryChallenge{} = rc <- Repo.one(lock_query),
           {:ok, signing_pub} <- get_identity_signing_public_key(user_id),
           user when user != nil <- get_user(user_id),
           true <- verify_recovery_timestamp(timestamp),
           message = build_recovery_signature_message(challenge, user.email, timestamp),
           true <- verify_ed25519_signature(message, signature, signing_pub) do
        Repo.delete(rc)
        :ok
      else
        nil -> Repo.rollback(:invalid_recovery)
        false -> Repo.rollback(:invalid_recovery)
        {:error, _} -> Repo.rollback(:invalid_recovery)
      end
    end)
    |> case do
      {:ok, :ok} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify_recovery_timestamp(timestamp_ms) do
    now_ms = DateTime.utc_now() |> DateTime.to_unix(:millisecond)
    diff_ms = now_ms - timestamp_ms

    diff_ms >= -@recovery_timestamp_future_tolerance_ms and
      diff_ms <= @recovery_timestamp_past_tolerance_ms
  end

  defp build_recovery_signature_message(challenge, email, timestamp_ms) do
    email_bytes = String.downcase(email)
    timestamp_bytes = <<timestamp_ms::little-unsigned-64>>
    "recovery-session:" <> challenge <> email_bytes <> timestamp_bytes
  end

  # ── Cleanup ───────────────────────────────────

  def delete_expired_pop_challenges do
    now = DateTime.utc_now()

    from(c in PopChallenge, where: c.expires_at < ^now)
    |> Repo.delete_all()
  end

  def delete_expired_sessions do
    now = DateTime.utc_now()

    from(s in Session, where: s.expires_at < ^now)
    |> Repo.delete_all()
  end

  def delete_expired_recovery_challenges do
    now = DateTime.utc_now()

    from(c in RecoveryChallenge, where: c.expires_at < ^now)
    |> Repo.delete_all()
  end

  def delete_expired_pending_devices do
    now = DateTime.utc_now()

    from(pd in PendingDevice, where: pd.expires_at < ^now)
    |> Repo.delete_all()
  end

  def delete_expired_trust_transfer_nonces do
    now = DateTime.utc_now()

    from(n in TrustTransferNonce, where: n.expires_at < ^now)
    |> Repo.delete_all()
  end

  # ── Password Reset ────────────────────────────

  @password_reset_ttl 60 * 60
  @password_reset_rate_limit 5 * 60

  def create_password_reset_token(user_id) do
    token = :crypto.strong_rand_bytes(32)
    token_hash = :crypto.hash(:sha256, token)
    now = DateTime.utc_now()

    case %PasswordResetToken{created_at: now}
         |> PasswordResetToken.changeset(%{
           user_id: user_id,
           token_hash: token_hash,
           expires_at: DateTime.add(now, @password_reset_ttl, :second)
         })
         |> Repo.insert() do
      {:ok, _} -> {:ok, token}
      {:error, changeset} -> {:error, changeset}
    end
  end

  def can_send_password_reset?(user_id) do
    cutoff = DateTime.add(DateTime.utc_now(), -@password_reset_rate_limit, :second)

    not Repo.exists?(
      from(t in PasswordResetToken,
        where: t.user_id == ^user_id and t.created_at > ^cutoff
      )
    )
  end

  def verify_password_reset_token(raw_token) do
    token_hash = :crypto.hash(:sha256, raw_token)
    now = DateTime.utc_now()

    Repo.transaction(fn ->
      query =
        from(t in PasswordResetToken,
          where: t.token_hash == ^token_hash and t.expires_at > ^now,
          lock: "FOR UPDATE"
        )

      case Repo.one(query) do
        nil -> Repo.rollback(:invalid_token)
        token ->
          # Invalidate token (single-use) but keep row for rate limiting (5-minute interval)
          from(t in PasswordResetToken, where: t.id == ^token.id)
          |> Repo.update_all(set: [token_hash: nil])

          token.user_id
      end
    end)
  end

  def delete_expired_password_reset_tokens do
    now = DateTime.utc_now()

    from(t in PasswordResetToken, where: t.expires_at < ^now)
    |> Repo.delete_all()
  end

  # ── Authentication Helpers ─────────────────────

  def get_salt_for_email(email) do
    case get_user_by_email(email) do
      nil ->
        {:ok, nil, generate_dummy_salt(email)}

      user ->
        case Repo.get(RefMD.Encryption.UserEncryptedMasterKey, user.id) do
          nil ->
            {:ok, nil, generate_dummy_salt(email)}

          %{salt: nil} = master_key ->
            {:ok, master_key, generate_dummy_salt(email)}

          master_key ->
            {:ok, master_key, master_key.salt}
        end
    end
  end

  defp generate_dummy_salt(email) do
    secret = dummy_salt_secret()

    :crypto.mac(:hmac, :sha256, secret, String.downcase(email))
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

          %{auth_key_hash: nil} ->
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
