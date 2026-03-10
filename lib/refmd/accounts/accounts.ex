defmodule RefMD.Accounts do
  @moduledoc """
  The Accounts context. Manages users, sessions, and devices.
  """

  import Ecto.Query

  alias RefMD.Accounts.{
    Device,
    DeviceRevocationEvent,
    PasswordResetToken,
    PendingDevice,
    PopChallenge,
    RecoveryChallenge,
    Session,
    TrustTransferNonce,
    TrustTransferState,
    User,
    UserSettings
  }

  alias RefMD.Repo

  # ── Users ──────────────────────────────────────

  @spec get_user(Ecto.UUID.t()) :: User.t() | nil
  def get_user(id), do: Repo.get(User, id)

  @spec get_user_by_email(String.t()) :: User.t() | nil
  def get_user_by_email(email) when is_binary(email) do
    Repo.get_by(User, email: String.downcase(email))
  end

  @spec create_user(map()) :: {:ok, User.t()} | {:error, Ecto.Changeset.t()}
  def create_user(attrs) do
    %User{}
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  @spec create_user_with_struct(User.t(), map()) :: {:ok, User.t()} | {:error, Ecto.Changeset.t()}
  def create_user_with_struct(%User{} = user_struct, attrs) do
    user_struct
    |> User.changeset(attrs)
    |> Repo.insert()
  end

  @spec create_user_settings(Ecto.UUID.t()) ::
          {:ok, UserSettings.t()} | {:error, Ecto.Changeset.t()}
  def create_user_settings(user_id) do
    %UserSettings{user_id: user_id, updated_at: DateTime.utc_now()}
    |> Repo.insert()
  end

  @spec update_encryption_setup(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def update_encryption_setup(user_id) do
    from(u in User, where: u.id == ^user_id)
    |> Repo.update_all(set: [encryption_setup_at: DateTime.utc_now()])
  end

  # ── Sessions ───────────────────────────────────

  @session_ttl_default 24 * 60 * 60
  @session_ttl_remember 30 * 24 * 60 * 60

  @spec create_session(Ecto.UUID.t(), map()) ::
          {:ok, Session.t(), binary()} | {:error, Ecto.Changeset.t()}
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

  @spec get_valid_session_by_token(binary()) :: {:ok, Session.t()} | {:error, :invalid_session}
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

  @spec get_valid_session_by_token_base64(String.t()) ::
          {:ok, Session.t()} | {:error, :invalid_session | :invalid_token}
  def get_valid_session_by_token_base64(token_base64) do
    case Base.url_decode64(token_base64, padding: false) do
      {:ok, raw_token} -> get_valid_session_by_token(raw_token)
      :error -> {:error, :invalid_token}
    end
  end

  @spec get_session(Ecto.UUID.t()) :: Session.t() | nil
  def get_session(session_id), do: Repo.get(Session, session_id)

  @spec delete_session(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def delete_session(session_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.delete_all()
  end

  @spec bind_pending_device_to_session(Ecto.UUID.t(), Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def bind_pending_device_to_session(session_id, pending_device_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.update_all(set: [pending_device_id: pending_device_id])
  end

  @spec delete_other_sessions(Ecto.UUID.t(), Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def delete_other_sessions(user_id, current_session_id) do
    from(s in Session,
      where: s.user_id == ^user_id and s.id != ^current_session_id
    )
    |> Repo.delete_all()
  end

  @spec delete_all_sessions(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def delete_all_sessions(user_id) do
    from(s in Session, where: s.user_id == ^user_id)
    |> Repo.delete_all()
  end

  @spec touch_session(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def touch_session(session_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.update_all(set: [last_seen_at: DateTime.utc_now()])
  end

  @spec update_session_verified_at(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def update_session_verified_at(session_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.update_all(set: [last_verified_at: DateTime.utc_now()])
  end

  @spec touch_device(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def touch_device(device_id) do
    from(d in Device, where: d.id == ^device_id and is_nil(d.revoked_at))
    |> Repo.update_all(set: [last_seen_at: DateTime.utc_now()])
  end

  @spec bind_session_to_device(Ecto.UUID.t(), Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def bind_session_to_device(session_id, device_id) do
    from(s in Session, where: s.id == ^session_id and is_nil(s.device_id))
    |> Repo.update_all(set: [device_id: device_id, is_recovery: false])
  end

  # ── Devices ────────────────────────────────────

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
         true <- verify_ed25519_signature(message, identity_signature, signing_pub) do
      now = DateTime.utc_now()

      Repo.transaction(fn ->
        # Lock user row to serialize concurrent bootstrap attempts
        Repo.one!(from(u in RefMD.Accounts.User, where: u.id == ^user_id, lock: "FOR UPDATE"))
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

  @spec user_owns_pending_device?(Ecto.UUID.t(), Ecto.UUID.t()) :: boolean()
  def user_owns_pending_device?(user_id, device_id) do
    now = DateTime.utc_now()

    from(pd in PendingDevice,
      where: pd.id == ^device_id and pd.user_id == ^user_id and pd.expires_at > ^now
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

  # ── Pending Devices ────────────────────────────

  @spec create_pending_device(map()) :: {:ok, PendingDevice.t()} | {:error, Ecto.Changeset.t()}
  def create_pending_device(attrs) do
    now = DateTime.utc_now()
    expires_at = DateTime.add(now, 5 * 60, :second)

    %PendingDevice{created_at: now, expires_at: expires_at}
    |> PendingDevice.changeset(attrs)
    |> Repo.insert()
  end

  @spec get_valid_pending_device(Ecto.UUID.t()) :: PendingDevice.t() | nil
  def get_valid_pending_device(id) do
    now = DateTime.utc_now()

    from(pd in PendingDevice,
      where: pd.id == ^id and pd.expires_at > ^now
    )
    |> Repo.one()
  end

  @spec get_user_pending_devices(Ecto.UUID.t()) :: [PendingDevice.t()]
  def get_user_pending_devices(user_id) do
    now = DateTime.utc_now()

    from(pd in PendingDevice,
      where: pd.user_id == ^user_id and pd.expires_at > ^now,
      order_by: [desc: :created_at]
    )
    |> Repo.all()
  end

  @spec get_pending_device_status(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, String.t()} | {:error, :not_found}
  def get_pending_device_status(user_id, device_id) do
    case Repo.get(PendingDevice, device_id) do
      nil ->
        resolve_device_status(user_id, device_id)

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

  defp resolve_device_status(user_id, device_id) do
    case get_device(device_id) do
      %{user_id: ^user_id, revoked_at: nil} ->
        if RefMD.Encryption.get_device_encrypted_umk(user_id, device_id) != nil do
          {:ok, "approved"}
        else
          {:ok, "pending"}
        end

      _ ->
        {:ok, "expired"}
    end
  end

  @spec delete_pending_device(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def delete_pending_device(id) do
    from(pd in PendingDevice, where: pd.id == ^id)
    |> Repo.delete_all()
  end

  @dialyzer {:nowarn_function, replace_user_pending_device: 3}
  @spec replace_user_pending_device(Ecto.UUID.t(), Ecto.UUID.t(), map()) ::
          {:ok, %{removed_ids: [Ecto.UUID.t()], pending: PendingDevice.t()}}
          | {:error, atom(), term(), map()}
  def replace_user_pending_device(user_id, session_id, attrs) do
    now = DateTime.utc_now()
    expires_at = DateTime.add(now, 5 * 60, :second)

    Ecto.Multi.new()
    |> Ecto.Multi.run(:removed_ids, fn repo, _changes ->
      ids =
        from(pd in PendingDevice,
          where: pd.user_id == ^user_id and pd.expires_at > ^now,
          select: pd.id
        )
        |> repo.all()

      if ids != [] do
        from(pd in PendingDevice, where: pd.id in ^ids)
        |> repo.delete_all()
      end

      {:ok, ids}
    end)
    |> Ecto.Multi.insert(
      :pending,
      %PendingDevice{created_at: now, expires_at: expires_at}
      |> PendingDevice.changeset(attrs)
    )
    |> Ecto.Multi.run(:bind_session, fn repo, %{pending: pending} ->
      from(s in Session, where: s.id == ^session_id)
      |> repo.update_all(set: [pending_device_id: pending.id])

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

  @spec approve_pending_device(PendingDevice.t(), binary(), keyword()) ::
          {:ok, Device.t()} | {:error, atom() | Ecto.Changeset.t()}
  def approve_pending_device(pending_device, identity_signature, opts \\ []) do
    user_id = pending_device.user_id
    is_recovery = Keyword.get(opts, :is_recovery, false)

    first_device = Keyword.get(opts, :first_device, false)

    with {:ok, signing_pub} <- get_identity_signing_public_key(user_id),
         action = determine_signature_action(user_id, is_recovery),
         message = build_device_signature_message(action, pending_device),
         true <- verify_ed25519_signature(message, identity_signature, signing_pub) do
      execute_approve_pending_device(pending_device, identity_signature, user_id, first_device)
    else
      false -> {:error, :invalid_signature}
      {:error, reason} -> {:error, reason}
    end
  end

  defp execute_approve_pending_device(pending_device, identity_signature, user_id, first_device) do
    Repo.transaction(fn ->
      # Re-check inside transaction to prevent race on first-device auto-approval
      if first_device, do: reject_if_has_devices(user_id, :not_first_device)

      device =
        insert_device_or_rollback(build_approved_device(pending_device, identity_signature))

      Repo.delete_all(from(pd in PendingDevice, where: pd.id == ^pending_device.id))
      device
    end)
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
      "device_ecdh_public_key" =>
        Base.url_encode64(pending_device.ecdh_public_key, padding: false),
      "device_signing_public_key" =>
        Base.url_encode64(pending_device.signing_public_key, padding: false),
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

  defp build_approved_device(pending_device, identity_signature) do
    now = DateTime.utc_now()

    %Device{
      id: pending_device.id,
      user_id: pending_device.user_id,
      name: pending_device.name,
      device_type: pending_device.device_type,
      ecdh_public_key: pending_device.ecdh_public_key,
      signing_public_key: pending_device.signing_public_key,
      identity_signature: identity_signature,
      client_nonce: pending_device.client_nonce,
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

  # ── PoP Challenges ────────────────────────────

  @pop_challenge_ttl 5 * 60

  @spec create_pop_challenge(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, binary()} | {:error, Ecto.Changeset.t()}
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

  @spec consume_pop_challenge(binary(), Ecto.UUID.t(), Ecto.UUID.t()) ::
          :ok | {:error, :invalid_challenge}
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

  @spec cleanup_expired_pop_challenges() :: {non_neg_integer(), nil}
  def cleanup_expired_pop_challenges do
    now = DateTime.utc_now()

    from(pc in PopChallenge, where: pc.expires_at <= ^now)
    |> Repo.delete_all()
  end

  # ── Trust Transfer ────────────────────────────

  @trust_transfer_nonce_ttl 5 * 60
  @trust_transfer_max_payload_bytes 1_048_576

  @spec create_trust_transfer_nonce(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, binary(), DateTime.t()} | {:error, Ecto.Changeset.t()}
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

  @spec consume_trust_transfer_nonce(Ecto.UUID.t(), Ecto.UUID.t(), binary()) ::
          :ok | {:error, :invalid_nonce}
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

  @spec trust_transfer_max_payload_bytes() :: pos_integer()
  def trust_transfer_max_payload_bytes, do: @trust_transfer_max_payload_bytes

  @spec save_trust_transfer_state(map()) ::
          {:ok, TrustTransferState.t()} | {:error, Ecto.Changeset.t()}
  def save_trust_transfer_state(attrs) do
    %TrustTransferState{created_at: DateTime.utc_now()}
    |> TrustTransferState.changeset(attrs)
    |> Repo.insert(
      on_conflict: {:replace, [:sender_device_id, :ciphertext, :nonce, :signature, :created_at]},
      conflict_target: [:user_id, :target_device_id]
    )
  end

  @spec consume_trust_transfer_state(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, TrustTransferState.t()} | {:error, :not_found}
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
    from(s in Session,
      where: s.user_id == ^user_id and (s.device_id == ^device_id or is_nil(s.device_id))
    )
    |> Repo.delete_all()
  end

  defp invalidate_revoked_device_sessions(_user_id, device_id, _revocation_mode) do
    from(s in Session, where: s.device_id == ^device_id)
    |> Repo.delete_all()
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

      verify_ed25519_signature(message, identity_signature, signing_pub)
    end
  end

  defp build_revocation_signature_message(
         user_id,
         device_id,
         revocation_mode,
         revoked_at_ms,
         revoked_by_device_id
       ) do
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

  @spec create_recovery_challenge(Ecto.UUID.t()) :: {:ok, binary()} | {:error, Ecto.Changeset.t()}
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

  @spec verify_recovery_session(Ecto.UUID.t(), binary(), binary(), integer()) ::
          :ok | {:error, :invalid_recovery}
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

  @spec delete_expired_pop_challenges() :: {non_neg_integer(), nil}
  def delete_expired_pop_challenges do
    now = DateTime.utc_now()

    from(c in PopChallenge, where: c.expires_at < ^now)
    |> Repo.delete_all()
  end

  @spec delete_expired_sessions() :: {non_neg_integer(), nil}
  def delete_expired_sessions do
    now = DateTime.utc_now()

    from(s in Session, where: s.expires_at < ^now)
    |> Repo.delete_all()
  end

  @spec delete_expired_recovery_challenges() :: {non_neg_integer(), nil}
  def delete_expired_recovery_challenges do
    now = DateTime.utc_now()

    from(c in RecoveryChallenge, where: c.expires_at < ^now)
    |> Repo.delete_all()
  end

  @spec delete_expired_pending_devices() :: {non_neg_integer(), nil}
  def delete_expired_pending_devices do
    now = DateTime.utc_now()

    from(pd in PendingDevice, where: pd.expires_at < ^now)
    |> Repo.delete_all()
  end

  @spec delete_expired_trust_transfer_nonces() :: {non_neg_integer(), nil}
  def delete_expired_trust_transfer_nonces do
    now = DateTime.utc_now()

    from(n in TrustTransferNonce, where: n.expires_at < ^now)
    |> Repo.delete_all()
  end

  # ── Password Reset ────────────────────────────

  @password_reset_ttl 60 * 60
  @password_reset_rate_limit 5 * 60

  @spec create_password_reset_token(Ecto.UUID.t()) ::
          {:ok, binary()} | {:error, Ecto.Changeset.t()}
  def create_password_reset_token(user_id) do
    token = :crypto.strong_rand_bytes(32)
    token_hash = :crypto.hash(:sha256, token)
    now = DateTime.utc_now()

    Repo.transaction(fn ->
      case %PasswordResetToken{created_at: now}
           |> PasswordResetToken.changeset(%{
             user_id: user_id,
             token_hash: token_hash,
             expires_at: DateTime.add(now, @password_reset_ttl, :second)
           })
           |> Repo.insert() do
        {:ok, _} ->
          from(u in User, where: u.id == ^user_id)
          |> Repo.update_all(set: [password_reset_requested_at: now])

          token

        {:error, changeset} ->
          Repo.rollback(changeset)
      end
    end)
  end

  @spec can_send_password_reset?(Ecto.UUID.t()) :: boolean()
  def can_send_password_reset?(user_id) do
    cutoff = DateTime.add(DateTime.utc_now(), -@password_reset_rate_limit, :second)

    case Repo.get(User, user_id) do
      %{password_reset_requested_at: nil} ->
        true

      %{password_reset_requested_at: requested_at} ->
        DateTime.compare(requested_at, cutoff) != :gt

      nil ->
        true
    end
  end

  @spec verify_password_reset_token(binary()) :: {:ok, Ecto.UUID.t()} | {:error, :invalid_token}
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
        nil ->
          Repo.rollback(:invalid_token)

        token ->
          Repo.delete!(token)
          token.user_id
      end
    end)
  end

  @spec delete_expired_password_reset_tokens() :: {non_neg_integer(), nil}
  def delete_expired_password_reset_tokens do
    now = DateTime.utc_now()

    from(t in PasswordResetToken, where: t.expires_at < ^now)
    |> Repo.delete_all()
  end

  # ── Authentication Helpers ─────────────────────

  @spec get_salt_for_email(String.t()) ::
          {:ok, RefMD.Encryption.UserEncryptedMasterKey.t() | nil, binary()}
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

  @spec verify_auth_key(String.t(), String.t()) ::
          {:ok, User.t()} | {:error, :invalid_credentials}
  def verify_auth_key(email, auth_key) do
    with %User{} = user <- get_user_by_email(email),
         auth_key_hash when auth_key_hash != nil <- get_auth_key_hash(user.id) do
      verify_auth_key_hash(user, auth_key, auth_key_hash)
    else
      _ ->
        Bcrypt.no_user_verify()
        {:error, :invalid_credentials}
    end
  end

  defp verify_auth_key_hash(user, auth_key, auth_key_hash) do
    if Bcrypt.verify_pass(auth_key, auth_key_hash) do
      {:ok, user}
    else
      {:error, :invalid_credentials}
    end
  end

  defp get_auth_key_hash(user_id) do
    case Repo.get(RefMD.Encryption.UserEncryptedMasterKey, user_id) do
      nil -> nil
      %{auth_key_hash: nil} -> nil
      master_key -> master_key.auth_key_hash
    end
  end
end
