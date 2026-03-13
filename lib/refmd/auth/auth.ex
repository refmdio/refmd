defmodule RefMD.Auth do
  @moduledoc """
  The Auth context. Manages sessions, authentication challenges, and trust transfer.
  """

  import Ecto.Query

  alias RefMD.Auth.{
    PasswordResetToken,
    PopChallenge,
    RecoveryChallenge,
    Session,
    TrustTransferNonce,
    TrustTransferState
  }

  alias RefMD.Repo

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

  @spec bind_device_registration_to_session(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {non_neg_integer(), nil}
  def bind_device_registration_to_session(session_id, device_registration_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.update_all(set: [device_registration_id: device_registration_id])
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

  @spec bind_session_to_device(Ecto.UUID.t(), Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def bind_session_to_device(session_id, device_id) do
    from(s in Session, where: s.id == ^session_id and is_nil(s.device_id))
    |> Repo.update_all(set: [device_id: device_id, is_recovery: false])
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

  # ── Trust Transfer ────────────────────────────

  @trust_transfer_nonce_ttl 5 * 60
  @trust_transfer_max_payload_bytes 1_048_576

  @spec create_trust_transfer_nonce(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, binary(), DateTime.t()} | {:error, Ecto.Changeset.t()}
  def create_trust_transfer_nonce(user_id, device_id) do
    nonce = :crypto.strong_rand_bytes(32)
    now = DateTime.utc_now()

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
      conflict_target: :device_id
    )
  end

  @spec consume_trust_transfer_state(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {:ok, TrustTransferState.t()} | {:error, :not_found}
  def consume_trust_transfer_state(user_id, device_id) do
    Repo.transaction(fn ->
      query =
        from(s in TrustTransferState,
          where: s.user_id == ^user_id and s.device_id == ^device_id,
          lock: "FOR UPDATE"
        )

      case Repo.one(query) do
        nil ->
          Repo.rollback(:not_found)

        state ->
          Repo.delete_all(
            from(s in TrustTransferState,
              where: s.user_id == ^user_id and s.device_id == ^device_id
            )
          )

          state
      end
    end)
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
           user when user != nil <- RefMD.Users.get_user(user_id),
           true <- verify_recovery_timestamp(timestamp),
           message = build_recovery_signature_message(challenge, user.email, timestamp),
           true <- RefMD.Crypto.verify_ed25519_signature(message, signature, signing_pub) do
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

  @spec delete_device_sessions(Ecto.UUID.t()) :: {non_neg_integer(), nil}
  def delete_device_sessions(device_id) do
    from(s in Session, where: s.device_id == ^device_id)
    |> Repo.delete_all()
  end

  @spec delete_device_and_unbound_sessions(Ecto.UUID.t(), Ecto.UUID.t()) ::
          {non_neg_integer(), nil}
  def delete_device_and_unbound_sessions(user_id, device_id) do
    from(s in Session,
      where: s.user_id == ^user_id and (s.device_id == ^device_id or is_nil(s.device_id))
    )
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
    token_hash = Base.url_encode64(:crypto.hash(:sha256, token), padding: false)
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

  @spec can_send_password_reset?(Ecto.UUID.t()) :: boolean()
  def can_send_password_reset?(user_id) do
    cutoff = DateTime.add(DateTime.utc_now(), -@password_reset_rate_limit, :second)

    not Repo.exists?(
      from(t in PasswordResetToken,
        where: t.user_id == ^user_id and t.created_at > ^cutoff
      )
    )
  end

  @spec verify_password_reset_token(binary()) :: {:ok, Ecto.UUID.t()} | {:error, :invalid_token}
  def verify_password_reset_token(raw_token) do
    token_hash = Base.url_encode64(:crypto.hash(:sha256, raw_token), padding: false)
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
    case RefMD.Users.get_user_by_email(email) do
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
          {:ok, RefMD.Users.User.t()} | {:error, :invalid_credentials}
  def verify_auth_key(email, auth_key) do
    with %RefMD.Users.User{} = user <- RefMD.Users.get_user_by_email(email),
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

  # ── Shared Helpers ──────────────────────────────

  defp get_identity_signing_public_key(user_id) do
    case RefMD.Encryption.get_user_identity_public_key(user_id) do
      nil -> {:error, :identity_key_not_found}
      key -> {:ok, key.signing_public_key}
    end
  end
end
