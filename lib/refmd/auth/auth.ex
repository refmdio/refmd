defmodule RefMD.Auth do
  @moduledoc """
  The Auth context. Manages sessions and authentication challenges.
  """

  import Ecto.Query

  alias RefMD.Auth.{RecoveryChallenge, RrpChallenge, Session}
  alias RefMD.Crypto.{Hash, JCS, Signature, TokenSigning}
  alias RefMD.Devices
  alias RefMD.Devices.DeviceRegistration
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Security

  alias RefMD.Auth.PasswordResets, as: WPasswordResets
  # ── Password Reset (delegated to RefMD.Auth.PasswordResets) ──

  defdelegate create_password_reset_token(user_id), to: WPasswordResets
  defdelegate can_send_password_reset?(user_id), to: WPasswordResets
  defdelegate verify_password_reset_token(raw_token), to: WPasswordResets
  defdelegate delete_expired_password_reset_tokens(), to: WPasswordResets

  def user_key_directory_event_ancestry(_user_id, nil), do: []

  def user_key_directory_event_ancestry(user_id, user_pin) do
    Encryption.user_key_directory_events_after_until(user_id, 0, user_pin.event_head_sequence)
    |> Enum.map(&%{payload: &1.payload, signatures: &1.signatures})
  end

  def user_key_directory_checkpoint_ancestry(_user_id, nil), do: []

  def user_key_directory_checkpoint_ancestry(_user_id, %{checkpoint_sequence: sequence})
      when sequence <= 1,
      do: []

  def user_key_directory_checkpoint_ancestry(user_id, user_pin) do
    Encryption.user_key_directory_checkpoints_between(
      user_id,
      1,
      user_pin.checkpoint_sequence - 1
    )
    |> Enum.map(&%{payload: &1.payload, signatures: &1.signatures})
  end

  def user_identity_rotation_deletion_evidences(_user_id, nil), do: []

  def user_identity_rotation_deletion_evidences(user_id, user_pin) do
    event_hashes =
      Encryption.user_key_directory_events_after_until(user_id, 0, user_pin.event_head_sequence)
      |> Enum.filter(&(&1.event_type == "old_key_deleted"))
      |> Enum.map(& &1.event_hash)

    event_hashes
    |> Encryption.user_identity_rotation_deletion_evidences_by_event_hash()
    |> Map.values()
    |> Enum.map(fn evidence ->
      %{
        old_key_deleted_event_hash: evidence.old_key_deleted_event_hash,
        user_id: evidence.user_id,
        rotation_kind: evidence.rotation_kind,
        scope_kind: evidence.scope_kind,
        scope_id: evidence.scope_id,
        old_key_version: evidence.old_key_version,
        deletion_manifest: evidence.deletion_manifest,
        device_key_deletion_proofs: evidence.device_key_deletion_proofs,
        wipe_required_device_ids: evidence.wipe_required_device_ids
      }
    end)
  end

  @session_ttl_default 24 * 60 * 60
  @session_ttl_remember 30 * 24 * 60 * 60

  def create_session(user_id, attrs \\ %{}) do
    token = :crypto.strong_rand_bytes(32)
    token_hash = Base.url_encode64(:crypto.hash(:sha256, token), padding: false)
    remember_me = Map.get(attrs, :remember_me, false)
    ttl = if remember_me, do: @session_ttl_remember, else: @session_ttl_default
    now = DateTime.utc_now()

    session_attrs = %{
      id: Map.get(attrs, :id),
      user_id: user_id,
      device_id: Map.get(attrs, :device_id),
      device_registration_id: Map.get(attrs, :device_registration_id),
      token_hash: token_hash,
      remember_me: remember_me,
      is_recovery: Map.get(attrs, :is_recovery, false),
      identity_recovery_required: Map.get(attrs, :identity_recovery_required, false),
      recovery_session_transcript_hash: Map.get(attrs, :recovery_session_transcript_hash),
      recovery_capability_hash: Map.get(attrs, :recovery_capability_hash),
      pending_registration_binding_hash: Map.get(attrs, :pending_registration_binding_hash),
      target_key_checkpoint_sequence: Map.get(attrs, :target_key_checkpoint_sequence),
      target_key_checkpoint_hash: Map.get(attrs, :target_key_checkpoint_hash),
      candidate_user_checkpoint_sequence: Map.get(attrs, :candidate_user_checkpoint_sequence),
      candidate_user_checkpoint_hash: Map.get(attrs, :candidate_user_checkpoint_hash),
      candidate_user_event_head_sequence: Map.get(attrs, :candidate_user_event_head_sequence),
      candidate_user_event_head_hash: Map.get(attrs, :candidate_user_event_head_hash),
      candidate_user_audit_sequence: Map.get(attrs, :candidate_user_audit_sequence),
      candidate_user_audit_hash: Map.get(attrs, :candidate_user_audit_hash),
      recovered_identity_signing_key_id: Map.get(attrs, :recovered_identity_signing_key_id),
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

  def bind_device_registration_to_session(session_id, device_registration_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.update_all(set: [device_registration_id: device_registration_id])
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

  def update_session_verified_at(session_id) do
    from(s in Session, where: s.id == ^session_id)
    |> Repo.update_all(set: [last_verified_at: DateTime.utc_now()])
  end

  def bind_session_to_device(session_id, device_id) do
    from(s in Session, where: s.id == ^session_id and is_nil(s.device_id))
    |> Repo.update_all(
      set: [device_id: device_id, is_recovery: false, identity_recovery_required: false]
    )
  end

  # ── RRP Challenges ────────────────────────────

  @rrp_challenge_ttl 5 * 60

  def create_rrp_challenge(user_id, device_id, session_id) do
    challenge = :crypto.strong_rand_bytes(32)
    challenge_hash = :crypto.hash(:sha256, challenge)
    now = DateTime.utc_now()

    case %RrpChallenge{created_at: now}
         |> RrpChallenge.changeset(%{
           device_id: device_id,
           challenge_hash: challenge_hash,
           session_id_hash: Hash.blake3_base64url(session_id),
           session_kind: "user",
           subject_id: user_id,
           expires_at: DateTime.add(now, @rrp_challenge_ttl, :second)
         })
         |> Repo.insert() do
      {:ok, _} -> {:ok, challenge}
      {:error, changeset} -> {:error, changeset}
    end
  end

  def consume_rrp_challenge(challenge, user_id, device_id, session_id) do
    challenge_hash = :crypto.hash(:sha256, challenge)
    session_id_hash = Hash.blake3_base64url(session_id)
    now = DateTime.utc_now()

    query =
      from(pc in RrpChallenge,
        where:
          pc.challenge_hash == ^challenge_hash and
            pc.session_kind == "user" and
            pc.subject_id == ^user_id and
            pc.device_id == ^device_id and
            pc.session_id_hash == ^session_id_hash and
            pc.expires_at > ^now
      )

    case Repo.delete_all(query) do
      {1, _} -> :ok
      {0, _} -> {:error, :invalid_challenge}
    end
  end

  # ── Recovery ──────────────────────────────────

  @recovery_challenge_ttl 5 * 60

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

  def establish_recovery_session(
        user_id,
        challenge,
        signature,
        proof,
        registration_attrs,
        session_attrs
      )
      when is_binary(user_id) and is_binary(challenge) and is_map(signature) and is_map(proof) and
             is_map(registration_attrs) and is_map(session_attrs) do
    Repo.transaction(fn ->
      with {:ok, pending_registration} <-
             Devices.create_device_registration(registration_attrs),
           {:ok, recovery_context} <-
             verify_recovery_session_with_registration(
               user_id,
               challenge,
               signature,
               proof,
               pending_registration
             ),
           {:ok, session, token} <-
             create_session(
               user_id,
               Map.merge(session_attrs, recovery_session_attrs(recovery_context))
             ) do
        %{context: recovery_context, session: session, token: token}
      else
        _ -> Repo.rollback(:invalid_recovery)
      end
    end)
    |> case do
      {:ok, result} -> {:ok, result}
      {:error, _reason} -> {:error, :invalid_recovery}
    end
  end

  def establish_recovery_session(_, _, _, _, _, _), do: {:error, :invalid_recovery}

  defp verify_recovery_session_with_registration(
         user_id,
         challenge,
         signature,
         proof,
         pending_registration
       ) do
    with {:ok, signature} <- validate_hybrid_signature_object(signature),
         {:ok, %{hybrid_signing_public_key_material: public_material}} <-
           Encryption.user_identity_key_for_new_encryption(user_id),
         %{recovery_authorization_public_material: recovery_public_key} = master_key <-
           Encryption.get_user_encrypted_master_key(user_id),
         true <- is_map(public_material),
         challenge_hash = Hash.blake3_base64url(challenge),
         recovered_identity_key_id = Signature.compute_signing_key_id!(public_material),
         %DeviceRegistration{} <- pending_registration,
         true <- pending_registration.id == proof.pending_registration_id,
         true <- pending_registration.id == proof.recipient_device_id,
         true <- pending_registration.user_id == user_id,
         pin when not is_nil(pin) <- Encryption.current_user_key_directory_pin(user_id),
         :ok <-
           validate_recovery_candidate!(proof, pin, challenge_hash, recovered_identity_key_id),
         pending_registration_binding_hash <-
           recovery_pending_registration_binding_hash!(
             user_id,
             pending_registration,
             proof,
             pin
           ),
         true <- pending_registration_binding_hash == proof.pending_registration_binding_hash,
         {:ok, recovery_capability_hash} <-
           verify_recovery_authorization_proof(master_key, user_id, proof, challenge_hash),
         true <- recovery_capability_hash == proof.recovery_capability_hash,
         audit_checkpoint when is_map(audit_checkpoint) <-
           Security.current_audit_checkpoint!("user:#{user_id}"),
         true <- audit_checkpoint.sequence == proof.candidate_user_audit_sequence,
         true <- audit_checkpoint.event_hash == proof.candidate_user_audit_hash,
         transcript <-
           Signature.build_recovery_session_transcript!(%{
             user_id: user_id,
             recipient_device_id: proof.recipient_device_id,
             pending_registration_id: pending_registration.id,
             recovery_session_id: proof.recovery_session_id,
             server_challenge_hash: challenge_hash,
             recovered_identity_signing_key_id: recovered_identity_key_id,
             recovery_authorization_key_id: proof.recovery_authorization_key_id,
             target_key_checkpoint_sequence: proof.target_key_checkpoint_sequence,
             target_key_checkpoint_hash: proof.target_key_checkpoint_hash,
             candidate_user_checkpoint_sequence: proof.candidate_user_checkpoint_sequence,
             candidate_user_checkpoint_hash: proof.candidate_user_checkpoint_hash,
             candidate_user_event_head_sequence: proof.candidate_user_event_head_sequence,
             candidate_user_event_head_hash: proof.candidate_user_event_head_hash,
             candidate_user_audit_sequence: proof.candidate_user_audit_sequence,
             candidate_user_audit_hash: proof.candidate_user_audit_hash,
             recovery_capability_hash: proof.recovery_capability_hash,
             pending_registration_binding_hash: proof.pending_registration_binding_hash
           }),
         transcript_hash = Hash.blake3_base64url(JCS.canonical_bytes!(transcript)),
         true <- transcript_hash == proof.recovery_session_transcript_hash,
         :ok <-
           Signature.verify_hybrid_signature_result(
             "recovery_session",
             transcript,
             signature,
             public_material,
             %{
               candidate_pin: pin,
               pending_registration: pending_registration,
               recovery_session: %{
                 server_challenge_hash: challenge_hash
               }
             }
           ),
         true <- is_map(recovery_public_key),
         :ok <- consume_recovery_challenge(challenge, user_id) do
      {:ok,
       %{
         recovery_session_transcript_hash: transcript_hash,
         recovery_capability_hash: recovery_capability_hash,
         pending_registration_binding_hash: pending_registration_binding_hash,
         device_registration_id: pending_registration.id,
         target_key_checkpoint_sequence: proof.target_key_checkpoint_sequence,
         target_key_checkpoint_hash: proof.target_key_checkpoint_hash,
         candidate_user_checkpoint_sequence: pin.checkpoint_sequence,
         candidate_user_checkpoint_hash: pin.checkpoint_hash,
         candidate_user_event_head_sequence: pin.event_head_sequence,
         candidate_user_event_head_hash: pin.event_head_hash,
         candidate_user_audit_sequence: proof.candidate_user_audit_sequence,
         candidate_user_audit_hash: proof.candidate_user_audit_hash,
         recovered_identity_signing_key_id: recovered_identity_key_id,
         recovery_session_id: proof.recovery_session_id
       }}
    else
      _ -> {:error, :invalid_recovery}
    end
  rescue
    _error in [ArgumentError, MatchError] -> {:error, :invalid_recovery}
  end

  defp recovery_session_attrs(context) do
    %{
      id: context.recovery_session_id,
      is_recovery: true,
      device_registration_id: context.device_registration_id,
      recovery_session_transcript_hash: context.recovery_session_transcript_hash,
      recovery_capability_hash: context.recovery_capability_hash,
      pending_registration_binding_hash: context.pending_registration_binding_hash,
      target_key_checkpoint_sequence: context.target_key_checkpoint_sequence,
      target_key_checkpoint_hash: context.target_key_checkpoint_hash,
      candidate_user_checkpoint_sequence: context.candidate_user_checkpoint_sequence,
      candidate_user_checkpoint_hash: context.candidate_user_checkpoint_hash,
      candidate_user_event_head_sequence: context.candidate_user_event_head_sequence,
      candidate_user_event_head_hash: context.candidate_user_event_head_hash,
      candidate_user_audit_sequence: context.candidate_user_audit_sequence,
      candidate_user_audit_hash: context.candidate_user_audit_hash,
      recovered_identity_signing_key_id: context.recovered_identity_signing_key_id
    }
  end

  defp verify_recovery_authorization_proof(
         master_key,
         user_id,
         proof,
         challenge_hash
       ) do
    public_material = recovery_authorization_public_material!(master_key, user_id)
    key_id = master_key.recovery_authorization_key_id
    proof_key_id = proof.recovery_authorization_key_id
    signature = proof.recovery_authorization_proof

    transcript =
      Signature.build_recovery_authorization_proof_transcript!(%{
        user_id: user_id,
        recovery_authorization_key_id: proof_key_id,
        recipient_device_id: proof.recipient_device_id,
        pending_registration_binding_hash: proof.pending_registration_binding_hash,
        server_challenge_hash: challenge_hash
      })

    cond do
      proof_key_id != key_id ->
        {:error, :invalid_recovery}

      Signature.compute_signing_key_id!(public_material) != key_id ->
        {:error, :invalid_recovery}

      not Signature.verify_recovery_authorization_proof_signature(
        transcript,
        signature,
        public_material
      ) ->
        {:error, :invalid_recovery}

      true ->
        {:ok, recovery_capability_hash!(proof, challenge_hash)}
    end
  end

  defp recovery_authorization_public_material!(master_key, user_id) do
    material = master_key.recovery_authorization_public_material
    true = is_map(material)
    true = is_binary(JCS.canonical_bytes!(material))
    :ok = Signature.assert_public_key_material!(material)
    true = material["owner_kind"] == "identity"
    true = material["owner_id"] == user_id
    material
  end

  defp validate_recovery_candidate!(proof, pin, challenge_hash, recovered_identity_key_id) do
    :ok =
      Encryption.verify_user_key_directory_replay!(
        pin.scope_id,
        proof.candidate_user_event_ancestry,
        proof.candidate_user_checkpoint,
        checkpoint_signer_kind: "identity"
      )

    true = proof.candidate_user_checkpoint_sequence == pin.checkpoint_sequence
    true = proof.candidate_user_checkpoint_hash == pin.checkpoint_hash
    true = proof.candidate_user_event_head_sequence == pin.event_head_sequence
    true = proof.candidate_user_event_head_hash == pin.event_head_hash
    true = candidate_checkpoint_matches_pin?(proof.candidate_user_checkpoint, pin)
    Hash.assert_blake3_base64url!(challenge_hash)
    Hash.assert_blake3_base64url!(recovered_identity_key_id)

    case Encryption.active_user_key_material_in_current_checkpoint(
           pin.scope_id,
           recovered_identity_key_id
         ) do
      {:ok, _material} -> :ok
      _ -> raise ArgumentError, "recovered_identity_key_inactive"
    end
  end

  defp candidate_checkpoint_matches_pin?(
         %{"payload" => %{"sequence" => sequence, "covered_event_head" => event_head} = payload},
         pin
       ) do
    sequence == pin.checkpoint_sequence and
      Hash.blake3_base64url(JCS.canonical_bytes!(payload)) == pin.checkpoint_hash and
      event_head["head_sequence"] == pin.event_head_sequence and
      event_head["head_hash"] == pin.event_head_hash
  end

  defp candidate_checkpoint_matches_pin?(_, _), do: false

  defp recovery_pending_registration_binding_hash!(user_id, pending_registration, proof, _pin) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "protocol" => "refmd.pending-registration-binding",
        "version" => 1,
        "user_id" => user_id,
        "pending_registration_id" => pending_registration.id,
        "pending_registration_challenge_hash" =>
          pending_registration.pending_registration_challenge_hash,
        "target_device_id" => pending_registration.id,
        "target_device_signing_key_id" => pending_registration.signing_key_id,
        "target_device_hybrid_signing_public_key_material_hash" =>
          Hash.blake3_base64url(
            JCS.canonical_bytes!(pending_registration.hybrid_signing_public_key_material)
          ),
        "target_device_hybrid_encryption_public_key_material_hash" =>
          Hash.blake3_base64url(
            JCS.canonical_bytes!(pending_registration.hybrid_encryption_public_key_material)
          ),
        "target_device_encryption_key_id" => pending_registration.encryption_key_id,
        "target_device_client_nonce_hash" =>
          Hash.blake3_base64url(pending_registration.client_nonce),
        "target_key_checkpoint_sequence" => proof.target_key_checkpoint_sequence,
        "target_key_checkpoint_hash" => proof.target_key_checkpoint_hash
      })
    )
  end

  defp recovery_capability_hash!(proof, challenge_hash) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "protocol" => "refmd.recovery-capability",
        "version" => 1,
        "recovery_authorization_key_id" => proof.recovery_authorization_key_id,
        "recovery_authorization_proof" => proof.recovery_authorization_proof,
        "recovery_authorization_proof_transcript_hash" =>
          proof.recovery_authorization_proof["transcript_hash"],
        "pending_registration_binding_hash" => proof.pending_registration_binding_hash,
        "recipient_device_id" => proof.recipient_device_id,
        "server_challenge_hash" => challenge_hash
      })
    )
  end

  defp validate_hybrid_signature_object(signature) when is_map(signature) do
    JCS.canonical_bytes!(signature)
    {:ok, signature}
  rescue
    ArgumentError -> {:error, :invalid_recovery}
  end

  defp consume_recovery_challenge(challenge, user_id) do
    challenge_hash = :crypto.hash(:sha256, challenge)
    now = DateTime.utc_now()

    query =
      from(c in RecoveryChallenge,
        where:
          c.challenge_hash == ^challenge_hash and
            c.user_id == ^user_id and
            c.expires_at > ^now
      )

    case Repo.delete_all(query) do
      {1, _} -> :ok
      {0, _} -> {:error, :invalid_recovery}
    end
  end

  def delete_expired_rrp_challenges do
    now = DateTime.utc_now()

    from(c in RrpChallenge, where: c.expires_at < ^now)
    |> Repo.delete_all()
  end

  def delete_device_sessions(device_id) do
    from(s in Session, where: s.device_id == ^device_id)
    |> Repo.delete_all()
  end

  def delete_device_and_unbound_sessions(user_id, device_id) do
    from(s in Session,
      where: s.user_id == ^user_id and (s.device_id == ^device_id or is_nil(s.device_id))
    )
    |> Repo.delete_all()
  end

  def has_unbound_sessions?(user_id) do
    now = DateTime.utc_now()

    from(s in Session,
      where: s.user_id == ^user_id and is_nil(s.device_id) and s.expires_at > ^now
    )
    |> Repo.exists?()
  end

  def delete_device_rrp_challenges(device_id) do
    from(c in RrpChallenge, where: c.device_id == ^device_id)
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

  # ── WebSocket Token ─────────────────────────────

  @ws_token_salt "ws_auth_token"
  @ws_token_max_age 300

  def generate_ws_token(session_id) do
    TokenSigning.sign(@ws_token_salt, session_id)
  end

  def verify_ws_token(token) do
    with {:ok, session_id} <-
           TokenSigning.verify(@ws_token_salt, token, max_age: @ws_token_max_age),
         {:ok, session} <- get_valid_session(session_id) do
      {:ok, session.user_id, session}
    end
  end

  defp get_valid_session(session_id) do
    case Repo.get(Session, session_id) do
      nil ->
        {:error, :session_not_found}

      %{expires_at: exp} = session ->
        cond do
          DateTime.compare(exp, DateTime.utc_now()) != :gt ->
            {:error, :session_expired}

          is_binary(session.device_id) and
              not Devices.user_owns_active_device?(session.user_id, session.device_id) ->
            {:error, :device_inactive}

          true ->
            {:ok, session}
        end
    end
  end
end
