defmodule RefMD.Workspaces.InvitationDelivery do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Encoding, Hash, HybridEncryptionMaterial, JCS, Signature}
  alias RefMD.Devices.Device
  alias RefMD.Documents.Document
  alias RefMD.Encryption
  alias RefMD.Encryption.KeyDirectory.PinBootstrap
  alias RefMD.Encryption.KeyDirectory.Protocol, as: KeyDirectoryProtocol
  alias RefMD.Encryption.Wraps.SignedPQ
  alias RefMD.Repo
  alias RefMD.Sharing.Share

  alias RefMD.Workspaces.{
    GuestInvitation,
    InvitationDeliveryAttempt,
    WorkspaceInvitation
  }

  alias RefMD.Users
  alias RefMD.Workspaces.Guests
  alias RefMD.Workspaces.Invitations
  alias RefMD.Workspaces.Members

  @attempt_ttl_seconds 300

  def create_attempt(token_hash, recipient_user_id, recipient_device_id, attrs)
      when is_binary(token_hash) and is_binary(recipient_user_id) and
             is_binary(recipient_device_id) and is_map(attrs) do
    Repo.transaction(
      fn ->
        with {:ok, invitation, context_kind} <- lock_known_invitation(token_hash),
             :ok <- validate_invitation_active(invitation),
             {:ok, recipient_device} <-
               validate_recipient(invitation, recipient_user_id, recipient_device_id),
             {:ok, normalized} <-
               normalize_attempt(
                 invitation,
                 context_kind,
                 recipient_user_id,
                 recipient_device,
                 attrs
               ),
             {:ok, attempt} <-
               %InvitationDeliveryAttempt{}
               |> InvitationDeliveryAttempt.create_changeset(normalized)
               |> Repo.insert() do
          attempt
        else
          {:error, reason} -> Repo.rollback(reason)
        end
      end,
      isolation: :serializable
    )
    |> unwrap_transaction()
  end

  def get_recipient_attempt(attempt_id, recipient_user_id, recipient_device_id) do
    expire_stale_attempts()

    from(a in InvitationDeliveryAttempt,
      where:
        a.id == ^attempt_id and a.recipient_user_id == ^recipient_user_id and
          a.recipient_device_id == ^recipient_device_id
    )
    |> Repo.one()
    |> case do
      %InvitationDeliveryAttempt{} = attempt -> {:ok, attempt}
      nil -> {:error, :not_found}
    end
  end

  def list_pending_attempts(workspace_id) do
    expire_stale_attempts()

    from(a in InvitationDeliveryAttempt,
      where: a.workspace_id == ^workspace_id and a.status == "pending",
      order_by: [asc: a.created_at]
    )
    |> Repo.all()
  end

  def approve_attempt(workspace_id, attempt_id, actor_user_id, actor_device_id, artifacts)
      when is_binary(workspace_id) and is_binary(attempt_id) and is_binary(actor_user_id) and
             is_binary(actor_device_id) and is_map(artifacts) do
    Repo.transaction(
      fn ->
        with {:ok, attempt} <- lock_pending_attempt(workspace_id, attempt_id),
             :ok <- validate_approver(attempt, actor_user_id, actor_device_id),
             {:ok, authorization_id} <-
               validate_approval_artifacts(attempt, actor_user_id, actor_device_id, artifacts),
             now = DateTime.utc_now(),
             {:ok, approved} <-
               attempt
               |> InvitationDeliveryAttempt.approve_changeset(%{
                 status: "approved",
                 authorization_id: authorization_id,
                 approved_artifacts: artifacts,
                 approved_at: now
               })
               |> Repo.update() do
          approved
        else
          {:error, reason} -> Repo.rollback(reason)
        end
      end,
      isolation: :serializable
    )
    |> unwrap_transaction()
  end

  def consume_workspace_attempt(
        attempt_id,
        token_hash,
        recipient_user_id,
        recipient_device_id
      )
      when is_binary(attempt_id) and is_binary(token_hash) and is_binary(recipient_user_id) and
             is_binary(recipient_device_id) do
    Repo.transaction(
      fn ->
        with {:ok, attempt} <-
               lock_approved_recipient_attempt(
                 attempt_id,
                 "workspace_invitation",
                 recipient_user_id,
                 recipient_device_id
               ),
             :ok <- validate_attempt_token(attempt, token_hash),
             :ok <- validate_approved_head_current(attempt),
             %{} = user <- Users.get_user(recipient_user_id),
             artifacts = attempt.approved_artifacts,
             {:ok, result} <-
               Invitations.accept_invitation(
                 token_hash,
                 recipient_user_id,
                 user.email,
                 recipient_device_id,
                 %{
                   key_directory: %{
                     events: artifacts["workspace_key_directory_events"],
                     checkpoint: artifacts["workspace_key_directory_checkpoint"]
                   },
                   member_envelope: artifacts["member_envelope"],
                   recipient_delivery_attempt: attempt
                 }
               ),
             {:ok, _consumed} <-
               attempt
               |> InvitationDeliveryAttempt.consume_changeset(DateTime.utc_now())
               |> Repo.update() do
          Map.put(result, :recipient_delivery_artifacts, artifacts)
        else
          nil -> Repo.rollback(:not_found)
          {:error, reason} -> Repo.rollback(reason)
        end
      end,
      isolation: :serializable
    )
    |> unwrap_transaction()
  end

  def consume_guest_attempt(
        attempt_id,
        token_hash,
        recipient_user_id,
        recipient_device_id,
        session_attrs
      )
      when is_binary(attempt_id) and is_binary(token_hash) and is_binary(recipient_user_id) and
             is_binary(recipient_device_id) and is_map(session_attrs) do
    Repo.transaction(
      fn ->
        with {:ok, attempt} <-
               lock_approved_recipient_attempt(
                 attempt_id,
                 "guest_invitation",
                 recipient_user_id,
                 recipient_device_id
               ),
             :ok <- validate_attempt_token(attempt, token_hash),
             :ok <- validate_approved_head_current(attempt),
             {:ok, device_attrs} <- guest_device_attrs(attempt),
             artifacts = attempt.approved_artifacts,
             recipient_account = %{
               user_id: recipient_user_id,
               device_id: recipient_device_id
             },
             {:ok, result} <-
               Guests.redeem_guest_invitation(
                 token_hash,
                 device_attrs,
                 session_attrs,
                 %{
                   events: artifacts["workspace_key_directory_events"],
                   intermediate_checkpoint:
                     artifacts["workspace_key_directory_intermediate_checkpoint"],
                   checkpoint: artifacts["workspace_key_directory_checkpoint"],
                   recipient_account: recipient_account,
                   recipient_delivery_attempt: attempt
                 },
                 recipient_account
               ),
             {:ok, _consumed} <-
               attempt
               |> InvitationDeliveryAttempt.consume_changeset(DateTime.utc_now())
               |> Repo.update() do
          Map.put(result, :recipient_delivery_artifacts, artifacts)
        else
          {:error, reason} -> Repo.rollback(reason)
        end
      end,
      isolation: :serializable
    )
    |> unwrap_transaction()
  end

  defp lock_known_invitation(token_hash) do
    workspace_invitation =
      from(i in WorkspaceInvitation, where: i.token_hash == ^token_hash, lock: "FOR UPDATE")
      |> Repo.one()

    case workspace_invitation do
      %WorkspaceInvitation{delivery_mode: "known_recipient"} = invitation ->
        {:ok, invitation, "workspace_invitation"}

      %WorkspaceInvitation{} ->
        {:error, :recipient_delivery_not_required}

      nil ->
        guest_invitation =
          from(i in GuestInvitation, where: i.token_hash == ^token_hash, lock: "FOR UPDATE")
          |> Repo.one()

        case guest_invitation do
          %GuestInvitation{delivery_mode: "known_recipient"} = invitation ->
            {:ok, invitation, "guest_invitation"}

          %GuestInvitation{} ->
            {:error, :recipient_delivery_not_required}

          nil ->
            {:error, :not_found}
        end
    end
  end

  defp lock_pending_attempt(workspace_id, attempt_id) do
    attempt =
      from(a in InvitationDeliveryAttempt,
        where: a.id == ^attempt_id and a.workspace_id == ^workspace_id,
        lock: "FOR UPDATE"
      )
      |> Repo.one()

    cond do
      is_nil(attempt) -> {:error, :not_found}
      attempt.status != "pending" -> {:error, :delivery_attempt_not_pending}
      expired?(attempt.expires_at) -> {:error, :delivery_attempt_expired}
      true -> {:ok, attempt}
    end
  end

  defp lock_approved_recipient_attempt(
         attempt_id,
         context_kind,
         recipient_user_id,
         recipient_device_id
       ) do
    attempt =
      from(a in InvitationDeliveryAttempt,
        where:
          a.id == ^attempt_id and a.context_kind == ^context_kind and
            a.recipient_user_id == ^recipient_user_id and
            a.recipient_device_id == ^recipient_device_id,
        lock: "FOR UPDATE"
      )
      |> Repo.one()

    cond do
      is_nil(attempt) -> {:error, :not_found}
      attempt.status != "approved" -> {:error, :delivery_attempt_not_approved}
      expired?(attempt.expires_at) -> {:error, :delivery_attempt_expired}
      true -> {:ok, attempt}
    end
  end

  defp validate_attempt_token(attempt, token_hash) do
    if attempt.context_snapshot["token_hash"] == token_hash,
      do: :ok,
      else: {:error, :delivery_attempt_token_mismatch}
  end

  defp validate_approved_head_current(attempt) do
    payload = get_in(attempt.approved_artifacts, ["authorization", "payload"])
    checkpoint = Encryption.current_workspace_key_directory_checkpoint(attempt.workspace_id)

    if is_map(payload) and payload["current_checkpoint_sequence"] == checkpoint.sequence and
         payload["current_checkpoint_hash"] == checkpoint.checkpoint_hash and
         payload["current_event_head_sequence"] == checkpoint.covered_event_head_sequence and
         payload["current_event_head_hash"] == checkpoint.covered_event_head_hash do
      :ok
    else
      {:error, :delivery_approval_stale}
    end
  end

  defp guest_device_attrs(attempt) do
    registration = attempt.target_registration
    proof = attempt.target_registration_proof

    identity_encryption_material =
      registration["identity_hybrid_encryption_public_key_material"]

    identity_signing_material = registration["identity_hybrid_signing_public_key_material"]

    with {:ok, client_nonce} <- decode_client_nonce(proof["client_nonce"]),
         {:ok, encrypted_identity_encryption} <-
           decode_registration_bytes(
             registration["encrypted_identity_hybrid_encryption_private_key_material"]
           ),
         {:ok, identity_encryption_nonce} <-
           decode_registration_bytes(
             registration["identity_hybrid_encryption_private_key_material_nonce"],
             24
           ),
         {:ok, encrypted_identity_signing} <-
           decode_registration_bytes(
             registration["encrypted_identity_hybrid_signing_private_key_material"]
           ),
         {:ok, identity_signing_nonce} <-
           decode_registration_bytes(
             registration["identity_hybrid_signing_private_key_material_nonce"],
             24
           ),
         true <- is_map(proof["approval_signature"]),
         :ok <-
           validate_hash_value(
             proof["pending_registration_challenge_hash"],
             :invalid_pending_registration_challenge
           ),
         true <- is_binary(proof["device_name"]),
         true <- is_binary(proof["device_type"]) do
      {:ok,
       %{
         guest_user_id: attempt.target_user_id,
         device_id: attempt.target_device_id,
         identity_hybrid_encryption_public_key_material: identity_encryption_material,
         identity_hybrid_signing_public_key_material: identity_signing_material,
         encrypted_identity_hybrid_encryption_private_key_material: encrypted_identity_encryption,
         identity_hybrid_encryption_private_key_material_nonce: identity_encryption_nonce,
         identity_encryption_key_id:
           HybridEncryptionMaterial.compute_key_id!(identity_encryption_material),
         encrypted_identity_hybrid_signing_private_key_material: encrypted_identity_signing,
         identity_hybrid_signing_private_key_material_nonce: identity_signing_nonce,
         identity_signing_key_id: Signature.compute_signing_key_id!(identity_signing_material),
         device_hybrid_encryption_public_key_material:
           registration["device_hybrid_encryption_public_key_material"],
         device_hybrid_signing_public_key_material:
           registration["device_hybrid_signing_public_key_material"],
         user_key_directory_events: registration["user_key_directory_events"],
         user_key_directory_checkpoint: registration["user_key_directory_checkpoint"],
         approval_signature: proof["approval_signature"],
         client_nonce: client_nonce,
         pending_registration_challenge_hash: proof["pending_registration_challenge_hash"],
         device_name: proof["device_name"],
         device_type: proof["device_type"]
       }}
    else
      _ -> {:error, :invalid_guest_registration_proof}
    end
  end

  defp decode_client_nonce(value) when is_binary(value) do
    nonce = Encoding.decode_base64url!(value, 16)
    {:ok, nonce}
  rescue
    ArgumentError -> {:error, :invalid_guest_registration_proof}
  end

  defp decode_client_nonce(_), do: {:error, :invalid_guest_registration_proof}

  defp decode_registration_bytes(value, expected_bytes \\ nil)

  defp decode_registration_bytes(value, expected_bytes) when is_binary(value) do
    bytes = Encoding.decode_base64url!(value, expected_bytes)

    if bytes == <<>>,
      do: {:error, :invalid_guest_registration},
      else: {:ok, bytes}
  rescue
    ArgumentError -> {:error, :invalid_guest_registration}
  end

  defp decode_registration_bytes(_, _), do: {:error, :invalid_guest_registration}

  defp validate_hash_value(value, _reason) when is_binary(value) do
    Hash.assert_blake3_base64url!(value)
    :ok
  rescue
    ArgumentError -> {:error, :invalid_guest_registration_proof}
  end

  defp validate_hash_value(_, _reason), do: {:error, :invalid_guest_registration_proof}

  defp validate_approver(attempt, actor_user_id, actor_device_id) do
    device = Repo.get(Device, actor_device_id)

    permission =
      if attempt.context_kind == "guest_invitation", do: "guest:invite", else: "member:invite"

    cond do
      is_nil(device) or device.user_id != actor_user_id or device.revoked_at != nil ->
        {:error, :approver_device_invalid}

      not Members.member_permission_granted?(attempt.workspace_id, actor_user_id, permission) ->
        {:error, :permission_denied}

      true ->
        :ok
    end
  end

  defp validate_approval_artifacts(attempt, actor_user_id, actor_device_id, artifacts) do
    required_keys =
      if attempt.context_kind == "workspace_invitation" do
        ~w(authorization delivery_wrap member_envelope redeem_freshness_proof workspace_key_directory_checkpoint workspace_key_directory_events workspace_pin_bootstrap)
      else
        ~w(authorization delivery_wrap redeem_freshness_proof workspace_key_directory_checkpoint workspace_key_directory_events workspace_key_directory_intermediate_checkpoint workspace_pin_bootstrap)
      end

    with true <- Enum.sort(Map.keys(artifacts)) == Enum.sort(required_keys),
         {:ok, authorization} <- fetch_map(artifacts, "authorization"),
         {:ok, freshness_proof} <- fetch_map(artifacts, "redeem_freshness_proof"),
         :ok <- validate_artifact_shapes(artifacts),
         :ok <- validate_freshness_proof(attempt, actor_user_id, actor_device_id, freshness_proof),
         {:ok, authorization_id} <-
           validate_authorization(
             attempt,
             actor_user_id,
             actor_device_id,
             authorization,
             freshness_proof,
             artifacts["workspace_pin_bootstrap"]
           ),
         :ok <- validate_delivery_wrap(attempt, artifacts, authorization) do
      {:ok, authorization_id}
    else
      false -> {:error, :invalid_delivery_approval}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_artifact_shapes(artifacts) do
    with true <- is_map(artifacts["delivery_wrap"]),
         true <- is_map(artifacts["workspace_pin_bootstrap"]),
         true <- is_list(artifacts["workspace_key_directory_events"]),
         true <- is_map(artifacts["workspace_key_directory_checkpoint"]),
         true <-
           not Map.has_key?(artifacts, "workspace_key_directory_intermediate_checkpoint") or
             is_map(artifacts["workspace_key_directory_intermediate_checkpoint"]),
         true <-
           not Map.has_key?(artifacts, "member_envelope") or
             is_map(artifacts["member_envelope"]) do
      :ok
    else
      _ -> {:error, :invalid_delivery_approval}
    end
  end

  defp validate_freshness_proof(attempt, actor_user_id, actor_device_id, proof) do
    checkpoint = Encryption.current_workspace_key_directory_checkpoint(attempt.workspace_id)

    common = %{
      "protocol" => "refmd.redeem-freshness-proof",
      "version" => 1,
      "workspace_id" => attempt.workspace_id,
      "current_event_head_sequence" => checkpoint.covered_event_head_sequence,
      "current_event_head_hash" => checkpoint.covered_event_head_hash,
      "current_checkpoint_hash" => checkpoint.checkpoint_hash,
      "recipient_redeem_nonce" => attempt.recipient_redeem_nonce,
      "live_redeem_challenge_hash" => attempt.live_redeem_challenge_hash
    }

    case proof["proof_kind"] do
      "authoritative_device_live" ->
        expected =
          Map.merge(common, %{
            "proof_kind" => "authoritative_device_live",
            "authoritative_device" => %{
              "user_id" => actor_user_id,
              "device_id" => actor_device_id
            }
          })

        if proof == expected, do: :ok, else: {:error, :invalid_redeem_freshness_proof}

      "member_gossip_quorum" ->
        validate_member_gossip_quorum(attempt, checkpoint, common, proof)

      _ ->
        {:error, :invalid_redeem_freshness_proof}
    end
  end

  defp validate_member_gossip_quorum(attempt, checkpoint, common, proof) do
    expected_keys = Map.keys(common) ++ ~w(proof_kind proof_hashes gossip_statements)
    statements = proof["gossip_statements"]
    proof_hashes = proof["proof_hashes"]

    with true <- Enum.sort(Map.keys(proof)) == Enum.sort(expected_keys),
         true <- is_list(statements) and length(statements) >= 2,
         true <- is_list(proof_hashes),
         {:ok, validated} <- validate_gossip_statements(attempt, checkpoint, statements),
         true <- length(Enum.uniq(validated.user_ids)) == length(validated.user_ids),
         true <- Enum.sort(proof_hashes) == Enum.sort(validated.hashes),
         true <- length(Enum.uniq(proof_hashes)) == length(proof_hashes) do
      :ok
    else
      _ -> {:error, :invalid_redeem_freshness_proof}
    end
  end

  defp validate_gossip_statements(attempt, checkpoint, statements) do
    Enum.reduce_while(statements, {:ok, %{user_ids: [], hashes: []}}, fn statement, {:ok, acc} ->
      with {:ok, payload} <- fetch_map(statement, "payload"),
           {:ok, transcript} <- fetch_map(statement, "transcript"),
           {:ok, signature} <- fetch_map(statement, "signature"),
           {:ok, public_material} <-
             fetch_map(statement, "hybrid_signing_public_key_material"),
           user_id when is_binary(user_id) <- payload["user_id"],
           device_id when is_binary(device_id) <- payload["device_id"],
           signing_key_id when is_binary(signing_key_id) <- statement["signing_key_id"],
           true <- valid_gossip_payload?(attempt, checkpoint, payload, user_id, device_id),
           %Device{} = device <- Repo.get(Device, device_id),
           true <-
             device.user_id == user_id and is_nil(device.revoked_at) and
               device.signing_key_id == signing_key_id and
               device.hybrid_signing_public_key_material == public_material,
           true <- not is_nil(Members.get_member_with_role(attempt.workspace_id, user_id)),
           expected_transcript <-
             Signature.build_pin_gossip_statement_transcript!(device_id, payload),
           true <- transcript == expected_transcript,
           true <-
             Signature.verify_hybrid_signature(
               "pin_gossip_statement",
               transcript,
               signature,
               public_material
             ) do
        hash = Hash.blake3_base64url(JCS.canonical_bytes!(payload))
        {:cont, {:ok, %{user_ids: [user_id | acc.user_ids], hashes: [hash | acc.hashes]}}}
      else
        _ -> {:halt, {:error, :invalid_redeem_freshness_proof}}
      end
    end)
  rescue
    _ -> {:error, :invalid_redeem_freshness_proof}
  end

  defp valid_gossip_payload?(attempt, checkpoint, payload, user_id, device_id) do
    payload == %{
      "protocol" => "refmd.pin.gossip.statement",
      "version" => 1,
      "workspace_id" => attempt.workspace_id,
      "current_event_head_sequence" => checkpoint.covered_event_head_sequence,
      "current_event_head_hash" => checkpoint.covered_event_head_hash,
      "current_checkpoint_hash" => checkpoint.checkpoint_hash,
      "user_id" => user_id,
      "device_id" => device_id,
      "recipient_redeem_nonce" => attempt.recipient_redeem_nonce,
      "live_redeem_challenge_hash" => attempt.live_redeem_challenge_hash
    }
  end

  defp validate_authorization(
         attempt,
         actor_user_id,
         actor_device_id,
         authorization,
         freshness_proof,
         workspace_pin_bootstrap
       ) do
    with {:ok, payload} <- fetch_map(authorization, "payload"),
         {:ok, transcript} <- fetch_map(authorization, "transcript"),
         {:ok, signature} <- fetch_map(authorization, "signature"),
         {:ok, public_material} <-
           fetch_map(authorization, "hybrid_signing_public_key_material"),
         signing_key_id when is_binary(signing_key_id) <- authorization["signing_key_id"],
         {:ok, authorization_id} <- fetch_uuid(payload, "authorization_id"),
         :ok <-
           validate_authorization_payload(
             attempt,
             actor_device_id,
             signing_key_id,
             payload,
             freshness_proof,
             workspace_pin_bootstrap
           ),
         :ok <-
           validate_authorization_signer(
             actor_user_id,
             actor_device_id,
             signing_key_id,
             public_material
           ),
         expected_transcript <-
           Signature.build_recipient_bound_authorization_transcript!(
             actor_device_id,
             actor_user_id,
             actor_device_id,
             signing_key_id,
             payload
           ),
         true <- transcript == expected_transcript,
         true <-
           Signature.verify_hybrid_signature(
             "recipient_bound_authorization",
             transcript,
             signature,
             public_material
           ) do
      {:ok, authorization_id}
    else
      _ -> {:error, :invalid_recipient_bound_authorization}
    end
  rescue
    ArgumentError -> {:error, :invalid_recipient_bound_authorization}
  end

  defp validate_authorization_payload(
         attempt,
         actor_device_id,
         signing_key_id,
         payload,
         freshness_proof,
         workspace_pin_bootstrap
       ) do
    checkpoint = Encryption.current_workspace_key_directory_checkpoint(attempt.workspace_id)
    recipient_kind = if attempt.context_kind == "guest_invitation", do: "guest", else: "invitee"

    expected = %{
      "protocol" => "refmd.recipient-bound-authorization",
      "version" => 1,
      "authorization_id" => payload["authorization_id"],
      "redeem_attempt_id" => attempt.id,
      "workspace_id" => attempt.workspace_id,
      "context_kind" => attempt.context_kind,
      "context_id" => attempt.context_id,
      "resource_hash" => attempt.resource_hash,
      "recipient" => %{
        "recipient_kind" => recipient_kind,
        "recipient_principal_id" => attempt.target_user_id,
        "recipient_device_id" => attempt.target_device_id,
        "encryption_key_id" => attempt.target_encryption_key_id
      },
      "workspace_pin_bootstrap_hash" => payload["workspace_pin_bootstrap_hash"],
      "current_checkpoint_sequence" => checkpoint.sequence,
      "current_checkpoint_hash" => checkpoint.checkpoint_hash,
      "current_event_head_sequence" => checkpoint.covered_event_head_sequence,
      "current_event_head_hash" => checkpoint.covered_event_head_hash,
      "redeem_authority_signing_key_id" => signing_key_id,
      "recipient_redeem_nonce" => attempt.recipient_redeem_nonce,
      "recipient_nonce_state_hash" => attempt.recipient_nonce_state_hash,
      "live_redeem_challenge_hash" => attempt.live_redeem_challenge_hash,
      "redeem_freshness_proof_hash" => hash(freshness_proof),
      "not_after_event_sequence" => checkpoint.covered_event_head_sequence + 1
    }

    with true <- payload == expected,
         :ok <-
           validate_workspace_pin_bootstrap(
             attempt,
             checkpoint,
             workspace_pin_bootstrap,
             payload["workspace_pin_bootstrap_hash"]
           ),
         true <- actor_device_id == authorization_actor_device_id(payload, actor_device_id) do
      :ok
    else
      _ -> {:error, :invalid_recipient_bound_authorization}
    end
  end

  defp authorization_actor_device_id(_payload, actor_device_id), do: actor_device_id

  defp validate_workspace_pin_bootstrap(
         attempt,
         checkpoint,
         workspace_pin_bootstrap,
         expected_hash
       ) do
    operation_sequence = checkpoint.covered_event_head_sequence + 1

    PinBootstrap.validate!(
      attempt.workspace_id,
      workspace_pin_bootstrap,
      checkpoint,
      operation_sequence
    )

    if PinBootstrap.hash!(attempt.workspace_id, workspace_pin_bootstrap) == expected_hash,
      do: :ok,
      else: {:error, :invalid_workspace_pin_bootstrap}
  rescue
    ArgumentError -> {:error, :invalid_workspace_pin_bootstrap}
  end

  defp validate_authorization_signer(
         actor_user_id,
         actor_device_id,
         signing_key_id,
         public_material
       ) do
    case Repo.get(Device, actor_device_id) do
      %Device{
        user_id: ^actor_user_id,
        revoked_at: nil,
        signing_key_id: ^signing_key_id,
        hybrid_signing_public_key_material: ^public_material
      } ->
        :ok

      _ ->
        {:error, :invalid_recipient_bound_authorization}
    end
  end

  defp validate_delivery_wrap(
         %InvitationDeliveryAttempt{context_kind: "workspace_invitation"} = attempt,
         artifacts,
         authorization
       ) do
    attrs = SignedPQ.attrs_from_container_params!(artifacts["delivery_wrap"])
    payload = authorization["payload"]
    public_material = authorization["hybrid_signing_public_key_material"]
    context = attempt.context_snapshot
    checkpoint_payload = artifacts["workspace_key_directory_checkpoint"]["payload"]
    operation_checkpoint_hash = KeyDirectoryProtocol.checkpoint_hash(checkpoint_payload)

    expected_resource = %{
      "workspace_id" => attempt.workspace_id,
      "invitation_id" => attempt.context_id,
      "redeemed_user_id" => attempt.target_user_id,
      "redeemed_device_id" => attempt.target_device_id,
      "recipient_encryption_key_id" => attempt.target_encryption_key_id,
      "role_id" => context["role_id"],
      "kek_version" => context["kek_version"],
      "workspace_invitation_redeemed_event_hash" =>
        workspace_redeemed_event_hash!(artifacts["workspace_key_directory_events"])
    }

    expected_sender = %{
      "signer_kind" => "device",
      "user_id" =>
        get_in(artifacts, ["redeem_freshness_proof", "authoritative_device", "user_id"]),
      "device_id" =>
        get_in(artifacts, ["redeem_freshness_proof", "authoritative_device", "device_id"]),
      "signing_key_id" => authorization["signing_key_id"],
      "key_scope_kind" => "workspace",
      "key_scope_id" => attempt.workspace_id,
      "key_checkpoint_sequence" => payload["current_checkpoint_sequence"],
      "key_checkpoint_hash" => payload["current_checkpoint_hash"]
    }

    expected_recipient = %{
      "recipient_kind" => "invitee",
      "invitee_user_id" => attempt.target_user_id,
      "invitee_device_id" => attempt.target_device_id,
      "encryption_key_id" => attempt.target_encryption_key_id,
      "key_scope_kind" => "user",
      "key_scope_id" => attempt.recipient_user_id,
      "key_checkpoint_sequence" => attempt.target_key_checkpoint_sequence,
      "key_checkpoint_hash" => attempt.target_key_checkpoint_hash
    }

    with :ok <-
           SignedPQ.validate_workspace_invitation_kek(attrs, %{
             event_scope: %{"scope_kind" => "workspace", "scope_id" => attempt.workspace_id},
             resource: expected_resource,
             sender: expected_sender,
             recipient: expected_recipient,
             sender_signing_key_id: authorization["signing_key_id"],
             recipient_key_id: attempt.target_encryption_key_id,
             key_directory_events: artifacts["workspace_key_directory_events"]
           }),
         true <- attrs.operation_checkpoint_sequence == checkpoint_payload["sequence"],
         true <-
           Encoding.encode_base64url(attrs.operation_checkpoint_hash) == operation_checkpoint_hash,
         true <-
           attrs.operation_checkpoint_covered_head_sequence ==
             get_in(checkpoint_payload, ["covered_event_head", "head_sequence"]),
         true <-
           Encoding.encode_base64url(attrs.operation_checkpoint_covered_head_hash) ==
             get_in(checkpoint_payload, ["covered_event_head", "head_hash"]),
         :ok <- SignedPQ.verify_signature(attrs, public_material) do
      :ok
    else
      _ -> {:error, :invalid_delivery_wrap}
    end
  rescue
    _ -> {:error, :invalid_delivery_wrap}
  end

  defp validate_delivery_wrap(
         %InvitationDeliveryAttempt{context_kind: "guest_invitation"} = attempt,
         artifacts,
         authorization
       ) do
    attrs = SignedPQ.attrs_from_container_params!(artifacts["delivery_wrap"])
    payload = authorization["payload"]
    public_material = authorization["hybrid_signing_public_key_material"]
    context = attempt.context_snapshot
    checkpoint_payload = artifacts["workspace_key_directory_checkpoint"]["payload"]

    intermediate_payload =
      artifacts["workspace_key_directory_intermediate_checkpoint"]["payload"]

    operation_checkpoint_hash = KeyDirectoryProtocol.checkpoint_hash(checkpoint_payload)
    intermediate_checkpoint_hash = KeyDirectoryProtocol.checkpoint_hash(intermediate_payload)
    redeemed = guest_redeemed_event!(artifacts["workspace_key_directory_events"])

    expected_resource = guest_delivery_resource(attempt, context, redeemed)

    expected_sender = %{
      "signer_kind" => "device",
      "user_id" =>
        get_in(artifacts, ["redeem_freshness_proof", "authoritative_device", "user_id"]),
      "device_id" =>
        get_in(artifacts, ["redeem_freshness_proof", "authoritative_device", "device_id"]),
      "signing_key_id" => authorization["signing_key_id"],
      "key_scope_kind" => "workspace",
      "key_scope_id" => attempt.workspace_id,
      "key_checkpoint_sequence" => payload["current_checkpoint_sequence"],
      "key_checkpoint_hash" => payload["current_checkpoint_hash"]
    }

    expected_recipient = %{
      "recipient_kind" => "guest",
      "guest_user_id" => attempt.target_user_id,
      "guest_device_id" => attempt.target_device_id,
      "encryption_key_id" => attempt.target_encryption_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => attempt.workspace_id,
      "key_checkpoint_sequence" => intermediate_payload["sequence"],
      "key_checkpoint_hash" => intermediate_checkpoint_hash
    }

    validation_context = %{
      event_scope: %{"scope_kind" => "workspace", "scope_id" => attempt.workspace_id},
      resource: expected_resource,
      sender: expected_sender,
      recipient: expected_recipient,
      sender_signing_key_id: authorization["signing_key_id"],
      recipient_key_id: attempt.target_encryption_key_id,
      key_directory_events: artifacts["workspace_key_directory_events"]
    }

    with :ok <- validate_guest_delivery_wrap(attrs, context["scope_kind"], validation_context),
         true <- attrs.operation_checkpoint_sequence == checkpoint_payload["sequence"],
         true <-
           Encoding.encode_base64url(attrs.operation_checkpoint_hash) == operation_checkpoint_hash,
         :ok <- SignedPQ.verify_signature(attrs, public_material) do
      :ok
    else
      _ -> {:error, :invalid_delivery_wrap}
    end
  rescue
    _ -> {:error, :invalid_delivery_wrap}
  end

  defp validate_delivery_wrap(_attempt, _artifacts, _authorization), do: :ok

  defp guest_delivery_resource(attempt, %{"scope_kind" => "workspace"} = context, redeemed) do
    %{
      "workspace_id" => attempt.workspace_id,
      "guest_invitation_id" => attempt.context_id,
      "guest_user_id" => attempt.target_user_id,
      "guest_device_id" => attempt.target_device_id,
      "recipient_encryption_key_id" => attempt.target_encryption_key_id,
      "guest_grant_id" => get_in(redeemed, ["payload", "body", "guest_grant_id"]),
      "scope_kind" => "workspace",
      "scope_id" => "none",
      "permission" => context["permission"],
      "kek_version" => context["kek_version"],
      "guest_invitation_redeemed_event_hash" =>
        KeyDirectoryProtocol.event_hash(redeemed["payload"])
    }
  end

  defp guest_delivery_resource(attempt, context, redeemed) do
    %{
      "workspace_id" => attempt.workspace_id,
      "guest_invitation_id" => attempt.context_id,
      "guest_user_id" => attempt.target_user_id,
      "guest_device_id" => attempt.target_device_id,
      "recipient_encryption_key_id" => attempt.target_encryption_key_id,
      "share_id" => context["share_id"],
      "scope_kind" => context["resource_scope_kind"],
      "scope_id" => context["resource_scope_id"],
      "permission" => context["permission"],
      "document_scope_hash" => context["document_scope_hash"],
      "share_key_version" => context["share_key_version"],
      "dek_version" => context["dek_version"],
      "guest_invitation_redeemed_event_hash" =>
        KeyDirectoryProtocol.event_hash(redeemed["payload"])
    }
  end

  defp validate_guest_delivery_wrap(attrs, "workspace", context),
    do: SignedPQ.validate_guest_invitation_workspace_kek(attrs, context)

  defp validate_guest_delivery_wrap(attrs, scope_kind, context)
       when scope_kind in ["document", "folder", "share"],
       do: SignedPQ.validate_guest_invitation_share_key(attrs, context)

  defp validate_guest_delivery_wrap(_attrs, _scope_kind, _context),
    do: {:error, :invalid_delivery_wrap}

  defp workspace_redeemed_event_hash!(events) do
    events
    |> Enum.find(fn event ->
      get_in(event, ["payload", "event_type"]) == "workspace_invitation_redeemed"
    end)
    |> then(fn event -> KeyDirectoryProtocol.event_hash(event["payload"]) end)
  end

  defp guest_redeemed_event!(events) do
    case Enum.filter(events, fn event ->
           get_in(event, ["payload", "event_type"]) == "guest_invitation_redeemed"
         end) do
      [event] -> event
      _ -> raise ArgumentError, "guest_invitation_redeemed_event_invalid"
    end
  end

  defp validate_invitation_active(%WorkspaceInvitation{} = invitation) do
    cond do
      invitation.revoked_at != nil -> {:error, :invitation_revoked}
      invitation.is_used -> {:error, :invitation_used}
      expired?(invitation.expires_at) -> {:error, :invitation_expired}
      true -> :ok
    end
  end

  defp validate_invitation_active(%GuestInvitation{} = invitation) do
    cond do
      invitation.revoked_at != nil ->
        {:error, :invitation_revoked}

      invitation.redemption_count >= invitation.max_redemptions ->
        {:error, :invitation_redemptions_exhausted}

      expired?(invitation.expires_at) ->
        {:error, :invitation_expired}

      true ->
        :ok
    end
  end

  defp validate_recipient(invitation, recipient_user_id, recipient_device_id) do
    device = Repo.get(Device, recipient_device_id)

    cond do
      invitation.recipient_user_id != recipient_user_id ->
        {:error, :recipient_mismatch}

      recipient_device_id not in invitation.recipient_device_ids ->
        {:error, :recipient_device_mismatch}

      is_nil(device) or device.user_id != recipient_user_id ->
        {:error, :recipient_device_mismatch}

      device.revoked_at != nil ->
        {:error, :recipient_device_revoked}

      true ->
        {:ok, device}
    end
  end

  defp normalize_attempt(
         invitation,
         context_kind,
         recipient_user_id,
         recipient_device,
         attrs
       ) do
    with {:ok, attempt_id} <- fetch_uuid(attrs, "redeem_attempt_id"),
         {:ok, target_user_id} <- fetch_uuid(attrs, "target_user_id"),
         {:ok, target_device_id} <- fetch_uuid(attrs, "target_device_id"),
         {:ok, recipient_redeem_nonce} <- fetch_hash(attrs, "recipient_redeem_nonce"),
         {:ok, live_redeem_challenge_hash} <-
           fetch_hash(attrs, "live_redeem_challenge_hash"),
         {:ok, target_registration} <- fetch_map(attrs, "target_registration"),
         {:ok, target_registration_proof} <-
           fetch_target_registration_proof(context_kind, attrs),
         {:ok, target_encryption_key_id} <-
           validate_target_registration(
             context_kind,
             recipient_user_id,
             recipient_device,
             target_user_id,
             target_device_id,
             target_registration
           ) do
      {target_key_checkpoint_sequence, target_key_checkpoint_hash} =
        target_key_checkpoint(context_kind, recipient_device)

      nonce_state = %{
        "redeem_attempt_id" => attempt_id,
        "recipient_redeem_nonce" => recipient_redeem_nonce,
        "recipient_device_id" => recipient_device.id,
        "context_id" => invitation.id
      }

      recipient_nonce_state_hash = hash(nonce_state)

      request_binding = %{
        "workspace_id" => invitation.workspace_id,
        "context_kind" => context_kind,
        "context_id" => invitation.id,
        "recipient_user_id" => recipient_user_id,
        "recipient_device_id" => recipient_device.id,
        "target_user_id" => target_user_id,
        "target_device_id" => target_device_id,
        "target_encryption_key_id" => target_encryption_key_id,
        "target_registration_hash" => hash(target_registration),
        "target_registration_proof_hash" =>
          if(is_map(target_registration_proof),
            do: hash(target_registration_proof),
            else: "NOT_APPLICABLE"
          ),
        "recipient_nonce_state_hash" => recipient_nonce_state_hash,
        "live_redeem_challenge_hash" => live_redeem_challenge_hash
      }

      context_snapshot = invitation_context_snapshot(invitation)

      {:ok,
       %{
         id: attempt_id,
         workspace_id: invitation.workspace_id,
         context_kind: context_kind,
         context_id: invitation.id,
         recipient_user_id: recipient_user_id,
         recipient_device_id: recipient_device.id,
         target_user_id: target_user_id,
         target_device_id: target_device_id,
         target_encryption_key_id: target_encryption_key_id,
         target_key_checkpoint_sequence: target_key_checkpoint_sequence,
         target_key_checkpoint_hash: target_key_checkpoint_hash,
         target_registration: target_registration,
         target_registration_proof: target_registration_proof,
         recipient_redeem_nonce: recipient_redeem_nonce,
         live_redeem_challenge_hash: live_redeem_challenge_hash,
         recipient_nonce_state_hash: recipient_nonce_state_hash,
         request_binding_hash: hash(request_binding),
         resource_hash: invitation.capability_context_hash,
         context_snapshot: context_snapshot,
         status: "pending",
         expires_at: attempt_expiry(invitation.expires_at)
       }}
    end
  end

  defp validate_target_registration(
         "workspace_invitation",
         recipient_user_id,
         recipient_device,
         target_user_id,
         target_device_id,
         registration
       ) do
    identity_key =
      case RefMD.Encryption.user_identity_key_for_new_encryption(recipient_user_id) do
        {:ok, key} -> key
        {:error, _reason} -> nil
      end

    with :ok <-
           validate_recipient_target(
             recipient_user_id,
             recipient_device,
             target_user_id,
             target_device_id
           ),
         {:ok, identity_key} <- require_recipient_identity_key(identity_key),
         true <-
           exact_public_registration?(
             registration,
             recipient_registration(recipient_device, identity_key)
           ) do
      {:ok, recipient_device.encryption_key_id}
    else
      false -> {:error, :recipient_target_key_mismatch}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_target_registration(
         "guest_invitation",
         _recipient_user_id,
         _recipient_device,
         target_user_id,
         target_device_id,
         registration
       ) do
    with {:ok, encryption_material} <-
           fetch_map(registration, "device_hybrid_encryption_public_key_material"),
         {:ok, signing_material} <-
           fetch_map(registration, "device_hybrid_signing_public_key_material"),
         {:ok, identity_encryption_material} <-
           fetch_map(registration, "identity_hybrid_encryption_public_key_material"),
         {:ok, identity_signing_material} <-
           fetch_map(registration, "identity_hybrid_signing_public_key_material"),
         {:ok, _encrypted_identity_encryption} <-
           decode_registration_bytes(
             registration["encrypted_identity_hybrid_encryption_private_key_material"]
           ),
         {:ok, _identity_encryption_nonce} <-
           decode_registration_bytes(
             registration["identity_hybrid_encryption_private_key_material_nonce"],
             24
           ),
         {:ok, _encrypted_identity_signing} <-
           decode_registration_bytes(
             registration["encrypted_identity_hybrid_signing_private_key_material"]
           ),
         {:ok, _identity_signing_nonce} <-
           decode_registration_bytes(
             registration["identity_hybrid_signing_private_key_material_nonce"],
             24
           ),
         {:ok, user_events} <- fetch_list(registration, "user_key_directory_events"),
         {:ok, _user_checkpoint} <-
           fetch_map(registration, "user_key_directory_checkpoint"),
         true <- user_events != [],
         true <-
           Enum.sort(Map.keys(registration)) ==
             Enum.sort(
               ~w(device_hybrid_encryption_public_key_material device_hybrid_signing_public_key_material encrypted_identity_hybrid_encryption_private_key_material encrypted_identity_hybrid_signing_private_key_material identity_hybrid_encryption_private_key_material_nonce identity_hybrid_encryption_public_key_material identity_hybrid_signing_private_key_material_nonce identity_hybrid_signing_public_key_material user_key_directory_checkpoint user_key_directory_events)
             ),
         :ok <- assert_encryption_material(encryption_material, "device", target_device_id),
         :ok <- assert_signing_material(signing_material, "device", target_device_id),
         :ok <-
           assert_encryption_material(identity_encryption_material, "identity", target_user_id),
         :ok <- assert_signing_material(identity_signing_material, "identity", target_user_id) do
      {:ok, HybridEncryptionMaterial.compute_key_id!(encryption_material)}
    else
      false -> {:error, :recipient_target_key_mismatch}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_recipient_target(
         recipient_user_id,
         recipient_device,
         target_user_id,
         target_device_id
       ) do
    if target_user_id == recipient_user_id and target_device_id == recipient_device.id,
      do: :ok,
      else: {:error, :recipient_target_mismatch}
  end

  defp require_recipient_identity_key(nil), do: {:error, :recipient_identity_key_missing}
  defp require_recipient_identity_key(identity_key), do: {:ok, identity_key}

  defp recipient_registration(recipient_device, identity_key) do
    %{
      "device_hybrid_encryption_public_key_material" =>
        recipient_device.hybrid_encryption_public_key_material,
      "device_hybrid_signing_public_key_material" =>
        recipient_device.hybrid_signing_public_key_material,
      "identity_hybrid_encryption_public_key_material" =>
        identity_key.hybrid_encryption_public_key_material,
      "identity_hybrid_signing_public_key_material" =>
        identity_key.hybrid_signing_public_key_material
    }
  end

  defp exact_public_registration?(registration, expected) do
    map_size(registration) == map_size(expected) and registration == expected and
      Enum.all?(expected, fn {_key, value} -> is_map(value) end)
  end

  defp target_key_checkpoint("workspace_invitation", recipient_device),
    do: {recipient_device.key_checkpoint_sequence, recipient_device.key_checkpoint_hash}

  defp target_key_checkpoint("guest_invitation", _recipient_device), do: {nil, nil}

  defp assert_encryption_material(material, owner_kind, owner_id) do
    with :ok <- HybridEncryptionMaterial.assert_public_key_material!(material),
         true <- material["owner_kind"] == owner_kind,
         true <- material["owner_id"] == owner_id do
      :ok
    else
      _ -> {:error, :recipient_target_key_mismatch}
    end
  rescue
    ArgumentError -> {:error, :recipient_target_key_mismatch}
  end

  defp assert_signing_material(material, owner_kind, owner_id) do
    with :ok <- Signature.assert_public_key_material!(material),
         true <- material["owner_kind"] == owner_kind,
         true <- material["owner_id"] == owner_id do
      :ok
    else
      _ -> {:error, :recipient_target_key_mismatch}
    end
  rescue
    ArgumentError -> {:error, :recipient_target_key_mismatch}
  end

  defp fetch_uuid(attrs, key) do
    case Ecto.UUID.cast(Map.get(attrs, key)) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, :invalid_delivery_attempt}
    end
  end

  defp fetch_hash(attrs, key) do
    case Map.get(attrs, key) do
      value when is_binary(value) ->
        Hash.assert_blake3_base64url!(value)
        {:ok, value}

      _ ->
        {:error, :invalid_delivery_attempt}
    end
  rescue
    ArgumentError -> {:error, :invalid_delivery_attempt}
  end

  defp fetch_map(attrs, key) do
    case Map.get(attrs, key) do
      value when is_map(value) -> {:ok, value}
      _ -> {:error, :invalid_delivery_attempt}
    end
  end

  defp fetch_list(attrs, key) do
    case Map.get(attrs, key) do
      value when is_list(value) -> {:ok, value}
      _ -> {:error, :invalid_delivery_attempt}
    end
  end

  defp fetch_target_registration_proof("workspace_invitation", attrs) do
    if is_nil(Map.get(attrs, "target_registration_proof")),
      do: {:ok, nil},
      else: {:error, :invalid_delivery_attempt}
  end

  defp fetch_target_registration_proof("guest_invitation", attrs),
    do: fetch_map(attrs, "target_registration_proof")

  defp attempt_expiry(invitation_expiry) do
    ttl_expiry = DateTime.add(DateTime.utc_now(), @attempt_ttl_seconds, :second)

    case DateTime.compare(invitation_expiry, ttl_expiry) do
      :lt -> invitation_expiry
      _ -> ttl_expiry
    end
  end

  defp invitation_context_snapshot(%WorkspaceInvitation{} = invitation) do
    %{
      "invitation_id" => invitation.id,
      "role_id" => invitation.role_id || "NOT_APPLICABLE",
      "invited_email" => String.downcase(invitation.invited_email),
      "kek_version" => invitation.kek_version,
      "token_hash" => invitation.token_hash
    }
  end

  defp invitation_context_snapshot(%GuestInvitation{} = invitation) do
    base = %{
      "guest_invitation_id" => invitation.id,
      "scope_kind" => invitation.scope_kind,
      "scope_id" => invitation.scope_id || "none",
      "permission" => invitation.permission,
      "kek_version" => invitation.kek_version,
      "share_key_version" => invitation.share_key_version,
      "dek_version" => invitation.dek_version,
      "token_hash" => invitation.token_hash,
      "max_redemptions" => invitation.max_redemptions
    }

    if invitation.scope_kind == "workspace" do
      base
    else
      Map.merge(base, scoped_guest_delivery_context!(invitation))
    end
  end

  defp scoped_guest_delivery_context!(%GuestInvitation{} = invitation) do
    target =
      from(s in Share,
        join: d in Document,
        on: d.id == s.document_id,
        left_join: root in Share,
        on: root.id == s.parent_share_id,
        left_join: root_document in Document,
        on: root_document.id == root.document_id,
        where: s.id == ^invitation.share_id,
        select: %{
          share_id: s.id,
          resource_scope_kind: s.scope,
          resource_scope_id: d.id,
          management_share_id: fragment("COALESCE(?, ?)", root.id, s.id),
          management_document_id: fragment("COALESCE(?, ?)", root_document.id, d.id)
        },
        limit: 1
      )
      |> Repo.one!()

    %{
      "share_id" => target.share_id,
      "resource_scope_kind" => target.resource_scope_kind,
      "resource_scope_id" => target.resource_scope_id,
      "management_share_id" => target.management_share_id,
      "management_document_id" => target.management_document_id,
      "document_scope_hash" =>
        hash(%{
          "workspace_id" => invitation.workspace_id,
          "document_id" => target.resource_scope_id
        })
    }
  end

  defp expire_stale_attempts do
    now = DateTime.utc_now()

    from(a in InvitationDeliveryAttempt,
      where: a.status in ["pending", "approved"] and a.expires_at <= ^now
    )
    |> Repo.update_all(set: [status: "expired", consumed_at: now, updated_at: now])
  end

  defp expired?(expires_at), do: DateTime.compare(expires_at, DateTime.utc_now()) != :gt
  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()

  defp unwrap_transaction({:ok, result}), do: {:ok, result}
  defp unwrap_transaction({:error, reason}), do: {:error, reason}
end
