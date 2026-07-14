defmodule RefMD.Workspaces.Invitations.KeyDirectory do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Devices
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Workspaces.{GuestInvitation, WorkspaceInvitation}

  def append_if_present(nil, _operation), do: Repo.rollback(:missing_key_directory)

  def append_if_present(%{events: events, checkpoint: checkpoint}, operation)
      when is_list(events) and is_map(checkpoint) and is_map(operation) do
    assert_append_matches_operation!(events, operation)

    checkpoint_signer_kind =
      if operation.kind in [:workspace_invitation_redeemed, :guest_invitation_redeemed] and
           is_nil(Map.get(operation, :recipient_delivery_attempt)),
         do: "invitation_redeem_authority",
         else: "device"

    append_key_directory!(
      operation,
      events,
      checkpoint,
      checkpoint_signer_kind
    )

    :ok
  rescue
    _ ->
      Repo.rollback(:invalid_key_directory)
  end

  def append_if_present(_key_directory, _operation), do: Repo.rollback(:invalid_key_directory)

  defp assert_append_matches_operation!(events, operation) when is_list(events) do
    expected_event_type = Atom.to_string(operation.kind)
    payloads = Enum.map(events, &Map.fetch!(&1, "payload"))
    payload = Enum.find(payloads, &(&1["event_type"] == expected_event_type))
    if is_nil(payload), do: raise(ArgumentError, "missing_admission_event")
    assert_allowed_event_set!(payloads, expected_event_type, operation)

    true = payload["scope_kind"] == "workspace"
    true = payload["scope_id"] == operation.workspace_id
    true = payload["event_type"] == expected_event_type
    assert_actor_matches!(payload["actor"], operation)
    assert_body_matches_operation!(expected_event_type, payload, operation)
  end

  defp assert_append_matches_operation!(_, _), do: raise(ArgumentError, "invalid_append")

  defp assert_allowed_event_set!(
         payloads,
         "workspace_invitation_redeemed",
         %{
           kind: :workspace_invitation_redeemed,
           recipient_delivery_attempt: attempt
         }
       ) do
    event_types = Enum.map(payloads, & &1["event_type"])

    if event_types != [
         "recipient_bound_delivery_admitted",
         "wrap_issued",
         "workspace_invitation_redeemed",
         "wrap_issued"
       ],
       do: raise(ArgumentError, "invalid_append_events")

    assert_recipient_bound_workspace_events!(payloads, attempt)
  end

  defp assert_allowed_event_set!(
         payloads,
         "guest_invitation_redeemed",
         %{
           kind: :guest_invitation_redeemed,
           recipient_delivery_attempt: attempt
         }
       )
       when not is_nil(attempt) do
    event_types = Enum.map(payloads, & &1["event_type"])

    if event_types != [
         "recipient_bound_delivery_admitted",
         "guest_invitation_redeemed",
         "wrap_issued"
       ],
       do: raise(ArgumentError, "invalid_append_events")

    assert_recipient_bound_guest_events!(payloads, attempt)
  end

  defp assert_allowed_event_set!(
         payloads,
         "workspace_invitation_redeemed",
         %{kind: :workspace_invitation_redeemed}
       ) do
    event_types = Enum.map(payloads, & &1["event_type"])

    if event_types != ["wrap_issued", "workspace_invitation_redeemed"],
      do: raise(ArgumentError, "invalid_append_events")

    :ok
  end

  defp assert_allowed_event_set!(
         payloads,
         "guest_invitation_redeemed",
         %{kind: :guest_invitation_redeemed}
       ) do
    event_types = Enum.map(payloads, & &1["event_type"])

    if event_types != ["guest_invitation_redeemed"],
      do: raise(ArgumentError, "invalid_append_events")

    :ok
  end

  defp assert_allowed_event_set!(
         [%{"event_type" => expected_event_type}],
         expected_event_type,
         _
       ),
       do: :ok

  defp assert_allowed_event_set!(_, _, _), do: raise(ArgumentError, "invalid_append_events")

  defp assert_recipient_bound_workspace_events!(
         [admission, member_wrap, redeemed, delivery_wrap],
         attempt
       ) do
    authorization = attempt.approved_artifacts["authorization"]["payload"]
    freshness = attempt.approved_artifacts["redeem_freshness_proof"]
    admission_body = admission["body"]
    member_wrap_body = member_wrap["body"]
    redeemed_body = redeemed["body"]
    delivery_wrap_body = delivery_wrap["body"]
    authorization_hash = context_hash(authorization)
    recipient_hash = context_hash(authorization["recipient"])

    assert_subset!(admission_body, %{
      "event_type" => "recipient_bound_delivery_admitted",
      "authorization_id" => authorization["authorization_id"],
      "redeem_attempt_id" => attempt.id,
      "authorization_hash" => authorization_hash,
      "workspace_id" => attempt.workspace_id,
      "context_kind" => "workspace_invitation",
      "context_id" => attempt.context_id,
      "recipient_hash" => recipient_hash,
      "recipient_device_id" => attempt.target_device_id,
      "permission" => "NOT_APPLICABLE",
      "share_session_id" => "NOT_APPLICABLE",
      "share_session_binding_hash" => "NOT_APPLICABLE",
      "recipient_nonce_state_hash" => attempt.recipient_nonce_state_hash,
      "live_redeem_challenge_hash" => attempt.live_redeem_challenge_hash,
      "redeem_freshness_proof_hash" => context_hash(freshness),
      "previous_workspace_event_sequence" => authorization["current_event_head_sequence"],
      "previous_workspace_event_hash" => authorization["current_event_head_hash"]
    })

    true = admission["sequence"] == authorization["current_event_head_sequence"] + 1
    true = admission["previous_event_hash"] == authorization["current_event_head_hash"]
    true = member_wrap["sequence"] == admission["sequence"] + 1
    true = member_wrap["previous_event_hash"] == event_hash(admission)
    true = member_wrap_body["purpose"] == "workspace_member_kek_wrap"
    true = redeemed["sequence"] == member_wrap["sequence"] + 1
    true = redeemed["previous_event_hash"] == event_hash(member_wrap)
    true = delivery_wrap["sequence"] == redeemed["sequence"] + 1
    true = delivery_wrap["previous_event_hash"] == event_hash(redeemed)
    true = delivery_wrap_body["purpose"] == "workspace_invitation_kek_wrap"

    true =
      delivery_wrap_body["resource"]["workspace_invitation_redeemed_event_hash"] ==
        event_hash(redeemed)

    true = redeemed_body["member_envelope_hash"] == context_hash(member_wrap_body)
    :ok
  end

  defp event_hash(payload), do: context_hash(payload)

  defp assert_recipient_bound_guest_events!([admission, redeemed, delivery_wrap], attempt) do
    authorization = attempt.approved_artifacts["authorization"]["payload"]
    freshness = attempt.approved_artifacts["redeem_freshness_proof"]
    admission_body = admission["body"]
    redeemed_body = redeemed["body"]
    delivery_wrap_body = delivery_wrap["body"]

    assert_subset!(admission_body, %{
      "event_type" => "recipient_bound_delivery_admitted",
      "authorization_id" => authorization["authorization_id"],
      "redeem_attempt_id" => attempt.id,
      "authorization_hash" => context_hash(authorization),
      "workspace_id" => attempt.workspace_id,
      "context_kind" => "guest_invitation",
      "context_id" => attempt.context_id,
      "recipient_hash" => context_hash(authorization["recipient"]),
      "recipient_device_id" => attempt.target_device_id,
      "permission" => "NOT_APPLICABLE",
      "share_session_id" => "NOT_APPLICABLE",
      "share_session_binding_hash" => "NOT_APPLICABLE",
      "recipient_nonce_state_hash" => attempt.recipient_nonce_state_hash,
      "live_redeem_challenge_hash" => attempt.live_redeem_challenge_hash,
      "redeem_freshness_proof_hash" => context_hash(freshness),
      "previous_workspace_event_sequence" => authorization["current_event_head_sequence"],
      "previous_workspace_event_hash" => authorization["current_event_head_hash"]
    })

    true = admission["sequence"] == authorization["current_event_head_sequence"] + 1
    true = admission["previous_event_hash"] == authorization["current_event_head_hash"]
    true = redeemed["sequence"] == admission["sequence"] + 1
    true = redeemed["previous_event_hash"] == event_hash(admission)
    true = delivery_wrap["sequence"] == redeemed["sequence"] + 1
    true = delivery_wrap["previous_event_hash"] == event_hash(redeemed)
    true = delivery_wrap_body["purpose"] == "guest_invitation_workspace_kek_wrap"
    true = redeemed_body["guest_user_id"] == attempt.target_user_id
    true = redeemed_body["guest_device_id"] == attempt.target_device_id

    true =
      delivery_wrap_body["resource"]["guest_invitation_redeemed_event_hash"] ==
        event_hash(redeemed)

    :ok
  end

  defp append_key_directory!(
         %{kind: :guest_invitation_redeemed, recipient_delivery_attempt: attempt},
         [admission, redeemed, delivery_wrap],
         checkpoint,
         "device"
       )
       when not is_nil(attempt) do
    intermediate_checkpoint =
      attempt.approved_artifacts["workspace_key_directory_intermediate_checkpoint"]

    Encryption.append_workspace_key_directory!(
      attempt.workspace_id,
      [admission, redeemed],
      intermediate_checkpoint,
      checkpoint_signer_kind: "device"
    )

    Encryption.append_workspace_key_directory!(
      attempt.workspace_id,
      [delivery_wrap],
      checkpoint,
      checkpoint_signer_kind: "device"
    )
  end

  defp append_key_directory!(operation, events, checkpoint, checkpoint_signer_kind) do
    Encryption.append_workspace_key_directory!(
      operation.workspace_id,
      events,
      checkpoint,
      checkpoint_signer_kind: checkpoint_signer_kind
    )
  end

  defp assert_actor_matches!(actor, %{actor_user_id: actor_user_id, actor_device_id: device_id})
       when is_binary(actor_user_id) and is_binary(device_id) do
    true = actor["user_id"] == actor_user_id
    true = actor["device_id"] == device_id
  end

  defp assert_actor_matches!(actor, %{actor_user_id: actor_user_id})
       when is_binary(actor_user_id) do
    true = actor["user_id"] == actor_user_id
  end

  defp assert_actor_matches!(
         actor,
         %{
           redeem_authority_signing_key_id: signing_key_id,
           invitation: %WorkspaceInvitation{} = invitation
         }
       )
       when is_binary(signing_key_id) do
    true = actor["signer_kind"] == "invitation_redeem_authority"
    true = actor["signing_key_id"] == signing_key_id
    true = actor["invitation_id"] == invitation.id
  end

  defp assert_actor_matches!(
         actor,
         %{
           recipient_delivery_attempt: %{
             approved_artifacts: %{
               "authorization" => authorization,
               "redeem_freshness_proof" => %{"authoritative_device" => authoritative_device}
             }
           },
           invitation: %GuestInvitation{}
         }
       ) do
    true = actor["signer_kind"] == "device"
    true = actor["user_id"] == authoritative_device["user_id"]
    true = actor["device_id"] == authoritative_device["device_id"]
    true = actor["signing_key_id"] == authorization["signing_key_id"]
  end

  defp assert_actor_matches!(
         actor,
         %{
           redeem_authority_signing_key_id: signing_key_id,
           invitation: %GuestInvitation{} = invitation
         }
       )
       when is_binary(signing_key_id) do
    true = actor["signer_kind"] == "invitation_redeem_authority"
    true = actor["signing_key_id"] == signing_key_id
    true = actor["invitation_id"] == invitation.id
  end

  defp assert_actor_matches!(actor, %{redeem_authority_signing_key_id: signing_key_id})
       when is_binary(signing_key_id) do
    true = actor["signer_kind"] == "invitation_redeem_authority"
    true = actor["signing_key_id"] == signing_key_id
  end

  defp assert_actor_matches!(_actor, _operation), do: :ok

  defp assert_body_matches_operation!(
         "workspace_invitation_created",
         payload,
         %{invitation: %WorkspaceInvitation{} = invitation, target_role: target_role}
       ) do
    assert_subset!(payload["body"], %{
      "workspace_id" => invitation.workspace_id,
      "invitation_id" => invitation.id,
      "role_id" => invitation.role_id,
      "base_role" => target_role.base_role,
      "delivery_mode" => invitation.delivery_mode,
      "recipient_user_id" => transcript_recipient_user_id(invitation.recipient_user_id),
      "recipient_device_ids" => Enum.sort(invitation.recipient_device_ids),
      "kek_version" => invitation.kek_version,
      "expires_event_sequence" => invitation_expiration_event_sequence(invitation.expires_at),
      "bootstrap_key_commitment" => invitation.bootstrap_key_commitment,
      "bootstrap_package_hash" => invitation.bootstrap_package_hash,
      "bootstrap_suite_id" => invitation.bootstrap_suite_id,
      "capability_context_hash" => invitation.capability_context_hash
    })

    true = payload["body"]["invitee_binding"]["kind"] == "email"
    true = payload["body"]["redeem_authority"]["signer_kind"] == "invitation_redeem_authority"
    assert_invitation_delivery_prestate!(invitation, payload)
  end

  defp assert_body_matches_operation!(
         "workspace_invitation_revoked",
         payload,
         %{invitation: %WorkspaceInvitation{} = invitation}
       ) do
    assert_subset!(payload["body"], %{
      "workspace_id" => invitation.workspace_id,
      "invitation_id" => invitation.id,
      "revoked_at_event_sequence" => payload["sequence"]
    })
  end

  defp assert_body_matches_operation!(
         "workspace_invitation_redeemed",
         payload,
         %{
           invitation: %WorkspaceInvitation{} = invitation,
           redeemed_user_id: user_id,
           redeemed_device_id: device_id
         } = operation
       ) do
    device = Devices.get_device(device_id)

    assert_subset!(payload["body"], %{
      "workspace_id" => invitation.workspace_id,
      "invitation_id" => invitation.id,
      "redeemed_user_id" => user_id,
      "redeemed_device_id" => device_id,
      "redeemed_encryption_key_id" => device.encryption_key_id,
      "member_envelope_key_version" => invitation.kek_version,
      "member_envelope_hash" => operation.member_envelope_hash,
      "redeemed_at_event_sequence" => payload["sequence"]
    })
  end

  defp assert_body_matches_operation!(
         "guest_invitation_created",
         payload,
         %{invitation: %GuestInvitation{} = invitation}
       ) do
    {scope_kind, scope_id} = guest_scope(invitation)

    assert_subset!(payload["body"], %{
      "workspace_id" => invitation.workspace_id,
      "guest_invitation_id" => invitation.id,
      "scope_kind" => scope_kind,
      "scope_id" => scope_id,
      "permission" => invitation.permission,
      "delivery_mode" => invitation.delivery_mode,
      "recipient_user_id" => transcript_recipient_user_id(invitation.recipient_user_id),
      "recipient_device_ids" => Enum.sort(invitation.recipient_device_ids),
      "allowed_share_ids_hash" => allowed_share_ids_hash(invitation),
      "expires_event_sequence" => invitation_expiration_event_sequence(invitation.expires_at),
      "bootstrap_key_commitment" => invitation.bootstrap_key_commitment,
      "bootstrap_package_hash" => invitation.bootstrap_package_hash,
      "bootstrap_suite_id" => invitation.bootstrap_suite_id,
      "capability_context_hash" => invitation.capability_context_hash
    })

    true = payload["body"]["key_version_context"] == guest_key_version_context(invitation)

    true = payload["body"]["redeem_authority"]["signer_kind"] == "invitation_redeem_authority"
    assert_invitation_delivery_prestate!(invitation, payload)
  end

  defp assert_body_matches_operation!(
         "guest_invitation_revoked",
         payload,
         %{invitation: %GuestInvitation{} = invitation}
       ) do
    assert_subset!(payload["body"], %{
      "workspace_id" => invitation.workspace_id,
      "guest_invitation_id" => invitation.id,
      "revoked_at_event_sequence" => payload["sequence"]
    })
  end

  defp assert_body_matches_operation!(
         "guest_invitation_redeemed",
         payload,
         %{
           invitation: %GuestInvitation{} = invitation,
           guest_grant_id: guest_grant_id,
           guest_user_id: user_id,
           guest_device_id: device_id
         } = operation
       ) do
    {scope_kind, scope_id} = guest_scope(invitation)
    device = Devices.get_device(device_id)
    recipient_account = Map.get(operation, :recipient_account)

    assert_subset!(payload["body"], %{
      "workspace_id" => invitation.workspace_id,
      "guest_invitation_id" => invitation.id,
      "guest_grant_id" => guest_grant_id,
      "guest_user_id" => user_id,
      "guest_device_id" => device_id,
      "guest_encryption_key_id" => device.encryption_key_id,
      "guest_signing_key_id" => device.signing_key_id,
      "scope_kind" => scope_kind,
      "scope_id" => scope_id,
      "permission" => invitation.permission,
      "recipient_account_user_id" => recipient_account_value(recipient_account, :user_id),
      "recipient_account_device_id" => recipient_account_value(recipient_account, :device_id),
      "redeemed_at_event_sequence" => payload["sequence"]
    })
  end

  defp assert_body_matches_operation!(_, _, _), do: raise(ArgumentError, "invalid_operation")

  defp assert_subset!(body, expected) when is_map(body) do
    Enum.each(expected, fn {key, value} ->
      true = Map.get(body, key) == value
    end)
  end

  defp assert_subset!(_, _), do: raise(ArgumentError, "invalid_body")

  defp guest_scope(%GuestInvitation{scope_kind: "workspace"}), do: {"workspace", "none"}

  defp guest_scope(%GuestInvitation{scope_kind: scope_kind, scope_id: document_id}),
    do: {scope_kind, document_id}

  defp transcript_recipient_user_id(nil), do: "NOT_APPLICABLE"
  defp transcript_recipient_user_id(user_id), do: user_id

  defp recipient_account_value(nil, _key), do: "NOT_APPLICABLE"
  defp recipient_account_value(account, key), do: Map.fetch!(account, key)

  defp assert_invitation_delivery_prestate!(%{delivery_mode: "unknown_fragment"}, _payload),
    do: :ok

  defp assert_invitation_delivery_prestate!(
         %{delivery_mode: "known_recipient", encrypted_bootstrap_package: package},
         _payload
       ) do
    true = package["package_key_recipient_wrap"]["wraps"] == []
  end

  defp assert_invitation_delivery_prestate!(_, _),
    do: raise(ArgumentError, "invalid_invitation_delivery")

  defp allowed_share_ids_hash(%GuestInvitation{scope_kind: "workspace"}),
    do: context_hash(%{"allowed_share_ids" => []})

  defp allowed_share_ids_hash(%GuestInvitation{share_id: share_id}) when is_binary(share_id),
    do: context_hash(%{"allowed_share_ids" => [share_id]})

  defp guest_key_version_context(%GuestInvitation{scope_kind: "workspace"} = invitation) do
    %{
      "workspace_kek_version" => invitation.kek_version,
      "share_key_version" => "NOT_APPLICABLE",
      "dek_version" => "NOT_APPLICABLE"
    }
  end

  defp guest_key_version_context(%GuestInvitation{} = invitation) do
    %{
      "workspace_kek_version" => "NOT_APPLICABLE",
      "share_key_version" => invitation.share_key_version,
      "dek_version" => invitation.dek_version
    }
  end

  defp invitation_expiration_event_sequence(%DateTime{} = expires_at),
    do: DateTime.to_unix(expires_at)

  defp context_hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
end
