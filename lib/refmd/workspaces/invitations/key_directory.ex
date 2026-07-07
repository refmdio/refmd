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
      if operation.kind in [:workspace_invitation_redeemed, :guest_invitation_redeemed],
        do: "invitation_redeem_authority",
        else: "device"

    Encryption.append_workspace_key_directory!(
      operation.workspace_id,
      events,
      checkpoint,
      checkpoint_signer_kind: checkpoint_signer_kind
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
      "kek_version" => invitation.kek_version,
      "expires_event_sequence" => invitation_expiration_event_sequence(invitation.expires_at),
      "bootstrap_key_commitment" => invitation.bootstrap_key_commitment,
      "bootstrap_package_hash" => invitation.bootstrap_package_hash,
      "bootstrap_suite_id" => invitation.bootstrap_suite_id,
      "capability_context_hash" => invitation.capability_context_hash
    })

    true = payload["body"]["invitee_binding"]["kind"] == "email"
    true = payload["body"]["redeem_authority"]["signer_kind"] == "invitation_redeem_authority"
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
      "allowed_share_ids_hash" => empty_allowed_share_ids_hash(),
      "expires_event_sequence" => invitation_expiration_event_sequence(invitation.expires_at),
      "bootstrap_key_commitment" => invitation.bootstrap_key_commitment,
      "bootstrap_package_hash" => invitation.bootstrap_package_hash,
      "bootstrap_suite_id" => invitation.bootstrap_suite_id,
      "capability_context_hash" => invitation.capability_context_hash
    })

    true =
      if scope_kind == "workspace" do
        payload["body"]["key_version_context"]["workspace_kek_version"] == invitation.kek_version
      else
        payload["body"]["key_version_context"]["workspace_kek_version"] == "NOT_APPLICABLE"
      end

    true = payload["body"]["redeem_authority"]["signer_kind"] == "invitation_redeem_authority"
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
         }
       ) do
    {scope_kind, scope_id} = guest_scope(invitation)
    device = Devices.get_device(device_id)

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

  defp empty_allowed_share_ids_hash do
    context_hash(%{"allowed_share_ids" => []})
  end

  defp invitation_expiration_event_sequence(%DateTime{} = expires_at),
    do: DateTime.to_unix(expires_at)

  defp context_hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
end
