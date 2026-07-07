defmodule RefMD.Crypto.Signature.Share do
  @moduledoc false

  @protocol_version 1

  import RefMD.Crypto.Signature.Core, only: [assert_transcript!: 4, transcript_base: 4]

  alias RefMD.Crypto.Hash
  alias RefMD.Crypto.JCS
  alias RefMD.Crypto.SigningSurface

  def build_recipient_bound_authorization_transcript!(
        owner_id,
        actor_user_id,
        actor_device_id,
        signing_key_id,
        authorization_payload
      )
      when is_binary(owner_id) and is_binary(actor_user_id) and is_binary(actor_device_id) and
             is_binary(signing_key_id) and is_map(authorization_payload) do
    surface = SigningSurface.get_active!("recipient_bound_authorization", "none")
    payload = normalize_recipient_bound_authorization_payload!(authorization_payload)

    if payload["redeem_authority_signing_key_id"] != signing_key_id,
      do: raise(ArgumentError, "recipient_bound_authorization_signing_key_mismatch")

    transcript =
      transcript_base("recipient_bound_authorization", surface, "device", owner_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(payload)),
        "subject_protocol" => "refmd.recipient-bound-authorization",
        "subject_version" => @protocol_version,
        "actor" => %{
          "signer_kind" => "device",
          "user_id" => actor_user_id,
          "device_id" => actor_device_id,
          "signing_key_id" => signing_key_id,
          "key_scope_kind" => "workspace",
          "key_scope_id" => payload["workspace_id"],
          "key_checkpoint_sequence" => payload["current_checkpoint_sequence"],
          "key_checkpoint_hash" => payload["current_checkpoint_hash"]
        },
        "authority_boundary" => %{
          "workspace_id" => payload["workspace_id"],
          "authorization_id" => payload["authorization_id"],
          "redeem_attempt_id" => payload["redeem_attempt_id"],
          "context_kind" => payload["context_kind"],
          "context_id" => payload["context_id"],
          "current_checkpoint_sequence" => payload["current_checkpoint_sequence"],
          "current_checkpoint_hash" => payload["current_checkpoint_hash"],
          "current_event_head_sequence" => payload["current_event_head_sequence"],
          "current_event_head_hash" => payload["current_event_head_hash"],
          "resource_hash" => payload["resource_hash"],
          "workspace_pin_bootstrap_hash" => payload["workspace_pin_bootstrap_hash"]
        },
        "recipient" => payload["recipient"],
        "freshness" => %{
          "recipient_redeem_nonce" => payload["recipient_redeem_nonce"],
          "recipient_nonce_state_hash" => payload["recipient_nonce_state_hash"],
          "live_redeem_challenge_hash" => payload["live_redeem_challenge_hash"],
          "redeem_freshness_proof_hash" => payload["redeem_freshness_proof_hash"],
          "not_after_event_sequence" => payload["not_after_event_sequence"]
        }
      })

    assert_transcript!(transcript, "recipient_bound_authorization", "device", owner_id)
    transcript
  end

  def build_recipient_bound_authorization_transcript!(_, _, _, _, _),
    do: raise(ArgumentError, "recipient_bound_authorization_transcript_invalid")

  def build_share_capability_authorization_transcript!(params) when is_map(params) do
    surface = SigningSurface.get_active!("share_capability_authorization", "none")
    subject = share_capability_authorization_subject!(params)
    owner_id = subject["authorization"]["token_hash"]

    transcript =
      transcript_base("share_capability_authorization", surface, "share_capability", owner_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(subject)),
        "subject_protocol" => "refmd.share.capability_authorization",
        "subject_version" => @protocol_version,
        "authorization" => subject["authorization"],
        "share_state" => subject["share_state"]
      })

    assert_transcript!(transcript, "share_capability_authorization", "share_capability", owner_id)
    transcript
  end

  def build_share_capability_authorization_transcript!(_),
    do: raise(ArgumentError, "share_capability_authorization_transcript_invalid")

  def build_share_participant_device_authorization_transcript!(params) when is_map(params) do
    params = share_participant_device_authorization_params!(params)
    surface = SigningSurface.get_active!("share_participant_device_authorization", "none")

    transcript =
      transcript_base(
        "share_participant_device_authorization",
        surface,
        "share_participant_device",
        params.share_participant_device_id
      )
      |> Map.merge(%{
        "share_id" => params.share_id,
        "share_session_id" => params.share_session_id,
        "share_participant_principal_id" => params.share_participant_principal_id,
        "share_participant_device_id" => params.share_participant_device_id,
        "participant_signing_key_id" => params.participant_signing_key_id,
        "participant_encryption_key_id" => params.participant_encryption_key_id,
        "capability_context_hash" => params.capability_context_hash,
        "share_created_event_hash" => params.share_created_event_hash,
        "latest_bootstrap_event_hash" => params.latest_bootstrap_event_hash,
        "scope_kind" => params.scope_kind,
        "scope_id" => params.scope_id,
        "permission" => params.permission
      })

    assert_transcript!(
      transcript,
      "share_participant_device_authorization",
      "share_participant_device",
      params.share_participant_device_id
    )

    transcript
  end

  def build_share_participant_device_authorization_transcript!(_),
    do: raise(ArgumentError, "share_participant_device_authorization_transcript_invalid")

  defp share_capability_authorization_subject!(params) do
    %{
      "authorization" => %{
        "token_hash" => Map.get(params, :token_hash),
        "workspace_pin_bootstrap_hash" => Map.get(params, :workspace_pin_bootstrap_hash)
      },
      "share_state" => %{
        "share_id" => Map.get(params, :share_id),
        "scope_kind" => Map.get(params, :scope_kind),
        "scope_id" => Map.get(params, :scope_id),
        "permission" => Map.get(params, :permission),
        "password_protected" => Map.get(params, :password_protected),
        "created_event_hash" => Map.get(params, :created_event_hash),
        "latest_bootstrap_event_hash" => Map.get(params, :latest_bootstrap_event_hash),
        "capability_context_hash" => Map.get(params, :capability_context_hash),
        "share_capability_secret_commitment" =>
          Map.get(params, :share_capability_secret_commitment),
        "password_capability_secret_commitment" =>
          Map.get(params, :password_capability_secret_commitment) || "none"
      }
    }
    |> validate_share_capability_authorization_subject!()
  end

  defp share_participant_device_authorization_params!(params) do
    invalid = "share_participant_device_authorization_transcript_invalid"

    %{
      share_id: assert_non_empty_string!(params[:share_id], invalid),
      share_session_id: assert_non_empty_string!(params[:share_session_id], invalid),
      share_participant_principal_id:
        assert_non_empty_string!(params[:share_participant_principal_id], invalid),
      share_participant_device_id:
        assert_non_empty_string!(params[:share_participant_device_id], invalid),
      participant_signing_key_id:
        assert_non_empty_string!(params[:participant_signing_key_id], invalid),
      participant_encryption_key_id:
        assert_non_empty_string!(params[:participant_encryption_key_id], invalid),
      capability_context_hash:
        assert_non_empty_string!(params[:capability_context_hash], invalid),
      share_created_event_hash:
        assert_non_empty_string!(params[:share_created_event_hash], invalid),
      latest_bootstrap_event_hash:
        assert_non_empty_string!(params[:latest_bootstrap_event_hash], invalid),
      scope_kind: assert_enum!(params[:scope_kind], ["document", "folder"], invalid),
      scope_id: assert_non_empty_string!(params[:scope_id], invalid),
      permission: assert_enum!(params[:permission], ["view", "edit"], invalid)
    }
  end

  defp assert_non_empty_string!(value, _invalid) when is_binary(value) and value != "", do: value
  defp assert_non_empty_string!(_value, invalid), do: raise(ArgumentError, invalid)

  defp assert_enum!(value, allowed, invalid) do
    if value in allowed,
      do: value,
      else: raise(ArgumentError, invalid)
  end

  defp validate_share_capability_authorization_subject!(subject) do
    authorization = subject["authorization"]
    share_state = subject["share_state"]

    valid? =
      [
        is_binary(authorization["token_hash"]),
        is_binary(authorization["workspace_pin_bootstrap_hash"]),
        share_state["scope_kind"] in ["document", "folder"],
        share_state["permission"] in ["view", "edit"],
        is_boolean(share_state["password_protected"]),
        Enum.all?(
          [
            "share_id",
            "scope_id",
            "created_event_hash",
            "latest_bootstrap_event_hash",
            "capability_context_hash",
            "share_capability_secret_commitment",
            "password_capability_secret_commitment"
          ],
          &is_binary(share_state[&1])
        )
      ]
      |> Enum.all?()

    if valid? do
      subject
    else
      raise ArgumentError, "share_capability_authorization_transcript_invalid"
    end
  end

  defp normalize_recipient_bound_authorization_payload!(payload) do
    expected_keys = [
      "authorization_id",
      "context_id",
      "context_kind",
      "current_checkpoint_hash",
      "current_checkpoint_sequence",
      "current_event_head_hash",
      "current_event_head_sequence",
      "live_redeem_challenge_hash",
      "not_after_event_sequence",
      "protocol",
      "recipient",
      "recipient_nonce_state_hash",
      "recipient_redeem_nonce",
      "redeem_attempt_id",
      "redeem_authority_signing_key_id",
      "redeem_freshness_proof_hash",
      "resource_hash",
      "workspace_id",
      "workspace_pin_bootstrap_hash",
      "version"
    ]

    if Map.keys(payload) |> Enum.sort() != Enum.sort(expected_keys) do
      raise ArgumentError, "recipient_bound_authorization_payload_invalid"
    end

    with %{
           "authorization_id" => authorization_id,
           "protocol" => protocol,
           "version" => version,
           "redeem_attempt_id" => redeem_attempt_id,
           "workspace_id" => workspace_id,
           "context_kind" => context_kind,
           "context_id" => context_id,
           "resource_hash" => resource_hash,
           "recipient" => recipient,
           "workspace_pin_bootstrap_hash" => workspace_pin_bootstrap_hash,
           "current_checkpoint_sequence" => current_checkpoint_sequence,
           "current_checkpoint_hash" => current_checkpoint_hash,
           "current_event_head_sequence" => current_event_head_sequence,
           "current_event_head_hash" => current_event_head_hash,
           "redeem_authority_signing_key_id" => redeem_authority_signing_key_id,
           "recipient_redeem_nonce" => recipient_redeem_nonce,
           "recipient_nonce_state_hash" => recipient_nonce_state_hash,
           "live_redeem_challenge_hash" => live_redeem_challenge_hash,
           "redeem_freshness_proof_hash" => redeem_freshness_proof_hash,
           "not_after_event_sequence" => not_after_event_sequence
         } <- payload,
         true <- protocol == "refmd.recipient-bound-authorization",
         true <- version == @protocol_version,
         true <- is_binary(authorization_id),
         true <- is_binary(redeem_attempt_id),
         true <- is_binary(workspace_id),
         true <- context_kind in ["workspace_invitation", "guest_invitation", "share"],
         true <- is_binary(context_id),
         true <- is_binary(resource_hash),
         true <- valid_recipient_bound_recipient?(recipient),
         true <- is_binary(workspace_pin_bootstrap_hash),
         true <- is_integer(current_checkpoint_sequence) and current_checkpoint_sequence > 0,
         true <- is_binary(current_checkpoint_hash),
         true <- is_integer(current_event_head_sequence) and current_event_head_sequence > 0,
         true <- is_binary(current_event_head_hash),
         true <- is_binary(redeem_authority_signing_key_id),
         true <- is_binary(recipient_redeem_nonce),
         true <- is_binary(recipient_nonce_state_hash),
         true <- is_binary(live_redeem_challenge_hash),
         true <- is_binary(redeem_freshness_proof_hash),
         true <- is_integer(not_after_event_sequence) and not_after_event_sequence > 0 do
      payload
    else
      _ -> raise ArgumentError, "recipient_bound_authorization_payload_invalid"
    end
  end

  defp valid_recipient_bound_recipient?(recipient) when is_map(recipient) do
    expected_keys = [
      "encryption_key_id",
      "recipient_device_id",
      "recipient_kind",
      "recipient_principal_id"
    ]

    Map.keys(recipient) |> Enum.sort() == expected_keys and
      recipient["recipient_kind"] in ["invitee", "guest", "share_participant_device"] and
      Enum.all?(
        ["recipient_principal_id", "recipient_device_id", "encryption_key_id"],
        &is_binary(recipient[&1])
      )
  end

  defp valid_recipient_bound_recipient?(_), do: false
end
