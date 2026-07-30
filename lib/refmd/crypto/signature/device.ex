defmodule RefMD.Crypto.Signature.Device do
  @moduledoc false

  @protocol_version 1
  @suite_rank 1000
  @suite_id "refmd-v2-hybrid-signature-ed25519-mldsa65"

  @transcript_protocol "refmd.hybrid-signature-transcript"
  @transcript_label "RefMD hybrid signature transcript v1"

  import RefMD.Crypto.Signature.Core, only: [assert_transcript!: 4, transcript_base: 4]

  alias RefMD.Crypto.Hash
  alias RefMD.Crypto.HybridEncryptionMaterial
  alias RefMD.Crypto.JCS
  alias RefMD.Crypto.Signature
  alias RefMD.Crypto.SigningSurface

  def build_rrp_transcript!(
        variant,
        owner_kind,
        owner_id,
        actor,
        challenge,
        session,
        resource \\ nil
      )

  def build_rrp_transcript!(
        variant,
        owner_kind,
        owner_id,
        actor,
        challenge,
        session,
        resource
      )
      when is_binary(variant) and is_binary(owner_kind) and is_binary(owner_id) and
             is_map(actor) and is_binary(challenge) and is_map(session) do
    surface = SigningSurface.get_active!("rrp_request", variant)
    transport = if String.starts_with?(variant, "channel_"), do: "phoenix_channel", else: "http"

    payload = %{
      "protocol" => @transcript_protocol,
      "label" => @transcript_label,
      "version" => @protocol_version,
      "transcript_owner" => surface.transcript_owner,
      "surface_id" => surface.surface_id,
      "surface_variant" => surface.variant,
      "signing_purpose" => "rrp_request",
      "owner_kind" => owner_kind,
      "owner_id" => owner_id,
      "signature_suite_id" => @suite_id,
      "signature_suite_rank" => @suite_rank,
      "challenge" => challenge,
      "rrp_variant" => variant,
      "transport" => transport,
      "actor" => normalize_rrp_actor!(variant, actor),
      "session" => normalize_rrp_session!(variant, session)
    }

    transcript = maybe_put_rrp_resource!(payload, variant, resource)

    assert_transcript!(transcript, "rrp_request", owner_kind, owner_id)
    transcript
  end

  def build_rrp_transcript!(_, _, _, _, _, _, _),
    do: raise(ArgumentError, "rrp_transcript_invalid")

  defp normalize_rrp_actor!("http_user_device", actor), do: normalize_user_rrp_actor!(actor)
  defp normalize_rrp_actor!("channel_user_device", actor), do: normalize_user_rrp_actor!(actor)

  defp normalize_rrp_actor!("http_share_participant_device", actor),
    do: normalize_share_rrp_actor!(actor)

  defp normalize_rrp_actor!("channel_share_participant_device", actor),
    do: normalize_share_rrp_actor!(actor)

  defp normalize_rrp_actor!(_, _), do: raise(ArgumentError, "rrp_actor_invalid")

  defp normalize_user_rrp_actor!(actor) when is_map(actor) do
    exact_map!(actor, [
      "device_id",
      "key_checkpoint_hash",
      "key_checkpoint_sequence",
      "key_scope_id",
      "key_scope_kind",
      "signer_kind",
      "signing_key_id",
      "user_id"
    ])
  end

  defp normalize_share_rrp_actor!(actor) when is_map(actor) do
    exact_map!(actor, [
      "key_checkpoint_hash",
      "key_checkpoint_sequence",
      "key_scope_id",
      "key_scope_kind",
      "share_id",
      "share_participant_device_id",
      "share_participant_principal_id",
      "signer_kind",
      "signing_key_id"
    ])
  end

  defp normalize_rrp_session!("http_user_device", session),
    do: normalize_user_rrp_session!(session)

  defp normalize_rrp_session!("channel_user_device", session),
    do: normalize_user_rrp_session!(session)

  defp normalize_rrp_session!("http_share_participant_device", session),
    do: normalize_share_rrp_session!(session)

  defp normalize_rrp_session!("channel_share_participant_device", session),
    do: normalize_share_rrp_session!(session)

  defp normalize_rrp_session!(_, _), do: raise(ArgumentError, "rrp_session_invalid")

  defp normalize_user_rrp_session!(session) when is_map(session) do
    exact_map!(session, ["is_recovery", "session_id_hash", "session_kind"])
  end

  defp normalize_share_rrp_session!(session) when is_map(session) do
    exact_map!(session, ["is_recovery", "session_id_hash", "session_kind", "share_id"])
  end

  defp exact_map!(map, keys) do
    if Map.keys(map) |> Enum.sort() == keys do
      map
    else
      raise ArgumentError, "rrp_transcript_invalid"
    end
  end

  defp maybe_put_rrp_resource!(payload, "http_" <> _, resource) when is_map(resource),
    do: Map.put(payload, "request", resource)

  defp maybe_put_rrp_resource!(payload, "channel_" <> _, resource) when is_map(resource),
    do: Map.put(payload, "resource", resource)

  defp maybe_put_rrp_resource!(_payload, "http_" <> _, _resource), do: raise(ArgumentError)
  defp maybe_put_rrp_resource!(_payload, "channel_" <> _, _resource), do: raise(ArgumentError)
  defp maybe_put_rrp_resource!(payload, _variant, _resource), do: payload

  def build_genesis_device_bootstrap_transcript!(params) when is_map(params) do
    registration_id = fetch_binary!(params, :registration_id)
    compound_intent_id = fetch_binary!(params, :compound_intent_id)
    mutation_id = fetch_binary!(params, :mutation_id)
    genesis_compound_context_hash = fetch_binary!(params, :genesis_compound_context_hash)
    user_id = fetch_binary!(params, :user_id)
    workspace_id = fetch_binary!(params, :workspace_id)
    owner_role_id = fetch_binary!(params, :owner_role_id)
    device_id = fetch_binary!(params, :device_id)
    device_public_material = fetch_map!(params, :device_public_material)

    device_hybrid_encryption_public_key_material =
      fetch_map!(params, :device_hybrid_encryption_public_key_material)

    client_nonce = fetch_binary!(params, :client_nonce)
    registration_challenge_hash = fetch_binary!(params, :registration_challenge_hash)
    identity_signing_key_id = fetch_binary!(params, :identity_signing_key_id)
    user_identity_public_key_hash = fetch_binary!(params, :user_identity_public_key_hash)
    user_device_key_added_event_hash = fetch_binary!(params, :user_device_key_added_event_hash)

    workspace_device_key_added_event_hash =
      fetch_binary!(params, :workspace_device_key_added_event_hash)

    owner_member_added_event_hash = fetch_binary!(params, :owner_member_added_event_hash)

    workspace_member_envelope_commitment_hash =
      fetch_binary!(params, :workspace_member_envelope_commitment_hash)

    user_audit_checkpoint = fetch_audit_checkpoint_ref!(params, :user_audit_checkpoint)
    workspace_audit_checkpoint = fetch_audit_checkpoint_ref!(params, :workspace_audit_checkpoint)

    surface = SigningSurface.get_active!("genesis_device_bootstrap", "none")

    encryption_key_id =
      HybridEncryptionMaterial.compute_key_id!(device_hybrid_encryption_public_key_material)

    device_signing_key_id = Signature.compute_signing_key_id!(device_public_material)

    device_hybrid_encryption_public_key_material_hash =
      Hash.blake3_base64url(JCS.canonical_bytes!(device_hybrid_encryption_public_key_material))

    bootstrap_authority = %{
      "authority_kind" => "first_device_no_existing_active_device",
      "user_identity_public_key_hash" => user_identity_public_key_hash,
      "registration_challenge_hash" => registration_challenge_hash
    }

    transcript =
      transcript_base("genesis_device_bootstrap", surface, "identity", user_id)
      |> Map.merge(%{
        "subject_protocol" => "refmd.genesis-device-bootstrap",
        "subject_version" => @protocol_version,
        "registration_id" => registration_id,
        "compound_intent_id" => compound_intent_id,
        "mutation_id" => mutation_id,
        "genesis_compound_context_hash" => genesis_compound_context_hash,
        "client_nonce" => client_nonce,
        "user_id" => user_id,
        "workspace_id" => workspace_id,
        "owner_role_id" => owner_role_id,
        "identity_signing_key_id" => identity_signing_key_id,
        "device_id" => device_id,
        "device_signing_key_id" => device_signing_key_id,
        "device_hybrid_encryption_public_key_material_hash" =>
          device_hybrid_encryption_public_key_material_hash,
        "device_encryption_key_id" => encryption_key_id,
        "user_device_key_added_event_hash" => user_device_key_added_event_hash,
        "workspace_device_key_added_event_hash" => workspace_device_key_added_event_hash,
        "owner_member_added_event_hash" => owner_member_added_event_hash,
        "workspace_member_envelope_commitment_hash" => workspace_member_envelope_commitment_hash,
        "user_audit_checkpoint" => user_audit_checkpoint,
        "workspace_audit_checkpoint" => workspace_audit_checkpoint,
        "bootstrap_authority" => bootstrap_authority
      })

    assert_transcript!(transcript, "genesis_device_bootstrap", "identity", user_id)
    transcript
  end

  def build_genesis_device_bootstrap_transcript!(_),
    do: raise(ArgumentError, "genesis_device_bootstrap_transcript_invalid")

  defp fetch_binary!(params, key) do
    case Map.fetch!(params, key) do
      value when is_binary(value) -> value
      _ -> raise ArgumentError, "genesis_device_bootstrap_transcript_invalid"
    end
  end

  defp fetch_map!(params, key) do
    case Map.fetch!(params, key) do
      value when is_map(value) -> value
      _ -> raise ArgumentError, "genesis_device_bootstrap_transcript_invalid"
    end
  end

  defp fetch_audit_checkpoint_ref!(params, key) do
    case fetch_map!(params, key) do
      %{"sequence" => sequence, "checkpoint_hash" => checkpoint_hash} = value
      when map_size(value) == 2 and is_integer(sequence) and sequence > 0 and
             is_binary(checkpoint_hash) ->
        value

      _ ->
        raise ArgumentError, "genesis_device_bootstrap_transcript_invalid"
    end
  end

  def build_device_approval_transcript!(
        user_id,
        approver_device_id,
        approved_device_id,
        approved_device_public_material,
        approved_device_hybrid_encryption_public_key_material,
        client_nonce,
        commitments
      )
      when is_binary(user_id) and is_binary(approver_device_id) and
             is_binary(approved_device_id) and is_map(approved_device_public_material) and
             is_map(approved_device_hybrid_encryption_public_key_material) and
             is_binary(client_nonce) and is_map(commitments) do
    surface = SigningSurface.get_active!("device_approval", "none")

    subject = %{
      "approval_signature_surface" => "device_approval",
      "approved_device_registration_sas_hash" =>
        Map.fetch!(commitments, "approved_device_registration_sas_hash"),
      "approving_key_checkpoint_hash" => Map.fetch!(commitments, "approving_key_checkpoint_hash"),
      "approving_device_key_directory_proof_hash" =>
        Map.fetch!(commitments, "approving_device_key_directory_proof_hash"),
      "approving_key_checkpoint_sequence" =>
        Map.fetch!(commitments, "approving_key_checkpoint_sequence"),
      "approving_owner_id" => Map.fetch!(commitments, "approving_owner_id"),
      "approving_owner_kind" => Map.fetch!(commitments, "approving_owner_kind"),
      "approving_signing_key_id" => Map.fetch!(commitments, "approving_signing_key_id"),
      "device_approval_kek_initial_delivery_commitments" =>
        Map.fetch!(commitments, "device_approval_kek_initial_delivery_commitments"),
      "pending_registration_challenge_hash" =>
        Map.fetch!(commitments, "pending_registration_challenge_hash"),
      "pending_registration_id" => Map.fetch!(commitments, "pending_registration_id"),
      "target_device_client_nonce_hash" =>
        Map.fetch!(commitments, "target_device_client_nonce_hash"),
      "target_device_encryption_key_id" =>
        Map.fetch!(commitments, "target_device_encryption_key_id"),
      "target_device_hybrid_encryption_public_key_material_hash" =>
        Map.fetch!(commitments, "target_device_hybrid_encryption_public_key_material_hash"),
      "target_device_hybrid_signing_public_key_material_hash" =>
        Map.fetch!(commitments, "target_device_hybrid_signing_public_key_material_hash"),
      "target_device_id" => Map.fetch!(commitments, "target_device_id"),
      "target_device_signing_key_id" => Map.fetch!(commitments, "target_device_signing_key_id"),
      "target_key_checkpoint_hash" => Map.fetch!(commitments, "target_key_checkpoint_hash"),
      "target_key_checkpoint_sequence" =>
        Map.fetch!(commitments, "target_key_checkpoint_sequence"),
      "trust_transfer_delivery_commitment" =>
        Map.fetch!(commitments, "trust_transfer_delivery_commitment"),
      "umk_distribution_delivery_commitment" =>
        Map.fetch!(commitments, "umk_distribution_delivery_commitment")
    }

    transcript =
      transcript_base("device_approval", surface, "device", approver_device_id)
      |> Map.merge(%{
        "approved_device_registration_sas_hash" =>
          subject["approved_device_registration_sas_hash"],
        "approval_signature_surface" => "device_approval",
        "device_approval_kek_initial_delivery_commitments" =>
          subject["device_approval_kek_initial_delivery_commitments"],
        "pending_registration_challenge_hash" => subject["pending_registration_challenge_hash"],
        "pending_registration_id" => subject["pending_registration_id"],
        "approving_owner_kind" => subject["approving_owner_kind"],
        "approving_owner_id" => subject["approving_owner_id"],
        "approving_signing_key_id" => subject["approving_signing_key_id"],
        "approving_key_checkpoint_sequence" => subject["approving_key_checkpoint_sequence"],
        "approving_key_checkpoint_hash" => subject["approving_key_checkpoint_hash"],
        "approving_device_key_directory_proof_hash" =>
          subject["approving_device_key_directory_proof_hash"],
        "target_device_id" => subject["target_device_id"],
        "target_device_signing_key_id" => subject["target_device_signing_key_id"],
        "target_device_hybrid_signing_public_key_material_hash" =>
          subject["target_device_hybrid_signing_public_key_material_hash"],
        "target_device_hybrid_encryption_public_key_material_hash" =>
          subject["target_device_hybrid_encryption_public_key_material_hash"],
        "target_device_encryption_key_id" => subject["target_device_encryption_key_id"],
        "target_device_client_nonce_hash" => subject["target_device_client_nonce_hash"],
        "target_key_checkpoint_sequence" => subject["target_key_checkpoint_sequence"],
        "target_key_checkpoint_hash" => subject["target_key_checkpoint_hash"],
        "trust_transfer_delivery_commitment" => subject["trust_transfer_delivery_commitment"],
        "umk_distribution_delivery_commitment" => subject["umk_distribution_delivery_commitment"]
      })

    assert_transcript!(transcript, "device_approval", "device", approver_device_id)
    transcript
  end

  def build_device_approval_transcript!(_, _, _, _, _, _, _),
    do: raise(ArgumentError, "device_approval_transcript_invalid")

  def build_device_revocation_transcript!(owner_id, actor, revoked_device, authority_boundary)
      when is_binary(owner_id) and is_map(actor) and is_map(revoked_device) and
             is_map(authority_boundary) do
    surface = SigningSurface.get_active!("device_revocation", "none")
    validate_device_revocation_subject!(owner_id, actor, revoked_device, authority_boundary)

    subject = %{
      "actor" => actor,
      "revoked_device" => revoked_device,
      "authority_boundary" => authority_boundary
    }

    transcript =
      transcript_base("device_revocation", surface, "device", owner_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(subject)),
        "subject_protocol" => "refmd.device-revocation",
        "subject_version" => @protocol_version,
        "actor" => subject["actor"],
        "authority_boundary" => subject["authority_boundary"],
        "revoked_device" => subject["revoked_device"]
      })

    assert_transcript!(transcript, "device_revocation", "device", owner_id)
    transcript
  end

  def build_device_revocation_transcript!(_, _, _, _),
    do: raise(ArgumentError, "device_revocation_transcript_invalid")

  defp validate_device_revocation_subject!(owner_id, actor, revoked_device, authority_boundary) do
    assert_exact_keys!(actor, ~w(device_id key_checkpoint_hash key_checkpoint_sequence
                                  key_scope_id key_scope_kind signing_key_id user_id))
    assert_exact_keys!(revoked_device, ~w(device_id encryption_key_id signing_key_id user_id))
    assert_exact_keys!(authority_boundary, ~w(revocation_event_hash revocation_event_sequence))

    unless actor["device_id"] == owner_id and actor["key_scope_kind"] == "user" and
             actor["key_scope_id"] == actor["user_id"] and
             revoked_device["user_id"] == actor["user_id"] and
             is_integer(actor["key_checkpoint_sequence"]) and actor["key_checkpoint_sequence"] > 0 and
             is_integer(authority_boundary["revocation_event_sequence"]) and
             authority_boundary["revocation_event_sequence"] > 0 do
      raise ArgumentError, "device_revocation_transcript_invalid"
    end

    Enum.each(
      [
        actor["signing_key_id"],
        actor["key_checkpoint_hash"],
        revoked_device["encryption_key_id"],
        revoked_device["signing_key_id"],
        authority_boundary["revocation_event_hash"]
      ],
      &Hash.assert_blake3_base64url!/1
    )

    :ok
  end

  defp assert_exact_keys!(value, keys) do
    unless Enum.sort(Map.keys(value)) == Enum.sort(keys),
      do: raise(ArgumentError, "device_revocation_transcript_invalid")
  end
end
