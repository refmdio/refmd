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

  @spec build_pop_transcript!(
          binary(),
          binary(),
          binary(),
          binary(),
          map(),
          map(),
          map() | nil
        ) ::
          map()
  def build_pop_transcript!(
        variant,
        owner_kind,
        owner_id,
        actor,
        challenge,
        session,
        resource \\ nil
      )

  @spec build_pop_transcript!(
          binary(),
          binary(),
          binary(),
          binary(),
          map(),
          map(),
          map() | nil
        ) ::
          map()
  def build_pop_transcript!(
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
    surface = SigningSurface.get_active!("pop_request", variant)
    transport = if String.starts_with?(variant, "channel_"), do: "phoenix_channel", else: "http"

    payload = %{
      "protocol" => @transcript_protocol,
      "label" => @transcript_label,
      "version" => @protocol_version,
      "transcript_owner" => surface.transcript_owner,
      "surface_id" => surface.surface_id,
      "surface_variant" => surface.variant,
      "signing_purpose" => "pop_request",
      "owner_kind" => owner_kind,
      "owner_id" => owner_id,
      "signature_suite_id" => @suite_id,
      "signature_suite_rank" => @suite_rank,
      "challenge" => challenge,
      "pop_variant" => variant,
      "transport" => transport,
      "actor" => normalize_pop_actor!(variant, actor),
      "session" => normalize_pop_session!(variant, session)
    }

    transcript = maybe_put_pop_resource!(payload, variant, resource)

    assert_transcript!(transcript, "pop_request", owner_kind, owner_id)
    transcript
  end

  def build_pop_transcript!(_, _, _, _, _, _, _),
    do: raise(ArgumentError, "pop_transcript_invalid")

  defp normalize_pop_actor!("http_user_device", actor), do: normalize_user_pop_actor!(actor)
  defp normalize_pop_actor!("channel_user_device", actor), do: normalize_user_pop_actor!(actor)

  defp normalize_pop_actor!("http_share_participant_device", actor),
    do: normalize_share_pop_actor!(actor)

  defp normalize_pop_actor!("channel_share_participant_device", actor),
    do: normalize_share_pop_actor!(actor)

  defp normalize_pop_actor!(_, _), do: raise(ArgumentError, "pop_actor_invalid")

  defp normalize_user_pop_actor!(actor) when is_map(actor) do
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

  defp normalize_share_pop_actor!(actor) when is_map(actor) do
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

  defp normalize_pop_session!("http_user_device", session),
    do: normalize_user_pop_session!(session)

  defp normalize_pop_session!("channel_user_device", session),
    do: normalize_user_pop_session!(session)

  defp normalize_pop_session!("http_share_participant_device", session),
    do: normalize_share_pop_session!(session)

  defp normalize_pop_session!("channel_share_participant_device", session),
    do: normalize_share_pop_session!(session)

  defp normalize_pop_session!(_, _), do: raise(ArgumentError, "pop_session_invalid")

  defp normalize_user_pop_session!(session) when is_map(session) do
    exact_map!(session, ["is_recovery", "session_id_hash", "session_kind"])
  end

  defp normalize_share_pop_session!(session) when is_map(session) do
    exact_map!(session, ["is_recovery", "session_id_hash", "session_kind", "share_id"])
  end

  defp exact_map!(map, keys) do
    if Map.keys(map) |> Enum.sort() == keys do
      map
    else
      raise ArgumentError, "pop_transcript_invalid"
    end
  end

  defp maybe_put_pop_resource!(payload, "http_" <> _, resource) when is_map(resource),
    do: Map.put(payload, "request", resource)

  defp maybe_put_pop_resource!(payload, "channel_" <> _, resource) when is_map(resource),
    do: Map.put(payload, "resource", resource)

  defp maybe_put_pop_resource!(_payload, "http_" <> _, _resource), do: raise(ArgumentError)
  defp maybe_put_pop_resource!(_payload, "channel_" <> _, _resource), do: raise(ArgumentError)
  defp maybe_put_pop_resource!(payload, _variant, _resource), do: payload

  @spec build_genesis_device_bootstrap_transcript!(map()) :: map()
  def build_genesis_device_bootstrap_transcript!(params) when is_map(params) do
    user_id = fetch_binary!(params, :user_id)
    device_id = fetch_binary!(params, :device_id)
    device_public_material = fetch_map!(params, :device_public_material)

    device_hybrid_encryption_public_key_material =
      fetch_map!(params, :device_hybrid_encryption_public_key_material)

    client_nonce = fetch_binary!(params, :client_nonce)
    registration_challenge_hash = fetch_binary!(params, :registration_challenge_hash)
    identity_signing_key_id = fetch_binary!(params, :identity_signing_key_id)
    user_identity_public_key_hash = fetch_binary!(params, :user_identity_public_key_hash)

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
        "client_nonce" => client_nonce,
        "user_id" => user_id,
        "identity_signing_key_id" => identity_signing_key_id,
        "device_id" => device_id,
        "device_signing_key_id" => device_signing_key_id,
        "device_hybrid_encryption_public_key_material_hash" =>
          device_hybrid_encryption_public_key_material_hash,
        "device_encryption_key_id" => encryption_key_id,
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

  @spec build_device_approval_transcript!(
          binary(),
          binary(),
          binary(),
          map(),
          map(),
          binary(),
          map()
        ) :: map()
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

  @spec build_device_revocation_transcript!(
          binary(),
          binary(),
          binary(),
          binary(),
          binary(),
          integer()
        ) :: map()
  def build_device_revocation_transcript!(
        user_id,
        actor_device_id,
        signing_key_id,
        revoked_device_id,
        revocation_mode,
        revoked_at_ms
      )
      when is_binary(user_id) and is_binary(actor_device_id) and is_binary(signing_key_id) and
             is_binary(revoked_device_id) and is_binary(revocation_mode) and
             is_integer(revoked_at_ms) do
    surface = SigningSurface.get_active!("device_revocation", "none")

    subject = %{
      "actor" => %{
        "device_id" => actor_device_id,
        "signing_key_id" => signing_key_id,
        "user_id" => user_id
      },
      "authority_boundary" => %{"user_id" => user_id},
      "revocation" => %{
        "device_id" => revoked_device_id,
        "mode" => revocation_mode,
        "revoked_at_ms" => revoked_at_ms
      }
    }

    transcript =
      transcript_base("device_revocation", surface, "device", actor_device_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(subject)),
        "subject_protocol" => "refmd.device.revocation",
        "subject_version" => @protocol_version,
        "actor" => subject["actor"],
        "authority_boundary" => subject["authority_boundary"],
        "revocation" => subject["revocation"]
      })

    assert_transcript!(transcript, "device_revocation", "device", actor_device_id)
    transcript
  end

  def build_device_revocation_transcript!(_, _, _, _, _, _),
    do: raise(ArgumentError, "device_revocation_transcript_invalid")
end
