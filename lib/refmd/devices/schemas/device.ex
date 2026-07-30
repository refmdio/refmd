defmodule RefMD.Devices.Device do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.{Encoding, Hash, HybridEncryptionMaterial, JCS, Signature}

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id
  @approval_proof_keys MapSet.new([
                         "approval_signature_surface",
                         "approval_surface_id",
                         "approval_surface_variant",
                         "approval_transcript_hash",
                         "approval_transcript_owner",
                         "approving_key_checkpoint_hash",
                         "approving_key_checkpoint_sequence",
                         "approving_owner_id",
                         "approving_owner_kind",
                         "approving_signing_key_id",
                         "protocol",
                         "surface_details",
                         "target_device_client_nonce_hash",
                         "target_device_encryption_key_id",
                         "target_device_hybrid_encryption_public_key_material_hash",
                         "target_device_hybrid_signing_public_key_material_hash",
                         "target_device_id",
                         "target_device_signing_key_id",
                         "target_key_checkpoint_hash",
                         "target_key_checkpoint_sequence",
                         "version"
                       ])
  @genesis_details_keys MapSet.new([
                          "compound_intent_id",
                          "genesis_compound_context_hash",
                          "kind",
                          "mutation_id",
                          "owner_member_added_event_hash",
                          "owner_role_id",
                          "registration_id",
                          "registration_challenge_hash",
                          "user_audit_checkpoint",
                          "user_device_key_added_event_hash",
                          "user_identity_public_key_hash",
                          "workspace_audit_checkpoint",
                          "workspace_device_key_added_event_hash",
                          "workspace_id",
                          "workspace_member_envelope_commitment_hash"
                        ])
  @device_approval_details_keys MapSet.new([
                                  "approved_device_registration_sas_hash",
                                  "approving_device_key_directory_proof_hash",
                                  "device_approval_kek_initial_delivery_commitments",
                                  "kind",
                                  "pending_registration_challenge_hash",
                                  "pending_registration_id",
                                  "trust_transfer_delivery_commitment",
                                  "umk_distribution_delivery_commitment"
                                ])
  @recovery_approval_details_keys MapSet.new([
                                    "kind",
                                    "pending_registration_binding_hash",
                                    "pending_registration_challenge_hash",
                                    "pending_registration_id",
                                    "recovery_capability_hash",
                                    "recovery_session_transcript_hash"
                                  ])
  @trust_transfer_commitment_keys MapSet.new([
                                    "ake_session_id",
                                    "delivery_id",
                                    "delivery_record_hash",
                                    "document_rollback_pin_set_hash",
                                    "transfer_scope_hash",
                                    "audit_checkpoint_pin_set_hash",
                                    "key_checkpoint_hash",
                                    "purpose",
                                    "recipient_device_id",
                                    "sender_device_id",
                                    "variant"
                                  ])
  @umk_distribution_commitment_keys MapSet.new([
                                      "delivery_id",
                                      "delivery_record_hash",
                                      "key_checkpoint_hash",
                                      "purpose",
                                      "recipient_device_id",
                                      "sender_device_id",
                                      "variant"
                                    ])
  @device_approval_kek_commitment_keys MapSet.new([
                                         "delivery_id",
                                         "delivery_record_hash",
                                         "key_checkpoint_hash",
                                         "key_version",
                                         "purpose",
                                         "recipient_device_id",
                                         "sender_device_id",
                                         "variant",
                                         "workspace_id"
                                       ])

  schema "devices" do
    belongs_to :user, RefMD.Users.User
    field :name, :string
    field :device_type, :string
    field :hybrid_encryption_public_key_material, :map
    field :encryption_key_id, :string
    field :hybrid_signing_public_key_material, :map
    field :signing_key_id, :string
    field :approval_signature, :map
    field :approval_signature_surface, :string
    field :approval_proof, :map
    field :approval_delivery_commitments, :map
    field :approval_delivery_artifacts, :map
    field :key_checkpoint_sequence, :integer
    field :key_checkpoint_hash, :string
    field :client_nonce, :binary
    field :last_seen_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
    field :revoked_at, :utc_datetime_usec
    field :identity_wipe_required_at, :utc_datetime_usec
    belongs_to :identity_replaced_by_device, __MODULE__
  end

  def changeset(device, attrs) do
    device
    |> cast(attrs, [
      :id,
      :user_id,
      :name,
      :device_type,
      :hybrid_encryption_public_key_material,
      :hybrid_signing_public_key_material,
      :approval_signature,
      :approval_signature_surface,
      :approval_proof,
      :approval_delivery_commitments,
      :approval_delivery_artifacts,
      :key_checkpoint_sequence,
      :key_checkpoint_hash,
      :client_nonce,
      :last_seen_at,
      :revoked_at,
      :identity_wipe_required_at,
      :identity_replaced_by_device_id
    ])
    |> validate_required([
      :id,
      :user_id,
      :name,
      :device_type,
      :hybrid_encryption_public_key_material,
      :hybrid_signing_public_key_material,
      :approval_signature,
      :approval_signature_surface,
      :approval_proof,
      :client_nonce,
      :last_seen_at
    ])
    |> validate_inclusion(:approval_signature_surface, [
      "genesis_device_bootstrap",
      "device_approval",
      "recovery_device_approval"
    ])
    |> validate_hybrid_signature_shape(:approval_signature)
    |> validate_inclusion(:device_type, ~w(browser desktop mobile))
    |> validate_hybrid_encryption_material()
    |> validate_hybrid_signing_material()
    |> validate_required([:encryption_key_id, :signing_key_id])
    |> validate_approval_proof()
    |> put_key_checkpoint_from_approval_proof()
    |> validate_required([:key_checkpoint_sequence, :key_checkpoint_hash])
    |> validate_key_checkpoint_hash()
    |> validate_byte_size(:client_nonce, 16)
    |> unique_constraint(:signing_key_id)
    |> unique_constraint(:encryption_key_id)
  end

  def guest_changeset(device, attrs) do
    device
    |> cast(attrs, [
      :id,
      :user_id,
      :name,
      :device_type,
      :hybrid_encryption_public_key_material,
      :hybrid_signing_public_key_material,
      :key_checkpoint_sequence,
      :key_checkpoint_hash,
      :client_nonce,
      :last_seen_at,
      :revoked_at,
      :identity_wipe_required_at,
      :identity_replaced_by_device_id
    ])
    |> validate_required([
      :id,
      :user_id,
      :name,
      :device_type,
      :hybrid_encryption_public_key_material,
      :hybrid_signing_public_key_material,
      :key_checkpoint_sequence,
      :key_checkpoint_hash,
      :client_nonce,
      :last_seen_at
    ])
    |> validate_inclusion(:device_type, ~w(browser desktop mobile))
    |> validate_hybrid_encryption_material()
    |> validate_hybrid_signing_material()
    |> validate_required([:encryption_key_id, :signing_key_id])
    |> validate_key_checkpoint_hash()
    |> validate_byte_size(:client_nonce, 16)
    |> unique_constraint(:signing_key_id)
    |> unique_constraint(:encryption_key_id)
  end

  defp put_key_checkpoint_from_approval_proof(changeset) do
    case get_field(changeset, :approval_proof) do
      %{
        "target_key_checkpoint_sequence" => sequence,
        "target_key_checkpoint_hash" => hash
      } ->
        changeset
        |> put_change(:key_checkpoint_sequence, sequence)
        |> put_change(:key_checkpoint_hash, hash)

      _ ->
        changeset
    end
  end

  defp validate_key_checkpoint_hash(changeset) do
    validate_change(changeset, :key_checkpoint_hash, fn field, value ->
      try do
        Hash.assert_blake3_base64url!(value)
        []
      rescue
        ArgumentError -> [{field, "is invalid"}]
      end
    end)
  end

  defp validate_hybrid_encryption_material(changeset) do
    changeset
    |> put_encryption_key_id()
    |> validate_change(:hybrid_encryption_public_key_material, fn field, material ->
      device_id = get_field(changeset, :id)

      try do
        with :ok <- HybridEncryptionMaterial.assert_public_key_material!(material),
             true <- material["owner_kind"] == "device",
             true <- is_binary(device_id),
             true <- material["owner_id"] == device_id do
          []
        else
          _ -> [{field, "must be valid device hybrid encryption public key material"}]
        end
      rescue
        ArgumentError -> [{field, "must be valid device hybrid encryption public key material"}]
      end
    end)
  end

  defp put_encryption_key_id(changeset) do
    case get_change(changeset, :hybrid_encryption_public_key_material) do
      material when is_map(material) ->
        put_change(
          changeset,
          :encryption_key_id,
          HybridEncryptionMaterial.compute_key_id!(material)
        )

      _ ->
        changeset
    end
  rescue
    ArgumentError -> changeset
  end

  defp validate_approval_proof(changeset) do
    validate_change(changeset, :approval_proof, fn field, proof ->
      purpose = get_field(changeset, :approval_signature_surface)

      if valid_approval_proof?(changeset, purpose, proof),
        do: [],
        else: [{field, "must be the exact device approval transcript"}]
    end)
  end

  defp valid_approval_proof?(changeset, "genesis_device_bootstrap", proof) when is_map(proof) do
    transcript =
      Signature.build_genesis_device_bootstrap_transcript!(%{
        registration_id: proof["surface_details"]["registration_id"],
        compound_intent_id: proof["surface_details"]["compound_intent_id"],
        mutation_id: proof["surface_details"]["mutation_id"],
        genesis_compound_context_hash: proof["surface_details"]["genesis_compound_context_hash"],
        user_id: get_field(changeset, :user_id),
        workspace_id: proof["surface_details"]["workspace_id"],
        owner_role_id: proof["surface_details"]["owner_role_id"],
        device_id: get_field(changeset, :id),
        device_public_material: get_field(changeset, :hybrid_signing_public_key_material),
        device_hybrid_encryption_public_key_material:
          get_field(changeset, :hybrid_encryption_public_key_material),
        client_nonce: encoded_field!(changeset, :client_nonce),
        registration_challenge_hash: proof["surface_details"]["registration_challenge_hash"],
        identity_signing_key_id: proof["approving_signing_key_id"],
        user_identity_public_key_hash: proof["surface_details"]["user_identity_public_key_hash"],
        user_device_key_added_event_hash:
          proof["surface_details"]["user_device_key_added_event_hash"],
        workspace_device_key_added_event_hash:
          proof["surface_details"]["workspace_device_key_added_event_hash"],
        owner_member_added_event_hash: proof["surface_details"]["owner_member_added_event_hash"],
        workspace_member_envelope_commitment_hash:
          proof["surface_details"]["workspace_member_envelope_commitment_hash"],
        user_audit_checkpoint: proof["surface_details"]["user_audit_checkpoint"],
        workspace_audit_checkpoint: proof["surface_details"]["workspace_audit_checkpoint"]
      })

    details = proof["surface_details"]

    exact_keys?(proof, @approval_proof_keys) and
      exact_keys?(details, @genesis_details_keys) and
      details["kind"] == "genesis_device_bootstrap" and
      valid_common_target_proof?(changeset, proof) and
      valid_proof_wrapper?(proof, "genesis_device_bootstrap", transcript)
  rescue
    ArgumentError -> false
  end

  defp valid_approval_proof?(changeset, "device_approval", proof) when is_map(proof) do
    with details when is_map(details) <- proof["surface_details"],
         true <- exact_keys?(proof, @approval_proof_keys),
         true <- exact_keys?(details, @device_approval_details_keys),
         true <- details["kind"] == "device_approval",
         true <- valid_device_approval_commitments?(changeset, details),
         true <- proof["approving_owner_kind"] == "device",
         true <- details["pending_registration_id"] == get_field(changeset, :id),
         true <- valid_common_target_proof?(changeset, proof),
         transcript <-
           Signature.build_device_approval_transcript!(
             get_field(changeset, :user_id),
             proof["approving_owner_id"],
             get_field(changeset, :id),
             get_field(changeset, :hybrid_signing_public_key_material),
             get_field(changeset, :hybrid_encryption_public_key_material),
             encoded_field!(changeset, :client_nonce),
             %{
               "approved_device_registration_sas_hash" =>
                 details["approved_device_registration_sas_hash"],
               "approving_device_key_directory_proof_hash" =>
                 details["approving_device_key_directory_proof_hash"],
               "approving_key_checkpoint_hash" => proof["approving_key_checkpoint_hash"],
               "approving_key_checkpoint_sequence" => proof["approving_key_checkpoint_sequence"],
               "approving_owner_id" => proof["approving_owner_id"],
               "approving_owner_kind" => proof["approving_owner_kind"],
               "approving_signing_key_id" => proof["approving_signing_key_id"],
               "device_approval_kek_initial_delivery_commitments" =>
                 details["device_approval_kek_initial_delivery_commitments"],
               "pending_registration_challenge_hash" =>
                 details["pending_registration_challenge_hash"],
               "pending_registration_id" => details["pending_registration_id"],
               "target_device_client_nonce_hash" => proof["target_device_client_nonce_hash"],
               "target_device_encryption_key_id" => proof["target_device_encryption_key_id"],
               "target_device_hybrid_encryption_public_key_material_hash" =>
                 proof["target_device_hybrid_encryption_public_key_material_hash"],
               "target_device_hybrid_signing_public_key_material_hash" =>
                 proof["target_device_hybrid_signing_public_key_material_hash"],
               "target_device_id" => proof["target_device_id"],
               "target_device_signing_key_id" => proof["target_device_signing_key_id"],
               "target_key_checkpoint_hash" => proof["target_key_checkpoint_hash"],
               "target_key_checkpoint_sequence" => proof["target_key_checkpoint_sequence"],
               "trust_transfer_delivery_commitment" =>
                 details["trust_transfer_delivery_commitment"],
               "umk_distribution_delivery_commitment" =>
                 details["umk_distribution_delivery_commitment"]
             }
           ) do
      valid_proof_wrapper?(proof, "device_approval", transcript)
    else
      _ -> false
    end
  rescue
    ArgumentError -> false
  end

  defp valid_approval_proof?(changeset, "recovery_device_approval", proof) when is_map(proof) do
    with details when is_map(details) <- proof["surface_details"],
         true <- exact_keys?(proof, @approval_proof_keys),
         true <- exact_keys?(details, @recovery_approval_details_keys),
         true <- details["kind"] == "recovery_device_approval",
         true <- details["pending_registration_id"] == get_field(changeset, :id),
         true <- valid_common_target_proof?(changeset, proof),
         true <- valid_recovery_pending_registration_binding?(changeset, proof, details),
         transcript <-
           Signature.build_recovery_device_approval_transcript!(%{
             user_id: get_field(changeset, :user_id),
             approving_signing_key_id: proof["approving_signing_key_id"],
             approving_key_checkpoint_sequence: proof["approving_key_checkpoint_sequence"],
             approving_key_checkpoint_hash: proof["approving_key_checkpoint_hash"],
             pending_registration_id: details["pending_registration_id"],
             pending_registration_challenge_hash: details["pending_registration_challenge_hash"],
             recovery_session_transcript_hash: details["recovery_session_transcript_hash"],
             recovery_capability_hash: details["recovery_capability_hash"],
             pending_registration_binding_hash: details["pending_registration_binding_hash"],
             approved_device_id: get_field(changeset, :id),
             approved_device_public_material:
               get_field(changeset, :hybrid_signing_public_key_material),
             approved_device_hybrid_encryption_public_key_material:
               get_field(changeset, :hybrid_encryption_public_key_material),
             client_nonce: encoded_field!(changeset, :client_nonce),
             target_key_checkpoint_sequence: proof["target_key_checkpoint_sequence"],
             target_key_checkpoint_hash: proof["target_key_checkpoint_hash"]
           }) do
      valid_proof_wrapper?(proof, "recovery_device_approval", transcript)
    else
      _ -> false
    end
  rescue
    ArgumentError -> false
  end

  defp valid_approval_proof?(_changeset, _purpose, _proof), do: false

  defp valid_proof_wrapper?(proof, approval_signature_surface, transcript) do
    proof["protocol"] == "refmd.device-approval-proof" and
      proof["version"] == 1 and
      proof["approval_signature_surface"] == approval_signature_surface and
      proof["approval_transcript_hash"] == Hash.blake3_base64url(JCS.canonical_bytes!(transcript)) and
      proof["approval_transcript_owner"] == transcript["transcript_owner"] and
      proof["approval_surface_id"] == transcript["surface_id"] and
      proof["approval_surface_variant"] == transcript["surface_variant"] and
      proof["approving_owner_kind"] == transcript["owner_kind"] and
      proof["approving_owner_id"] == transcript["owner_id"]
  end

  defp valid_common_target_proof?(changeset, proof) do
    signing_material = get_field(changeset, :hybrid_signing_public_key_material)
    encryption_material = get_field(changeset, :hybrid_encryption_public_key_material)

    proof["target_device_id"] == get_field(changeset, :id) and
      proof["target_device_signing_key_id"] == get_field(changeset, :signing_key_id) and
      proof["target_device_encryption_key_id"] == get_field(changeset, :encryption_key_id) and
      proof["target_device_client_nonce_hash"] ==
        Hash.blake3_base64url(get_field(changeset, :client_nonce)) and
      proof["target_device_hybrid_signing_public_key_material_hash"] ==
        Hash.blake3_base64url(JCS.canonical_bytes!(signing_material)) and
      proof["target_device_hybrid_encryption_public_key_material_hash"] ==
        Hash.blake3_base64url(JCS.canonical_bytes!(encryption_material))
  end

  defp valid_recovery_pending_registration_binding?(changeset, proof, details) do
    signing_material = get_field(changeset, :hybrid_signing_public_key_material)
    encryption_material = get_field(changeset, :hybrid_encryption_public_key_material)

    binding_hash =
      Hash.blake3_base64url(
        JCS.canonical_bytes!(%{
          "protocol" => "refmd.pending-registration-binding",
          "version" => 1,
          "user_id" => get_field(changeset, :user_id),
          "pending_registration_id" => details["pending_registration_id"],
          "pending_registration_challenge_hash" => details["pending_registration_challenge_hash"],
          "target_device_id" => get_field(changeset, :id),
          "target_device_signing_key_id" => Signature.compute_signing_key_id!(signing_material),
          "target_device_hybrid_signing_public_key_material_hash" =>
            Hash.blake3_base64url(JCS.canonical_bytes!(signing_material)),
          "target_device_hybrid_encryption_public_key_material_hash" =>
            Hash.blake3_base64url(JCS.canonical_bytes!(encryption_material)),
          "target_device_encryption_key_id" =>
            HybridEncryptionMaterial.compute_key_id!(encryption_material),
          "target_device_client_nonce_hash" =>
            Hash.blake3_base64url(get_field(changeset, :client_nonce)),
          "target_key_checkpoint_sequence" => proof["target_key_checkpoint_sequence"],
          "target_key_checkpoint_hash" => proof["target_key_checkpoint_hash"]
        })
      )

    details["pending_registration_binding_hash"] == binding_hash
  end

  defp valid_device_approval_commitments?(changeset, details) do
    valid_commitment?(
      details["trust_transfer_delivery_commitment"],
      @trust_transfer_commitment_keys,
      "trust_transfer"
    ) and
      valid_commitment?(
        details["umk_distribution_delivery_commitment"],
        @umk_distribution_commitment_keys,
        "umk_distribution"
      ) and
      valid_device_approval_kek_commitments?(
        details["device_approval_kek_initial_delivery_commitments"]
      ) and
      approval_delivery_artifacts_match?(changeset, details)
  end

  defp valid_device_approval_kek_commitments?(commitments) when is_list(commitments) do
    commitment_keys =
      Enum.map(commitments, fn commitment ->
        {
          commitment["workspace_id"],
          commitment["key_version"],
          commitment["delivery_id"]
        }
      end)

    Enum.all?(commitments, fn commitment ->
      valid_commitment?(
        commitment,
        @device_approval_kek_commitment_keys,
        "device_approval_kek_initial"
      )
    end) and
      commitments == Enum.sort_by(commitments, &JCS.canonical_bytes!/1) and
      Enum.uniq(commitment_keys) == commitment_keys
  rescue
    ArgumentError -> false
  end

  defp valid_device_approval_kek_commitments?(_), do: false

  defp approval_delivery_artifacts_match?(changeset, details) do
    artifacts = get_field(changeset, :approval_delivery_artifacts)

    is_map(artifacts) and
      delivery_record_hash_matches?(
        details["umk_distribution_delivery_commitment"],
        artifacts["umk_distribution_initial_delivery"]
      ) and
      delivery_record_hash_matches?(
        details["trust_transfer_delivery_commitment"],
        artifacts["trust_transfer_initial_delivery"]
      ) and
      kek_delivery_record_hashes_match?(
        details["device_approval_kek_initial_delivery_commitments"],
        artifacts["device_approval_kek_initial_deliveries"]
      )
  end

  defp delivery_record_hash_matches?(commitment, artifact)
       when is_map(commitment) and is_map(artifact) do
    delivery = artifact["initial_key_delivery"]
    metadata = if is_map(delivery), do: delivery["metadata"]
    aead = if is_map(delivery), do: delivery["aead"]

    is_map(metadata) and is_map(aead) and
      commitment["delivery_record_hash"] ==
        Hash.blake3_base64url(
          JCS.canonical_bytes!(%{
            "metadata" => Map.delete(metadata, "key_confirmation_hash"),
            "aead" => aead
          })
        )
  rescue
    ArgumentError -> false
  end

  defp delivery_record_hash_matches?(_, _), do: false

  defp kek_delivery_record_hashes_match?(commitments, artifacts)
       when is_list(commitments) and is_map(artifacts) do
    expected_workspace_ids =
      commitments
      |> Enum.map(& &1["workspace_id"])
      |> Enum.sort()

    Map.keys(artifacts) |> Enum.sort() == expected_workspace_ids and
      Enum.all?(commitments, fn commitment ->
        is_map(commitment) and
          is_binary(commitment["workspace_id"]) and
          delivery_record_hash_matches?(commitment, artifacts[commitment["workspace_id"]])
      end)
  end

  defp kek_delivery_record_hashes_match?(_, _), do: false

  defp valid_commitment?(commitment, keys, purpose) when is_map(commitment) do
    exact_keys?(commitment, keys) and
      commitment["purpose"] == purpose and
      commitment["variant"] == purpose and
      Enum.all?(
        keys,
        &(is_binary(commitment[&1]) or (&1 == "key_version" and is_integer(commitment[&1])))
      )
  end

  defp valid_commitment?(_, _, _), do: false

  defp exact_keys?(map, expected) when is_map(map) do
    MapSet.equal?(MapSet.new(Map.keys(map)), MapSet.new(expected))
  end

  defp exact_keys?(_, _), do: false

  defp encoded_field!(changeset, field) do
    changeset
    |> get_field(field)
    |> Encoding.encode_base64url()
  end

  defp validate_hybrid_signing_material(changeset) do
    validate_change(changeset, :hybrid_signing_public_key_material, fn field, material ->
      device_id = get_field(changeset, :id)

      try do
        with :ok <- Signature.assert_public_key_material!(material),
             true <- material["owner_kind"] == "device",
             true <- is_binary(device_id),
             true <- material["owner_id"] == device_id do
          []
        else
          _ -> [{field, "must be valid device hybrid signing public key material"}]
        end
      rescue
        ArgumentError -> [{field, "must be valid device hybrid signing public key material"}]
      end
    end)
    |> put_signing_key_id()
  end

  defp put_signing_key_id(changeset) do
    case get_change(changeset, :hybrid_signing_public_key_material) do
      material when is_map(material) ->
        put_change(changeset, :signing_key_id, Signature.compute_signing_key_id!(material))

      _ ->
        changeset
    end
  rescue
    ArgumentError -> changeset
  end

  defp validate_byte_size(changeset, field, expected) do
    validate_change(changeset, field, fn _, value ->
      if byte_size(value) == expected,
        do: [],
        else: [{field, "must be exactly #{expected} bytes"}]
    end)
  end

  defp validate_hybrid_signature_shape(changeset, field) do
    validate_change(changeset, field, fn ^field, signature ->
      try do
        Signature.assert_hybrid_signature_shape!(signature)
        []
      rescue
        ArgumentError -> [{field, "must be an exact hybrid signature object"}]
      end
    end)
  end
end
