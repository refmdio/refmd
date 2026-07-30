defmodule RefMD.Auth.Genesis.Prepare do
  @moduledoc false

  alias RefMD.Auth.PendingAccountGenesis
  alias RefMD.Crypto.{Encoding, Hash, HybridEncryptionMaterial, JCS, Signature, Suite}
  alias RefMD.Encryption.RecoverableIdentitySecretRecord

  @wrap_suite_id "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65"
  @prepare_keys ~w(
    client_nonce device_encryption_key_id device_hybrid_encryption_public_key_material
    device_hybrid_signing_public_key_material device_id device_signing_key_id device_type
    encrypted_umk encrypted_umk_nonce identity_encryption_key_id
    identity_hybrid_encryption_public_key_material identity_hybrid_signing_public_key_material
    identity_signing_key_id initial_suite_policy name owner_role_id recoverable_identity_secret_record
    recovery_authorization registration_challenge registration_id user_id workspace_id
    workspace_member_envelope_precommit
  )
  @precommit_keys ~w(
    authorization_key_directory_checkpoint_hash
    authorization_key_directory_checkpoint_sequence kek_version protocol target_identity_encryption_key_id
    target_identity_key_material_hash target_user_id version workspace_id wrap
  )
  @wrap_keys ~w(event_scope hpke protocol protocol_version purpose recipient resource sender suite_id suite_rank)
  @sender_keys ~w(device_id key_checkpoint_hash key_checkpoint_sequence key_scope_id key_scope_kind signer_kind signing_key_id user_id)
  @recipient_keys ~w(encryption_key_id key_checkpoint_hash key_checkpoint_sequence key_scope_id key_scope_kind recipient_kind user_id)
  @hpke_keys ~w(aead_id ciphertext enc kdf_id kem_id mode)

  def validate!(%PendingAccountGenesis{} = genesis, params) when is_map(params) do
    exact_keys!(params, @prepare_keys)

    user_id = genesis.reserved_user_id
    workspace_id = genesis.reserved_workspace_id
    owner_role_id = genesis.reserved_workspace_role_ids["owner"]

    literal!(params["registration_id"], genesis.registration_id)
    literal!(params["user_id"], user_id)
    literal!(params["workspace_id"], workspace_id)
    literal!(params["owner_role_id"], owner_role_id)
    non_empty_string!(params["name"])
    literal_in!(params["device_type"], ~w(browser desktop mobile))
    uuid_v4!(params["device_id"])
    decode!(params["registration_challenge"], 32)
    decode_non_empty!(params["encrypted_umk"])
    decode!(params["encrypted_umk_nonce"], 24)
    decode!(params["client_nonce"], 16)

    identity_signing = params["identity_hybrid_signing_public_key_material"]
    identity_encryption = params["identity_hybrid_encryption_public_key_material"]
    device_signing = params["device_hybrid_signing_public_key_material"]
    device_encryption = params["device_hybrid_encryption_public_key_material"]

    signing_key_id = signing_material!(identity_signing, "identity", user_id)
    encryption_key_id = encryption_material!(identity_encryption, "identity", user_id)
    device_signing_key_id = signing_material!(device_signing, "device", params["device_id"])

    device_encryption_key_id =
      encryption_material!(device_encryption, "device", params["device_id"])

    literal!(params["identity_signing_key_id"], signing_key_id)
    literal!(params["identity_encryption_key_id"], encryption_key_id)
    literal!(params["device_signing_key_id"], device_signing_key_id)
    literal!(params["device_encryption_key_id"], device_encryption_key_id)
    validate_suite_policy!(params["initial_suite_policy"])

    secret_record =
      RecoverableIdentitySecretRecord.validate!(params["recoverable_identity_secret_record"], %{
        user_id: params["user_id"],
        signing_key_id: params["identity_signing_key_id"],
        encryption_key_id: params["identity_encryption_key_id"]
      })

    recovery = validate_recovery_authorization!(params["recovery_authorization"], user_id)

    envelope =
      validate_member_envelope_precommit!(
        params["workspace_member_envelope_precommit"],
        params,
        identity_encryption
      )

    %{
      params: params,
      secret_record: secret_record,
      recovery_authorization: recovery,
      member_envelope: envelope,
      identity_signing_key_id: signing_key_id,
      identity_encryption_key_id: encryption_key_id,
      device_signing_key_id: device_signing_key_id,
      device_encryption_key_id: device_encryption_key_id,
      prepare_request_hash: hash(params)
    }
  end

  def validate!(_, _), do: raise(ArgumentError, "genesis_prepare_invalid")

  defp validate_recovery_authorization!(recovery, user_id) do
    exact_keys!(
      recovery,
      ~w(recovery_authorization_key_id recovery_authorization_public_material recovery_encrypted_umk recovery_nonce)
    )

    decode_non_empty!(recovery["recovery_encrypted_umk"])
    decode!(recovery["recovery_nonce"], 24)

    key_id =
      signing_material!(
        recovery["recovery_authorization_public_material"],
        "recovery_authorization",
        user_id
      )

    literal!(recovery["recovery_authorization_key_id"], key_id)
    recovery
  end

  def validate_member_envelope_precommit!(precommit, params, identity_encryption) do
    exact_keys!(precommit, @precommit_keys)
    literal!(precommit["protocol"], "refmd.workspace-member-envelope")
    literal!(precommit["version"], 1)
    literal!(precommit["workspace_id"], params["workspace_id"])
    literal!(precommit["target_user_id"], params["user_id"])
    literal!(precommit["kek_version"], 1)
    literal!(precommit["target_identity_encryption_key_id"], params["identity_encryption_key_id"])

    identity_material_hash = hash(identity_encryption)
    literal!(precommit["target_identity_key_material_hash"], identity_material_hash)
    literal!(precommit["authorization_key_directory_checkpoint_sequence"], 1)
    literal!(precommit["authorization_key_directory_checkpoint_hash"], "GENESIS")

    wrap = validate_genesis_wrap!(precommit["wrap"], params)

    commitment = %{
      "protocol" => "refmd.workspace-member-envelope-commitment",
      "version" => 1,
      "workspace_id" => params["workspace_id"],
      "target_user_id" => params["user_id"],
      "kek_version" => 1,
      "target_identity_encryption_key_id" => params["identity_encryption_key_id"],
      "target_identity_key_material_hash" => identity_material_hash,
      "authorization_key_directory_checkpoint_sequence" => 1,
      "authorization_key_directory_checkpoint_hash" => "GENESIS",
      "wrap_resource_hash" => wrap.resource_hash,
      "sender_signing_key_id" => params["device_signing_key_id"],
      "recipient_encryption_key_id" => params["identity_encryption_key_id"],
      "hpke_enc_hash" => wrap.hpke_enc_hash,
      "ciphertext_hash" => wrap.ciphertext_hash
    }

    %{
      precommit: precommit,
      commitment: commitment,
      commitment_hash: hash(commitment),
      wrap_body: wrap.wrap_body,
      wrap_body_hash: hash(wrap.wrap_body),
      resource_hash: wrap.resource_hash,
      hpke_info_hash: wrap.hpke_info_hash,
      aad_hash: wrap.aad_hash,
      ciphertext_hash: wrap.ciphertext_hash
    }
  end

  defp validate_genesis_wrap!(wrap, params) do
    exact_keys!(wrap, @wrap_keys)
    literal!(wrap["protocol"], "refmd.signed-pq-hybrid-wrap")
    literal!(wrap["protocol_version"], 1)
    literal!(wrap["suite_id"], @wrap_suite_id)
    literal!(wrap["suite_rank"], 1000)
    literal!(wrap["purpose"], "workspace_member_kek_wrap")

    resource = wrap["resource"]
    exact_keys!(resource, ~w(kek_version target_user_id workspace_id))
    literal!(resource["workspace_id"], params["workspace_id"])
    literal!(resource["target_user_id"], params["user_id"])
    literal!(resource["kek_version"], 1)

    sender = wrap["sender"]
    exact_keys!(sender, @sender_keys)
    literal!(sender["signer_kind"], "device")
    literal!(sender["user_id"], params["user_id"])
    literal!(sender["device_id"], params["device_id"])
    literal!(sender["signing_key_id"], params["device_signing_key_id"])
    assert_genesis_key_scope!(sender, params["workspace_id"])

    recipient = wrap["recipient"]
    exact_keys!(recipient, @recipient_keys)
    literal!(recipient["recipient_kind"], "user_identity")
    literal!(recipient["user_id"], params["user_id"])
    literal!(recipient["encryption_key_id"], params["identity_encryption_key_id"])
    assert_genesis_key_scope!(recipient, params["workspace_id"])

    event_scope = wrap["event_scope"]
    exact_keys!(event_scope, ~w(scope_id scope_kind))
    literal!(event_scope["scope_kind"], "workspace")
    literal!(event_scope["scope_id"], params["workspace_id"])

    hpke = wrap["hpke"]
    exact_keys!(hpke, @hpke_keys)
    literal!(hpke["mode"], "base")
    literal!(hpke["kem_id"], 25_722)
    literal!(hpke["kdf_id"], 1)
    literal!(hpke["aead_id"], 3)
    hpke_enc = decode!(hpke["enc"], 1120)
    ciphertext = decode_non_empty!(hpke["ciphertext"])

    resource_hash = hash(resource)
    info = hpke_info(wrap)
    aad = hpke_aad(wrap, Map.delete(hpke, "ciphertext"))
    hpke_info_hash = hash(info)
    aad_hash = hash(aad)

    wrap_body = %{
      "label" => "RefMD PQ wrap body v1",
      "protocol" => wrap["protocol"],
      "version" => 1,
      "suite_id" => wrap["suite_id"],
      "suite_rank" => wrap["suite_rank"],
      "purpose" => wrap["purpose"],
      "resource" => resource,
      "sender" => sender,
      "recipient" => recipient,
      "event_scope" => event_scope,
      "hpke" => hpke,
      "hpke_info_hash" => hpke_info_hash,
      "aad_hash" => aad_hash
    }

    %{
      wrap_body: wrap_body,
      resource_hash: resource_hash,
      hpke_info_hash: hpke_info_hash,
      aad_hash: aad_hash,
      hpke_enc_hash: hash_bytes(hpke_enc),
      ciphertext_hash: hash_bytes(ciphertext)
    }
  end

  defp hpke_info(wrap) do
    %{
      "label" => "RefMD HPKE info v1",
      "protocol" => wrap["protocol"],
      "protocol_version" => wrap["protocol_version"],
      "suite_id" => wrap["suite_id"],
      "suite_rank" => wrap["suite_rank"],
      "purpose" => wrap["purpose"],
      "resource_hash" => hash(wrap["resource"]),
      "sender_user_id" => wrap["sender"]["user_id"],
      "sender_device_id" => wrap["sender"]["device_id"],
      "sender_signing_key_id" => wrap["sender"]["signing_key_id"],
      "sender_key_scope_kind" => wrap["sender"]["key_scope_kind"],
      "sender_key_scope_id" => wrap["sender"]["key_scope_id"],
      "sender_key_checkpoint_hash" => wrap["sender"]["key_checkpoint_hash"],
      "recipient_kind" => wrap["recipient"]["recipient_kind"],
      "recipient_key_id" => wrap["recipient"]["encryption_key_id"],
      "recipient_key_scope_kind" => wrap["recipient"]["key_scope_kind"],
      "recipient_key_scope_id" => wrap["recipient"]["key_scope_id"],
      "recipient_key_checkpoint_hash" => wrap["recipient"]["key_checkpoint_hash"],
      "event_scope_kind" => wrap["event_scope"]["scope_kind"],
      "event_scope_id" => wrap["event_scope"]["scope_id"]
    }
  end

  defp hpke_aad(wrap, hpke) do
    %{
      "label" => "RefMD PQ wrap AAD v1",
      "protocol" => wrap["protocol"],
      "protocol_version" => wrap["protocol_version"],
      "suite_id" => wrap["suite_id"],
      "suite_rank" => wrap["suite_rank"],
      "purpose" => wrap["purpose"],
      "resource" => wrap["resource"],
      "sender" => wrap["sender"],
      "recipient" => wrap["recipient"],
      "event_scope" => wrap["event_scope"],
      "hpke" => hpke
    }
  end

  defp validate_suite_policy!(policy) do
    exact_keys!(policy, ~w(allowed_suite_ids min_suite_rank suite_policy_version))
    current = Suite.current_suite_policy()
    literal!(policy["suite_policy_version"], current["suite_policy_version"])
    literal!(policy["min_suite_rank"], current["min_suite_rank"])
    literal!(policy["allowed_suite_ids"], current["allowed_suite_ids"])
  end

  defp signing_material!(material, owner_kind, owner_id) do
    key_id = Signature.compute_signing_key_id!(material)
    literal!(material["owner_kind"], owner_kind)
    literal!(material["owner_id"], owner_id)
    key_id
  end

  defp encryption_material!(material, owner_kind, owner_id) do
    key_id = HybridEncryptionMaterial.compute_key_id!(material)
    literal!(material["owner_kind"], owner_kind)
    literal!(material["owner_id"], owner_id)
    key_id
  end

  defp assert_genesis_key_scope!(value, workspace_id) do
    literal!(value["key_scope_kind"], "workspace")
    literal!(value["key_scope_id"], workspace_id)
    literal!(value["key_checkpoint_sequence"], 0)
    literal!(value["key_checkpoint_hash"], "GENESIS")
  end

  defp exact_keys!(value, keys) when is_map(value) do
    if Enum.sort(Map.keys(value)) != Enum.sort(keys),
      do: raise(ArgumentError, "genesis_prepare_keys_invalid")
  end

  defp exact_keys!(_, _), do: raise(ArgumentError, "genesis_prepare_object_invalid")

  defp literal!(value, value), do: :ok
  defp literal!(_, _), do: raise(ArgumentError, "genesis_prepare_value_mismatch")

  defp literal_in!(value, values) do
    if value not in values, do: raise(ArgumentError, "genesis_prepare_value_invalid")
  end

  defp non_empty_string!(value) when is_binary(value) and value != "", do: :ok
  defp non_empty_string!(_), do: raise(ArgumentError, "genesis_prepare_string_invalid")

  defp uuid_v4!(value) when is_binary(value) do
    if not Regex.match?(
         ~r/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
         value
       ),
       do: raise(ArgumentError, "genesis_prepare_uuid_invalid")
  end

  defp uuid_v4!(_), do: raise(ArgumentError, "genesis_prepare_uuid_invalid")

  defp decode!(value, size), do: Encoding.decode_base64url!(value, size)

  defp decode_non_empty!(value) do
    decoded = Encoding.decode_base64url!(value)
    if byte_size(decoded) < 16, do: raise(ArgumentError, "genesis_prepare_ciphertext_invalid")
    decoded
  end

  defp hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()
  defp hash_bytes(value), do: Hash.blake3_base64url(value)
end
