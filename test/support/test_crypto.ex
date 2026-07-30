defmodule RefMD.TestCrypto do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Crypto.{Blake3, Encoding, Hash, HybridEncryptionMaterial, JCS, Signature}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Documents.Document
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.KeyDirectory.{Payload, PinBootstrap}
  alias RefMD.Encryption.Wraps.SignedPQ
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.{AuditChainEvent, CompoundAppend}
  alias RefMD.Sharing.Capability
  alias RefMD.TestCrypto.Native, as: TestCryptoNative
  alias RefMD.Workspaces.AuthorityMutations.{Intent, Prepare}
  alias RefMD.Workspaces.KekRotation.DeletionProofs
  alias RefMDWeb.Http.RrpSessionBinding
  alias RefMDWeb.Http.RrpTranscript

  @protocol_version 1
  @suite_rank 1000
  @suite_id "refmd-v2-hybrid-signature-ed25519-mldsa65"
  @hybrid_encryption_suite_id "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65"
  @hybrid_encryption_public_material_protocol "refmd.hybrid-encryption-key-material"
  @valid_mlkem768_public_key [
                               "olU0gNRviVdLxaSZ5tEoLc4l55SiVd3dNsEdic54pT_EYL-_cuVGqUIitRTewAfHzbpArJBfTv2MMWUj7ReRc8ndUO6RGx9h4hF1WLM7SvbKQpmRtTCPcsYSnk9cHOsj_RNsOZljmFCZsIF0TH_xuLuNMeMCWETvB9mvmFjzEGdWKIPJI0cvzU9F4dmSwlrpO4hXKGQIE5b6QthYPwP4sMJ6Le87QI0ZB8bOlxY8Ct6LlLjIxy4u3dyEcBoznsy13TSFu74S4p8w5SICAiDuMfMRM1Q3EHQ2WzGptv4RQatjW--qj1RAOqZuWOAbRydACEGWytu771rYzmO57kv7ZigthK4KY5kRCuNmzv26DdWtUzUxkzp1sU3OtxNWrhZ6hT10zIl0VR2cvZlC3u5bge3rpfnKt87Hu7gFinxlV19VbansdIbOm7UQzr5kgw6oU6KGoObzvBb3C5WaF7L4ZSUDBg0c-aM28CYX7GJ4KL-VpX-db9uN0icpNI_PqCoNAZcYrDLlcswiDOXNZJbxdySEFTy2-JDhPGDmoiNNzP_RSHEkFBZJHX-5BTkF9YwdkNupdH_ciZ-caPUdnNMHsLf2GkasdU2wYhB4ih_xdwzpfvRd90pPeNuNTtiluKY6gAifU9kaHJSpKJU8rjUmK9EzrnRM5v9eKlNmkX_Jd1o",
                               "hapMnYwwA9Zm4tPFQ3zExwzdcwiZr-_VQ0cX11mjuYrlyZDFBzgobIfdSAIuLrJuL4_TlGB16VBgMiG7zE0nqu0rwDFirXVK1iKcQIThOIHM0FosKICtHg-Bux6u6c4VzdlW39yVa2W6HJ4Of3b84-nEJVnCjD6CW6QQeL4oQDpsT-_o2KIE_nc-hpR5n1VrmV2WyphukMoxEctq-TMkealSCnBMTQwWKsA0-9D-LVyiO7HiqZNvMcTf39TmO5MtWdy3awBAVVuFIIjrzP2YT0TdYYjCmou9uVb9FMbjjfab_rI_ycKKkElcsYoQcpCwSRuftNFM5PwtQQJZSZalt9KcG5_adB-MTUZcdTTh_4u1LlO9xtaf0iYCnVhrDJiRZjWEYfRna8Oc_q_p9Q_gJzWPtnLn-7BR2V-BnVJiNSb8LQT6yNA5pjtfgipK_TLOccO_Gy610R56X4NNGz1rKIwsfrAPzmjyq4971gdbPhrvEElj2WtPvPsXnm70iZmBGtSxqTiqrBBivH08LxzK4qHMv3KK8pvGmQy2UqcilpogWgJYYEj_S2nicZO3R_d2z9R10xLMwy2GEyYM3MJJdW-1yX1k1k1M1BwBIvjPhZjQfaFjCuxScUnIawB2vi37pDdd4prIulfum8M-G6om8ul3MrIAIR6YgEaibrwULJQ",
                               "-Z1lS_zo6vi7efuNB--Hji3i1JVcKSJ4rwKOyNBT0-SHI1NtJnJ0koPg6jX8zrn6dRkg0_xFlrwkh78ejaKsUUJwTST2ARaBfz9RE7mh9PPp7HAjUzFlmH0i6TzOJ1Ytg7i1HRKnQgG9BX_uDW_wcI6zL4nKIB8O9wKyvM9uORa7g8nwQ9QU3-ZUVp8W-RcQav4VtvaTLqcYmM-j-VblWw"
                             ]
                             |> Enum.map(&Base.url_decode64!(&1, padding: false))
                             |> IO.iodata_to_binary()
  @private_material_protocol "refmd.hybrid-signing-private-key-material"
  @public_material_protocol "refmd.hybrid-signing-key-material"
  @signature_protocol "refmd.hybrid-signature"
  @mldsa_context_prefix "RefMD:v2:"
  @signed_pq_wrap_suite_id "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65"
  @max_safe_integer 9_007_199_254_740_991
  @kek_deletion_storage_classes [
    "crypto_worker_state",
    "indexeddb_cache",
    "local_encrypted_key_store",
    "offline_cache",
    "pending_queue"
  ]

  def install_signed_audit_genesis!(scope_kind, scope_id, signer_user_id, opts \\ [])
      when scope_kind in ["user", "workspace"] do
    {variant, owner_kind, owner_id, signer_device_id, event_types, subject_kind} =
      case scope_kind do
        "user" ->
          {"user_identity", "identity", signer_user_id, nil,
           ["user.account.genesis", "user.device.genesis_bootstrapped"], "account"}

        "workspace" ->
          device_id = Keyword.get(opts, :signer_device_id, Ecto.UUID.generate())
          {"workspace_device", "device", device_id, device_id, ["workspace.genesis"], "workspace"}
      end

    private_material = hybrid_signing_private_key_material(owner_kind, owner_id)
    public_material = hybrid_signing_public_key_material(private_material)

    attrs =
      Enum.map(event_types, fn event_type ->
        test_audit_genesis_attrs(
          scope_kind,
          scope_id,
          signer_user_id,
          signer_device_id,
          owner_kind,
          subject_kind,
          event_type
        )
      end)

    event_hash =
      attrs
      |> Enum.with_index(1)
      |> Enum.reduce("GENESIS", fn {event_attrs, sequence}, previous_hash ->
        %{
          event_id: event_attrs.event_id,
          chain_scope_kind: scope_kind,
          chain_scope_id: scope_id,
          sequence: sequence,
          previous_event_hash: previous_hash,
          event_type: event_attrs.type,
          event_body: event_attrs.event_body
        }
        |> AuditChainEvent.build!()
        |> AuditChainEvent.hash!()
      end)

    event_type = List.last(event_types)
    sequence = length(event_types)

    payload =
      %{
        "protocol" => "refmd.signed-audit-checkpoint",
        "version" => 1,
        "chain_scope_kind" => scope_kind,
        "chain_scope_id" => scope_id,
        "sequence" => sequence,
        "event_hash" => event_hash,
        "signer_user_id" => signer_user_id,
        "signing_key_id" => Signature.compute_signing_key_id!(public_material),
        "authorization_checkpoint_scope_kind" => scope_kind,
        "authorization_checkpoint_scope_id" => scope_id,
        "authorization_checkpoint_sequence" => 0,
        "authorization_checkpoint_hash" => "GENESIS",
        "covered_event_class" => "authority",
        "covered_event_type" => event_type
      }
      |> then(fn payload ->
        if signer_device_id,
          do: Map.put(payload, "signer_device_id", signer_device_id),
          else: payload
      end)

    transcript = Audit.build_audit_checkpoint_transcript!(variant, owner_kind, owner_id, payload)

    envelope = %{
      "payload" => payload,
      "signature" =>
        Signature.__test_sign_hybrid_signature__(
          "audit_checkpoint",
          transcript,
          private_material,
          public_material
        ),
      "checkpoint_hash" => Audit.checkpoint_hash!(variant, payload)
    }

    authority = %{
      chain_scope_kind: scope_kind,
      chain_scope_id: scope_id,
      signer_user_id: signer_user_id,
      signer_device_id: signer_device_id,
      public_key_material: public_material
    }

    {:ok, result} =
      Security.record_signed_audit_events(attrs, envelope, [],
        genesis_candidate_authority: authority
      )

    result
  end

  def workspace_authority_authorization!(intent, actor_private_material, command) do
    [scope] = intent["scopes"]
    [audit_event] = scope["candidate_events"]
    [first_effect | _] = scope["candidate_key_directory_effects"]
    actor = first_effect["event_payload"]["actor"]
    audit_actor = audit_event["event_body"]["actor"]
    public_material = hybrid_signing_public_key_material(actor_private_material)

    prepared =
      Prepare.validate!(
        audit_actor["user_id"],
        audit_actor["device_id"],
        audit_event["event_type"],
        command
      )

    audit_payload =
      Intent.audit_checkpoint_payload(prepared, audit_event)

    audit_transcript =
      Audit.build_audit_checkpoint_transcript!(
        "workspace_device",
        "device",
        actor["device_id"],
        audit_payload
      )

    audit_signature =
      Signature.__test_sign_hybrid_signature__(
        "audit_checkpoint",
        audit_transcript,
        actor_private_material,
        public_material
      )

    effect_authorizations =
      Enum.map(scope["effect_signature_requirements"], fn requirement ->
        transcript = workspace_authority_effect_transcript(requirement, scope, actor, prepared)

        signature =
          Signature.__test_sign_hybrid_signature__(
            requirement["signing_purpose"],
            transcript,
            actor_private_material,
            public_material
          )

        requirement
        |> Map.take(~w(
          authorization_kind requirement_order signer_key_id signing_purpose subject_hash
          surface_variant
        ))
        |> Map.merge(%{"signature" => signature, "approval_proof" => "NONE"})
      end)

    %{
      "protocol" => "refmd.audit.compound-append-authorization",
      "version" => 1,
      "compound_intent_id" => intent["compound_intent_id"],
      "mutation_id" => intent["mutation_id"],
      "intent_hash" => CompoundAppend.hash(intent),
      "scope_signatures" => [
        %{
          "chain_scope_kind" => "workspace",
          "chain_scope_id" => scope["chain_scope_id"],
          "checkpoint_hash" => scope["checkpoint_payload_hash"],
          "checkpoint_variant" => "workspace_device",
          "signature" => audit_signature
        }
      ],
      "effect_authorizations" => effect_authorizations
    }
  end

  defp workspace_authority_effect_transcript(
         %{"authorization_kind" => "key_directory_event"} = requirement,
         scope,
         actor,
         _prepared
       ) do
    payload =
      scope["candidate_key_directory_effects"]
      |> Enum.at(requirement["requirement_order"] - 1)
      |> Map.fetch!("event_payload")

    Signature.build_key_directory_event_transcript!(
      payload["event_type"],
      "device",
      actor["device_id"],
      payload
    )
  end

  defp workspace_authority_effect_transcript(
         %{"authorization_kind" => "key_directory_checkpoint"},
         scope,
         actor,
         prepared
       ) do
    signer = Intent.checkpoint_signer(prepared)

    Signature.build_key_directory_checkpoint_transcript!(
      "workspace_authorized",
      "device",
      actor["device_id"],
      scope["candidate_key_directory_checkpoint_payload"],
      signer
    )
  end

  defp workspace_authority_effect_transcript(
         %{"authorization_kind" => "pq_wrap", "pq_wrap_signing_input" => input},
         _scope,
         actor,
         _prepared
       ) do
    Signature.build_pq_wrap_transcript!(
      actor["device_id"],
      input["actor"],
      input["authority_boundary"],
      input["subject_hashes"]
    )
  end

  defp test_audit_genesis_attrs(
         scope_kind,
         scope_id,
         signer_user_id,
         signer_device_id,
         owner_kind,
         subject_kind,
         event_type
       ) do
    %{
      event_id: Ecto.UUID.generate(),
      class: "authority",
      type: event_type,
      event_body: %{
        "protocol" => "refmd.audit.high-risk-mutation",
        "version" => 1,
        "event_type" => event_type,
        "mutation_id" => Ecto.UUID.generate(),
        "chain_scope_kind" => scope_kind,
        "chain_scope_id" => scope_id,
        "actor" =>
          if(owner_kind == "identity",
            do: %{"kind" => "identity", "user_id" => signer_user_id},
            else: %{
              "kind" => "device",
              "user_id" => signer_user_id,
              "device_id" => signer_device_id
            }
          ),
        "subject_kind" => subject_kind,
        "subject_id" => scope_id,
        "canonical_request_hash" => Hash.blake3_base64url("test-audit-genesis-request"),
        "key_directory_effects_hash" => Hash.blake3_base64url("test-audit-genesis-effects")
      },
      actor: %{
        "user_id" => signer_user_id,
        "device_id" => signer_device_id,
        "session_id" => nil,
        "principal_kind" => "user",
        "principal_id" => signer_user_id
      },
      scope: %{
        "workspace_id" => if(scope_kind == "workspace", do: scope_id, else: nil),
        "document_id" => nil,
        "share_id" => nil
      },
      resource: %{"kind" => scope_kind, "id" => scope_id, "version_hash" => nil},
      action: %{"operation" => event_type, "result" => "completed", "reason_code" => nil},
      sensitivity: Security.empty_sensitivity(),
      correlation: %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => nil
      }
    }
  end

  def recoverable_identity_secret_record(
        user_id,
        signing_key_id,
        encryption_key_id,
        signing_ciphertext,
        signing_nonce,
        encryption_ciphertext,
        encryption_nonce,
        opts \\ []
      ) do
    record_id = Keyword.get(opts, :id, Ecto.UUID.generate())
    identity_key_epoch = Keyword.get(opts, :identity_key_epoch, 1)
    previous_record_hash = Keyword.get(opts, :previous_record_hash, "GENESIS")
    is_current = Keyword.get(opts, :is_current, true)

    storage_scope = %{
      "kind" => "user_identity_key",
      "user_id" => user_id,
      "identity_key_epoch" => identity_key_epoch
    }

    signing_aad_hash =
      context_hash(%{
        "protocol" => "refmd.hybrid-signing-private-key-material-encryption",
        "version" => 1,
        "purpose" => "identity_hybrid_signing_private_key_material",
        "owner_kind" => "identity",
        "owner_id" => user_id,
        "signing_key_id" => signing_key_id,
        "suite_id" => @suite_id,
        "suite_rank" => @suite_rank,
        "storage_scope" => storage_scope
      })

    encryption_aad_hash =
      context_hash(%{
        "protocol" => "refmd.hybrid-encryption-private-key-material-encryption",
        "version" => 1,
        "purpose" => "identity_hybrid_encryption_private_key_material",
        "owner_kind" => "identity",
        "owner_id" => user_id,
        "encryption_key_id" => encryption_key_id,
        "suite_id" => @hybrid_encryption_suite_id,
        "suite_rank" => @suite_rank,
        "storage_scope" => storage_scope
      })

    preimage = %{
      "protocol" => "refmd.recoverable-identity-secret-record",
      "version" => 1,
      "record_id" => record_id,
      "user_id" => user_id,
      "identity_key_epoch" => identity_key_epoch,
      "previous_record_hash" => previous_record_hash,
      "signing_key_id" => signing_key_id,
      "encryption_key_id" => encryption_key_id,
      "signing_ciphertext_hash" => Hash.blake3_base64url(signing_ciphertext),
      "signing_nonce_hash" => Hash.blake3_base64url(signing_nonce),
      "signing_material_aad_hash" => signing_aad_hash,
      "encryption_ciphertext_hash" => Hash.blake3_base64url(encryption_ciphertext),
      "encryption_nonce_hash" => Hash.blake3_base64url(encryption_nonce),
      "encryption_material_aad_hash" => encryption_aad_hash
    }

    %{
      "id" => record_id,
      "user_id" => user_id,
      "identity_key_epoch" => identity_key_epoch,
      "previous_record_hash" => previous_record_hash,
      "encrypted_identity_hybrid_signing_private_key_material" =>
        Encoding.encode_base64url(signing_ciphertext),
      "identity_hybrid_signing_private_key_material_nonce" =>
        Encoding.encode_base64url(signing_nonce),
      "encrypted_identity_hybrid_encryption_private_key_material" =>
        Encoding.encode_base64url(encryption_ciphertext),
      "identity_hybrid_encryption_private_key_material_nonce" =>
        Encoding.encode_base64url(encryption_nonce),
      "signing_key_id" => signing_key_id,
      "encryption_key_id" => encryption_key_id,
      "signing_material_aad_hash" => signing_aad_hash,
      "encryption_material_aad_hash" => encryption_aad_hash,
      "record_hash" => context_hash(preimage),
      "is_current" => is_current
    }
  end

  def hybrid_signing_private_key_material(owner_kind, owner_id) do
    hybrid_signing_private_key_material(owner_kind, owner_id, nil)
  end

  def hybrid_signing_private_key_material(owner_kind, owner_id, label) do
    seed_label =
      case label do
        nil -> "#{owner_kind}:#{owner_id}"
        label when is_binary(label) -> "#{owner_kind}:#{owner_id}:#{label}"
      end

    ed25519_seed = deterministic_bytes("hybrid-signing:#{seed_label}:ed25519", 32)
    {ed25519_public, ed25519_private} = :crypto.generate_key(:eddsa, :ed25519, ed25519_seed)
    mldsa65_seed = deterministic_bytes("hybrid-signing:#{seed_label}:mldsa65", 32)
    {mldsa65_private, mldsa65_public} = mldsa65_keypair(mldsa65_seed)

    %{
      "protocol" => @private_material_protocol,
      "version" => @protocol_version,
      "owner_kind" => owner_kind,
      "owner_id" => owner_id,
      "suite_id" => @suite_id,
      "suite_rank" => @suite_rank,
      "ed25519_private" => Encoding.encode_base64url(ed25519_private),
      "ed25519_public" => Encoding.encode_base64url(ed25519_public),
      "mldsa65_private" => Encoding.encode_base64url(mldsa65_private),
      "mldsa65_public" => Encoding.encode_base64url(mldsa65_public)
    }
  end

  def mldsa65_keypair(seed) when is_binary(seed) do
    TestCryptoNative.keypair_from_seed(seed)
  end

  def mldsa65_sign(message, context, private_key)
      when is_binary(message) and is_binary(context) and is_binary(private_key) do
    TestCryptoNative.sign(message, context, private_key)
  end

  defp deterministic_bytes(label, size)
       when is_binary(label) and is_integer(size) and size >= 0 do
    deterministic_bytes(label, 0, <<>>, size)
  end

  defp deterministic_bytes(_label, _counter, bytes, size) when byte_size(bytes) >= size,
    do: binary_part(bytes, 0, size)

  defp deterministic_bytes(label, counter, bytes, size) do
    deterministic_bytes(
      label,
      counter + 1,
      bytes <> :crypto.hash(:sha256, [label, <<counter::32>>]),
      size
    )
  end

  def hybrid_signing_public_key_material(private_material) do
    %{
      "protocol" => @public_material_protocol,
      "version" => private_material["version"],
      "owner_kind" => private_material["owner_kind"],
      "owner_id" => private_material["owner_id"],
      "suite_id" => private_material["suite_id"],
      "suite_rank" => private_material["suite_rank"],
      "ed25519_public" => private_material["ed25519_public"],
      "mldsa65_public" => private_material["mldsa65_public"]
    }
  end

  def recovery_authorization_material(user_id) do
    private = hybrid_signing_private_key_material("recovery_authorization", user_id)
    public = hybrid_signing_public_key_material(private)

    %{
      private: private,
      public: public,
      public_bytes: JCS.canonical_bytes!(public),
      key_id: Signature.compute_signing_key_id!(public)
    }
  end

  defp ensure_test_identity_material!(user_id, registration_challenge_hash) do
    process_key = {:test_identity_material, user_id}

    material =
      case Process.get(process_key) do
        nil ->
          private = hybrid_signing_private_key_material("identity", user_id)
          public = hybrid_signing_public_key_material(private)
          {x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)
          encryption = hybrid_encryption_public_key_material("identity", user_id, x25519_public)

          %{
            private: private,
            public: public,
            encryption_public: encryption.public,
            x25519_public_key: x25519_public,
            mlkem768_public_key: encryption.mlkem768_public_key
          }
          |> tap(&Process.put(process_key, &1))

        cached ->
          cached
      end

    case RefMD.Encryption.get_user_identity_public_key(user_id) do
      nil ->
        {:ok, _identity} =
          RefMD.Encryption.create_user_identity_public_key(%{
            user_id: user_id,
            hybrid_encryption_public_key_material: material.encryption_public,
            hybrid_signing_public_key_material: material.public,
            pending_registration_challenge_hash: registration_challenge_hash
          })

      _identity ->
        :ok
    end

    material
  end

  def hybrid_device_material(device_id) do
    private = hybrid_signing_private_key_material("device", device_id)
    public = hybrid_signing_public_key_material(private)

    %{
      private: private,
      public: public,
      signing_key_id: Signature.compute_signing_key_id!(public)
    }
  end

  def hybrid_encryption_public_key_material(owner_kind, owner_id, x25519_public_key)
      when is_binary(owner_kind) and is_binary(owner_id) and is_binary(x25519_public_key) do
    mlkem768_public_key = @valid_mlkem768_public_key

    public = %{
      "protocol" => @hybrid_encryption_public_material_protocol,
      "version" => @protocol_version,
      "owner_kind" => owner_kind,
      "owner_id" => owner_id,
      "suite_id" => @hybrid_encryption_suite_id,
      "suite_rank" => @suite_rank,
      "x25519_public" => Encoding.encode_base64url(x25519_public_key),
      "mlkem768_public" => Encoding.encode_base64url(mlkem768_public_key),
      "hybrid_public" => Encoding.encode_base64url(mlkem768_public_key <> x25519_public_key)
    }

    %{
      public: public,
      mlkem768_public_key: mlkem768_public_key,
      encryption_key_id: HybridEncryptionMaterial.compute_key_id!(public)
    }
  end

  def hybrid_share_participant_device_material(device_id) do
    private = hybrid_signing_private_key_material("share_participant_device", device_id)
    public = hybrid_signing_public_key_material(private)

    %{
      private: private,
      public: public,
      signing_key_id: Signature.compute_signing_key_id!(public)
    }
  end

  def share_capability_private_key_material(authorization_secret, share_token_hash)
      when is_binary(authorization_secret) and is_binary(share_token_hash) do
    ed25519_seed =
      hkdf_sha256!(
        authorization_secret,
        "RefMD:v2:share-capability-ed25519-seed",
        32
      )

    {ed25519_public, ed25519_private} = :crypto.generate_key(:eddsa, :ed25519, ed25519_seed)

    mldsa65_seed =
      hkdf_sha256!(
        authorization_secret,
        "RefMD:v2:share-capability-mldsa65-seed",
        32
      )

    {mldsa65_private, mldsa65_public} = mldsa65_keypair(mldsa65_seed)

    %{
      "protocol" => @private_material_protocol,
      "version" => @protocol_version,
      "owner_kind" => "share_capability",
      "owner_id" => share_token_hash,
      "suite_id" => @suite_id,
      "suite_rank" => @suite_rank,
      "ed25519_private" => Encoding.encode_base64url(ed25519_private),
      "ed25519_public" => Encoding.encode_base64url(ed25519_public),
      "mldsa65_private" => Encoding.encode_base64url(mldsa65_private),
      "mldsa65_public" => Encoding.encode_base64url(mldsa65_public)
    }
  end

  defp hkdf_sha256!(input_key_material, info, length) do
    pseudorandom_key = :crypto.mac(:hmac, :sha256, <<0::256>>, input_key_material)
    hkdf_expand_sha256!(pseudorandom_key, info, length)
  end

  defp hkdf_expand_sha256!(pseudorandom_key, info, length) do
    blocks = ceil(length / 32)

    {output, _previous} =
      Enum.reduce(1..blocks, {<<>>, <<>>}, fn counter, {acc, previous} ->
        block = :crypto.mac(:hmac, :sha256, pseudorandom_key, previous <> info <> <<counter>>)
        {acc <> block, block}
      end)

    binary_part(output, 0, length)
  end

  def share_capability_public_key_material(authorization_secret, share_token_hash) do
    authorization_secret
    |> share_capability_private_key_material(share_token_hash)
    |> hybrid_signing_public_key_material()
  end

  def share_capability_public_key_material_for_slug(authorization_secret, share_slug) do
    share_token_hash =
      share_slug
      |> Encoding.decode_base64url!(16)
      |> Blake3.hash_base64url()

    share_capability_public_key_material(authorization_secret, share_token_hash)
  end

  def share_participant_attrs(display_name \\ "Guest User") do
    device_id = Ecto.UUID.generate()
    material = hybrid_share_participant_device_material(device_id)
    {encryption_public_key, _encryption_private_key} = :crypto.generate_key(:ecdh, :x25519)
    principal_id = Ecto.UUID.generate()
    session_id = Ecto.UUID.generate()

    encryption =
      hybrid_encryption_public_key_material(
        "share_participant_device",
        device_id,
        encryption_public_key
      )

    %{
      "display_name" => display_name,
      "share_participant_principal_id" => principal_id,
      "share_participant_device_id" => device_id,
      "share_participant_session_id" => session_id,
      "__share_participant_private_material" => material.private,
      "hybrid_signing_public_key_material" => material.public,
      "hybrid_encryption_public_key_material" => encryption.public
    }
  end

  def share_participant_request_attrs(display_name \\ "Guest User") do
    attrs = share_participant_attrs(display_name)

    encode_share_participant_request_attrs(attrs)
  end

  def share_participant_request_attrs(display_name, created_share, authorization_secret) do
    display_name
    |> share_participant_attrs()
    |> attach_share_participant_device_authorization(created_share, authorization_secret)
    |> encode_share_participant_request_attrs()
  end

  def attach_share_participant_device_authorization(
        attrs,
        created_share,
        authorization_secret \\ open_admission_key()
      ) do
    share =
      created_share
      |> Map.fetch!(:share)
      |> then(&Repo.get!(RefMD.Sharing.Share, &1.id))

    private_material = Map.fetch!(attrs, "__share_participant_private_material")
    signing_public_material = Map.fetch!(attrs, "hybrid_signing_public_key_material")
    encryption_public_material = Map.fetch!(attrs, "hybrid_encryption_public_key_material")

    capability_private_material =
      share_capability_private_key_material(authorization_secret, share.token_hash)

    device_id = Map.fetch!(attrs, "share_participant_device_id")
    principal_id = Map.get(attrs, "share_participant_principal_id") || Ecto.UUID.generate()
    session_id = Map.get(attrs, "share_participant_session_id") || Ecto.UUID.generate()

    capability_transcript =
      Signature.build_share_capability_authorization_transcript!(%{
        token_hash: share.token_hash,
        workspace_pin_bootstrap_hash: share.authenticated_workspace_pin_bootstrap_hash,
        share_id: share.id,
        scope_kind: share.scope,
        scope_id: share.document_id,
        permission: share.permission,
        password_protected: share.password_protected,
        created_event_hash: share.created_event_hash,
        latest_bootstrap_event_hash: share.latest_bootstrap_event_hash,
        capability_context_hash: share.capability_context_hash,
        share_capability_secret_commitment: share.share_capability_secret_commitment,
        password_capability_secret_commitment: share.password_capability_secret_commitment
      })

    capability_signature =
      Signature.__test_sign_hybrid_signature__(
        "share_capability_authorization",
        capability_transcript,
        capability_private_material,
        share.authorization_public_key_material
      )

    transcript =
      Signature.build_share_participant_device_authorization_transcript!(%{
        share_id: share.id,
        share_session_id: session_id,
        share_participant_principal_id: principal_id,
        share_participant_device_id: device_id,
        participant_signing_key_id: Signature.compute_signing_key_id!(signing_public_material),
        participant_encryption_key_id:
          HybridEncryptionMaterial.compute_key_id!(encryption_public_material),
        capability_context_hash: share.capability_context_hash,
        share_created_event_hash: share.created_event_hash,
        latest_bootstrap_event_hash: share.latest_bootstrap_event_hash,
        scope_kind: share.scope,
        scope_id: share.document_id,
        permission: share.permission
      })

    signature =
      Signature.__test_sign_hybrid_signature__(
        "share_participant_device_authorization",
        transcript,
        private_material,
        signing_public_material
      )

    attrs
    |> Map.put("share_participant_principal_id", principal_id)
    |> Map.put("share_participant_session_id", session_id)
    |> Map.put("share_capability_authorization", %{
      "transcript" => capability_transcript,
      "signature" => capability_signature
    })
    |> Map.put("share_participant_device_authorization", %{
      "transcript" => transcript,
      "signature" => signature
    })
  end

  def encode_share_participant_request_attrs(attrs) do
    attrs
    |> Map.drop(["__share_participant_private_material"])
    |> preserve_authorization_signature_object()
  end

  def bootstrap_share_participant(
        created_share,
        attrs_or_display,
        authorization_secret \\ open_admission_key()
      )

  def bootstrap_share_participant(created_share, display_name, authorization_secret)
      when is_binary(display_name) do
    bootstrap_share_participant(
      created_share,
      share_participant_attrs(display_name),
      authorization_secret
    )
  end

  def bootstrap_share_participant(created_share, attrs, authorization_secret)
      when is_map(attrs) do
    attrs =
      attach_share_participant_device_authorization(attrs, created_share, authorization_secret)

    case RefMD.Sharing.bootstrap_participant(created_share.share_slug, attrs) do
      {:ok, bootstrapped} ->
        {:ok, bootstrapped}

      other ->
        other
    end
  end

  def open_admission_key, do: :crypto.hash(:sha256, "refmd-test-open-share-admission")

  def open_share_capability_secret_commitment do
    Hash.blake3_base64url(open_admission_key())
  end

  defp preserve_authorization_signature_object(attrs), do: attrs

  def signed_rrp_header_value(
        private_material,
        variant,
        user_id,
        device_id,
        challenge,
        session_binding \\ nil,
        resource \\ nil
      ) do
    signature =
      private_material
      |> sign_rrp(variant, user_id, device_id, challenge, session_binding, resource)
      |> JCS.canonical_bytes!()

    Encoding.encode_base64url(signature)
  end

  def signed_rrp_header_value_for_actor(
        private_material,
        variant,
        actor,
        challenge,
        session_binding,
        resource
      ) do
    private_material
    |> sign_rrp_with_actor(variant, actor, challenge, session_binding, resource)
    |> JCS.canonical_bytes!()
    |> Encoding.encode_base64url()
  end

  def signed_rrp_signature(
        private_material,
        variant,
        user_id,
        device_id,
        challenge,
        session_binding \\ nil,
        resource \\ nil
      ) do
    sign_rrp(private_material, variant, user_id, device_id, challenge, session_binding, resource)
  end

  def signed_rrp_signature_for_actor(
        private_material,
        variant,
        actor,
        challenge,
        session_binding,
        resource
      ) do
    sign_rrp_with_actor(private_material, variant, actor, challenge, session_binding, resource)
  end

  def hybrid_signature_transport(signature) when is_map(signature) do
    signature
    |> JCS.canonical_bytes!()
    |> Encoding.encode_base64url()
  end

  def sign_rrp(
        private_material,
        variant,
        user_id,
        device_id,
        challenge,
        session_binding,
        resource
      ) do
    public_material = hybrid_signing_public_key_material(private_material)

    session_binding =
      session_binding ||
        rrp_session_fixture(variant)

    transcript =
      Signature.build_rrp_transcript!(
        variant,
        private_material["owner_kind"],
        private_material["owner_id"],
        rrp_actor_fixture(
          variant,
          user_id,
          device_id,
          Signature.compute_signing_key_id!(public_material)
        ),
        challenge,
        session_binding,
        resource
      )

    sign_rrp_transcript(private_material, public_material, transcript)
  end

  def sign_rrp_with_actor(private_material, variant, actor, challenge, session_binding, resource) do
    public_material = hybrid_signing_public_key_material(private_material)

    transcript =
      Signature.build_rrp_transcript!(
        variant,
        private_material["owner_kind"],
        private_material["owner_id"],
        actor,
        challenge,
        session_binding,
        resource
      )

    sign_rrp_transcript(private_material, public_material, transcript)
  end

  defp sign_rrp_transcript(private_material, public_material, transcript) do
    transcript_bytes = JCS.canonical_bytes!(transcript)

    %{
      "protocol" => @signature_protocol,
      "version" => @protocol_version,
      "suite_id" => @suite_id,
      "suite_rank" => @suite_rank,
      "signing_key_id" => Signature.compute_signing_key_id!(public_material),
      "transcript_hash" => Hash.blake3_base64url(transcript_bytes),
      "ed25519" =>
        private_material["ed25519_private"]
        |> Encoding.decode_base64url!(32)
        |> then(&:crypto.sign(:eddsa, :none, transcript_bytes, [&1, :ed25519]))
        |> Encoding.encode_base64url(),
      "mldsa65" =>
        mldsa65_sign(
          transcript_bytes,
          @mldsa_context_prefix <> "rrp_request",
          Encoding.decode_base64url!(private_material["mldsa65_private"], 4032)
        )
        |> Encoding.encode_base64url()
    }
  end

  defp rrp_actor_fixture(
         "http_share_participant_device",
         principal_id,
         device_id,
         signing_key_id
       ),
       do: rrp_share_actor_fixture(principal_id, device_id, signing_key_id)

  defp rrp_actor_fixture(
         "channel_share_participant_device",
         principal_id,
         device_id,
         signing_key_id
       ),
       do: rrp_share_actor_fixture(principal_id, device_id, signing_key_id)

  defp rrp_actor_fixture(_variant, user_id, device_id, signing_key_id) do
    %{
      "signer_kind" => "device",
      "user_id" => user_id,
      "device_id" => device_id,
      "signing_key_id" => signing_key_id,
      "key_scope_kind" => "user",
      "key_scope_id" => user_id,
      "key_checkpoint_sequence" => 1,
      "key_checkpoint_hash" => Hash.blake3_base64url("test-user-checkpoint")
    }
  end

  defp rrp_share_actor_fixture(principal_id, device_id, signing_key_id) do
    %{
      "signer_kind" => "share_participant_device",
      "share_id" => "00000000-0000-4000-8000-000000000501",
      "share_participant_principal_id" => principal_id,
      "share_participant_device_id" => device_id,
      "signing_key_id" => signing_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => "00000000-0000-4000-8000-000000000502",
      "key_checkpoint_sequence" => 1,
      "key_checkpoint_hash" => Hash.blake3_base64url("test-workspace-checkpoint")
    }
  end

  defp rrp_session_fixture("http_share_participant_device"), do: rrp_share_session_fixture()
  defp rrp_session_fixture("channel_share_participant_device"), do: rrp_share_session_fixture()

  defp rrp_session_fixture(_variant) do
    %{
      "session_id_hash" => Hash.blake3_base64url("test-session"),
      "session_kind" => "user",
      "is_recovery" => false
    }
  end

  defp rrp_share_session_fixture do
    %{
      "session_id_hash" => Hash.blake3_base64url("test-session"),
      "session_kind" => "share_participant",
      "share_id" => "00000000-0000-4000-8000-000000000501",
      "is_recovery" => false
    }
  end

  def test_rrp_resource(method, path, body \\ "", query \\ "") do
    canonical_query = canonical_test_query_string(query)

    %{
      "body_hash" => body |> encode_test_rrp_body() |> Hash.blake3_base64url(),
      "canonical_query" => canonical_query,
      "method" => method,
      "path" => path,
      "query_hash" => Hash.blake3_base64url(canonical_query)
    }
  end

  defp canonical_test_query_string(query) when is_binary(query) do
    query
    |> URI.query_decoder()
    |> Enum.map(fn {key, value} -> {to_string(key), to_string(value)} end)
    |> Enum.sort()
    |> Enum.map_join("&", fn {key, value} ->
      URI.encode_www_form(key) <> "=" <> URI.encode_www_form(value)
    end)
  rescue
    _ -> query
  end

  def test_json_body(body) when is_map(body) or is_list(body) do
    Phoenix.json_library().encode_to_iodata!(body) |> IO.iodata_to_binary()
  end

  def test_json_body(body) when is_binary(body), do: body

  def put_test_rrp_headers(
        conn,
        user_id,
        device,
        signing_private_key,
        method,
        path,
        body \\ "",
        query \\ ""
      ) do
    session = conn.private.test_session
    device = ensure_test_user_rrp_key_directory!(user_id, device)
    {:ok, challenge} = RefMD.Auth.create_rrp_challenge(user_id, device.id, session.id)
    challenge = Base.url_encode64(challenge, padding: false)

    signature =
      signed_rrp_header_value_for_actor(
        signing_private_key,
        "http_user_device",
        RrpTranscript.user_actor!(device, user_id),
        challenge,
        RrpSessionBinding.for_user_session(session),
        test_rrp_resource(method, path, body, query)
      )

    conn
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> Plug.Conn.put_req_header("x-refmd-rrp-device-id", device.id)
    |> Plug.Conn.put_req_header("x-refmd-rrp-actor-variant", "user_device")
    |> Plug.Conn.put_req_header("x-refmd-rrp-challenge", challenge)
    |> Plug.Conn.put_req_header("x-refmd-rrp-signature-transport", signature)
  end

  def ensure_test_user_rrp_key_directory!(user_id, device) do
    checkpoint =
      case RefMD.Encryption.current_user_key_directory_checkpoint(user_id) do
        nil -> insert_test_user_key_directory!(user_id, device).checkpoint
        checkpoint -> checkpoint
      end

    device
    |> Ecto.Changeset.change(
      key_checkpoint_sequence: checkpoint.sequence,
      key_checkpoint_hash: checkpoint.checkpoint_hash
    )
    |> Repo.update!()
  end

  defp insert_test_user_key_directory!(user_id, device) do
    registration_challenge_hash = Hash.blake3_base64url("registration:" <> device.id)
    identity_material = ensure_test_identity_material!(user_id, registration_challenge_hash)
    device_private_material = hybrid_signing_private_key_material("device", device.id)

    key_directory =
      initial_key_directory_bootstrap(
        user_id,
        Ecto.UUID.generate(),
        Ecto.UUID.generate(),
        identity_material.private,
        identity_material.encryption_public,
        device_private_material,
        device.hybrid_encryption_public_key_material
      )

    KeyDirectory.insert_signed_initial_scope!(
      "user",
      user_id,
      key_directory.user_events,
      key_directory.user_checkpoint,
      checkpoint_signer_kind: "identity"
    )
  end

  defp encode_test_rrp_body(body) when is_binary(body), do: body
  defp encode_test_rrp_body(nil), do: ""

  defp encode_test_rrp_body(body) when is_map(body) or is_list(body) do
    Phoenix.json_library().encode_to_iodata!(body) |> IO.iodata_to_binary()
  end

  def signed_document_update_header_value(
        private_material,
        user_id,
        device_id,
        ciphertext,
        nonce,
        public_data
      ) do
    private_material
    |> sign_document_update(
      user_id,
      device_id,
      ciphertext,
      nonce,
      public_data,
      test_document_authority_boundary(public_data, "document_write_session_admitted")
    )
    |> JCS.canonical_bytes!()
    |> Encoding.encode_base64url()
  end

  def sign_document_update(
        private_material,
        user_id,
        device_id,
        ciphertext,
        nonce,
        public_data,
        authority_boundary
      ) do
    sign_document_update(
      private_material,
      user_id,
      device_id,
      ciphertext,
      nonce,
      public_data,
      authority_boundary,
      workspace_id_from_public_data!(public_data)
    )
  end

  def sign_document_update(
        private_material,
        user_id,
        device_id,
        ciphertext,
        nonce,
        public_data,
        authority_boundary,
        workspace_id
      ) do
    public_material = hybrid_signing_public_key_material(private_material)

    transcript =
      Signature.build_document_update_transcript!(%{
        owner_kind: private_material["owner_kind"],
        owner_id: private_material["owner_id"],
        workspace_id: workspace_id,
        actor_user_id: user_id,
        actor_device_id: device_id,
        signing_key_id: Signature.compute_signing_key_id!(public_material),
        public_data: public_data,
        authority_boundary: authority_boundary,
        ciphertext: ciphertext,
        nonce: nonce
      })

    sign_transcript(private_material, public_material, "document_update", transcript)
  end

  def sign_document_snapshot(
        private_material,
        user_id,
        device_id,
        ciphertext,
        nonce,
        public_data,
        authority_boundary
      ) do
    sign_document_snapshot(
      private_material,
      user_id,
      device_id,
      ciphertext,
      nonce,
      public_data,
      authority_boundary,
      workspace_id_from_public_data!(public_data)
    )
  end

  def sign_document_snapshot(
        private_material,
        user_id,
        device_id,
        ciphertext,
        nonce,
        public_data,
        authority_boundary,
        workspace_id
      ) do
    public_material = hybrid_signing_public_key_material(private_material)

    transcript =
      Signature.build_document_snapshot_transcript!(%{
        owner_kind: private_material["owner_kind"],
        owner_id: private_material["owner_id"],
        workspace_id: workspace_id,
        actor_user_id: user_id,
        actor_device_id: device_id,
        signing_key_id: Signature.compute_signing_key_id!(public_material),
        public_data: public_data,
        authority_boundary: authority_boundary,
        ciphertext: ciphertext,
        nonce: nonce
      })

    sign_transcript(private_material, public_material, "document_snapshot", transcript)
  end

  def sign_editor_ephemeral(
        private_material,
        user_id,
        device_id,
        ciphertext,
        nonce,
        public_data
      ) do
    sign_editor_ephemeral(
      private_material,
      user_id,
      device_id,
      ciphertext,
      nonce,
      public_data,
      workspace_id_from_public_data!(public_data)
    )
  end

  def sign_editor_ephemeral(
        private_material,
        user_id,
        device_id,
        ciphertext,
        nonce,
        public_data,
        workspace_id
      ) do
    public_material = hybrid_signing_public_key_material(private_material)

    transcript =
      Signature.build_editor_ephemeral_transcript!(%{
        owner_kind: private_material["owner_kind"],
        owner_id: private_material["owner_id"],
        actor_user_id: user_id,
        actor_device_id: device_id,
        signing_key_id: Signature.compute_signing_key_id!(public_material),
        workspace_id: workspace_id,
        public_data: public_data,
        authority_boundary: editor_ephemeral_authority_boundary(workspace_id, public_data),
        ciphertext: ciphertext,
        nonce: nonce
      })

    sign_transcript(private_material, public_material, "editor_ephemeral", transcript)
  end

  defp workspace_id_from_public_data!(%{
         "authorityKind" => "workspace_device",
         "authorityId" => id
       })
       when is_binary(id),
       do: id

  defp workspace_id_from_public_data!(_public_data),
    do: raise(ArgumentError, "workspace_id_missing")

  defp editor_ephemeral_authority_boundary(workspace_id, public_data) do
    actor_active_proof =
      JCS.canonical_bytes!(%{
        "protocol" => "refmd.editor-ephemeral-actor-active-proof",
        "version" => 1,
        "owner_kind" => public_data["ownerKind"],
        "owner_id" => public_data["ownerId"],
        "authority_kind" => public_data["authorityKind"],
        "authority_id" => public_data["authorityId"],
        "authority_context_key" => public_data["authorityContextKey"],
        "key_checkpoint_sequence" => public_data["keyCheckpointSequence"],
        "key_checkpoint_hash" => public_data["keyCheckpointHash"],
        "signing_key_id" => public_data["signingKeyId"]
      })

    permission_proof =
      JCS.canonical_bytes!(%{
        "protocol" => "refmd.document-permission-proof",
        "version" => 1,
        "workspace_id" => workspace_id,
        "document_id" => public_data["docId"],
        "authority_kind" => public_data["authorityKind"],
        "authority_id" => public_data["authorityId"],
        "authority_context_key" => public_data["authorityContextKey"],
        "authority_scope_id" => public_data["authorityScopeId"],
        "authority_permission_version" => public_data["authorityPermissionVersion"],
        "permission" => "edit"
      })

    %{
      "workspace_event_head_sequence" => public_data["workspaceEventHeadSequence"],
      "workspace_event_head_hash" => public_data["workspaceEventHeadHash"],
      "actor_active_proof_hash" => Hash.blake3_base64url(actor_active_proof),
      "document_permission_proof_hash" => Hash.blake3_base64url(permission_proof),
      "expires_event_sequence" => public_data["workspaceEventHeadSequence"] + 1
    }
  end

  defp test_document_authority_boundary(public_data, event_type) do
    if event_type == "document_write_session_admitted" do
      %{
        "write_session_event_hash" => public_data["writeSessionEventHash"],
        "write_session_id" => public_data["writeSessionId"],
        "write_session_counter" => public_data["writeSessionCounter"],
        "min_dek_version" => public_data["minDekVersion"],
        "document_permission_proof_hash" => public_data["keyCheckpointHash"]
      }
    else
      %{
        "previous_workspace_event_sequence" => public_data["keyCheckpointSequence"],
        "previous_workspace_event_hash" => public_data["keyCheckpointHash"],
        "admission_event_type" => event_type,
        "admission_nonce" => public_data["keyCheckpointHash"],
        "min_dek_version" => public_data["keyVersion"],
        "document_permission_proof_hash" => public_data["keyCheckpointHash"]
      }
    end
  end

  def sign_genesis_device_bootstrap(
        identity_private_material,
        device_id,
        device_public_material,
        _device_x25519_public,
        device_hybrid_encryption_public_key_material,
        client_nonce
      ) do
    registration_challenge_hash = Hash.blake3_base64url("registration:" <> device_id)

    sign_genesis_device_bootstrap(
      identity_private_material,
      device_id,
      device_public_material,
      nil,
      device_hybrid_encryption_public_key_material,
      client_nonce,
      registration_challenge_hash
    )
  end

  def sign_genesis_device_bootstrap(
        identity_private_material,
        device_id,
        device_public_material,
        _device_x25519_public,
        device_hybrid_encryption_public_key_material,
        client_nonce,
        registration_challenge_hash
      ) do
    user_id = identity_private_material["owner_id"]
    identity_public_material = hybrid_signing_public_key_material(identity_private_material)

    user_identity_public_key_hash =
      Hash.blake3_base64url(JCS.canonical_bytes!(identity_public_material))

    transcript =
      user_id
      |> genesis_device_bootstrap_fixture_params(
        device_id,
        device_public_material,
        device_hybrid_encryption_public_key_material,
        client_nonce,
        registration_challenge_hash,
        identity_public_material,
        user_identity_public_key_hash
      )
      |> Signature.build_genesis_device_bootstrap_transcript!()

    sign_transcript(
      identity_private_material,
      identity_public_material,
      "genesis_device_bootstrap",
      transcript
    )
  end

  def genesis_device_bootstrap_signature(
        user_id,
        device_id,
        device_public_material,
        device_x25519_public,
        device_hybrid_encryption_public_key_material,
        client_nonce
      ) do
    registration_challenge_hash = Hash.blake3_base64url("registration:" <> device_id)

    user_id
    |> ensure_test_identity_material!(registration_challenge_hash)
    |> Map.fetch!(:private)
    |> sign_genesis_device_bootstrap(
      device_id,
      device_public_material,
      device_x25519_public,
      device_hybrid_encryption_public_key_material,
      client_nonce
    )
  end

  def genesis_device_approval_proof(
        user_id,
        device_id,
        device_public_material,
        _device_x25519_public,
        device_hybrid_encryption_public_key_material,
        client_nonce
      ) do
    registration_challenge_hash = Hash.blake3_base64url("registration:" <> device_id)
    identity_material = ensure_test_identity_material!(user_id, registration_challenge_hash)
    identity_public_material = identity_material.public
    registration_challenge_hash = Hash.blake3_base64url("registration:" <> device_id)

    user_identity_public_key_hash =
      Hash.blake3_base64url(JCS.canonical_bytes!(identity_public_material))

    transcript =
      user_id
      |> genesis_device_bootstrap_fixture_params(
        device_id,
        device_public_material,
        device_hybrid_encryption_public_key_material,
        client_nonce,
        registration_challenge_hash,
        identity_public_material,
        user_identity_public_key_hash
      )
      |> Signature.build_genesis_device_bootstrap_transcript!()

    fixture = genesis_device_bootstrap_fixture(device_id, user_id)

    Signature.build_device_approval_proof!(
      "genesis_device_bootstrap",
      transcript,
      %{
        "kind" => "genesis_device_bootstrap",
        "registration_id" => device_id,
        "compound_intent_id" => fixture.compound_intent_id,
        "mutation_id" => fixture.mutation_id,
        "genesis_compound_context_hash" => fixture.compound_context_hash,
        "workspace_id" => user_id,
        "owner_role_id" => user_id,
        "registration_challenge_hash" => registration_challenge_hash,
        "user_identity_public_key_hash" => user_identity_public_key_hash,
        "user_device_key_added_event_hash" => fixture.user_device_event_hash,
        "workspace_device_key_added_event_hash" => fixture.workspace_device_event_hash,
        "owner_member_added_event_hash" => fixture.owner_member_event_hash,
        "workspace_member_envelope_commitment_hash" => fixture.member_envelope_hash,
        "user_audit_checkpoint" => fixture.user_audit_checkpoint,
        "workspace_audit_checkpoint" => fixture.workspace_audit_checkpoint
      },
      %{
        "approving_signing_key_id" => Signature.compute_signing_key_id!(identity_public_material),
        "approving_key_checkpoint_sequence" => 1,
        "approving_key_checkpoint_hash" => Hash.blake3_base64url("checkpoint:" <> user_id),
        "target_device_id" => device_id,
        "target_device_signing_key_id" =>
          Signature.compute_signing_key_id!(device_public_material),
        "target_device_hybrid_signing_public_key_material_hash" =>
          Hash.blake3_base64url(JCS.canonical_bytes!(device_public_material)),
        "target_device_hybrid_encryption_public_key_material_hash" =>
          Hash.blake3_base64url(
            JCS.canonical_bytes!(device_hybrid_encryption_public_key_material)
          ),
        "target_device_encryption_key_id" =>
          HybridEncryptionMaterial.compute_key_id!(device_hybrid_encryption_public_key_material),
        "target_device_client_nonce_hash" => Hash.blake3_base64url(client_nonce),
        "target_key_checkpoint_sequence" => 1,
        "target_key_checkpoint_hash" => Hash.blake3_base64url("checkpoint:" <> device_id)
      }
    )
  end

  defp genesis_device_bootstrap_fixture_params(
         user_id,
         device_id,
         device_public_material,
         device_encryption_material,
         client_nonce,
         registration_challenge_hash,
         identity_public_material,
         user_identity_public_key_hash
       ) do
    fixture = genesis_device_bootstrap_fixture(device_id, user_id)

    %{
      registration_id: device_id,
      compound_intent_id: fixture.compound_intent_id,
      mutation_id: fixture.mutation_id,
      genesis_compound_context_hash: fixture.compound_context_hash,
      user_id: user_id,
      workspace_id: user_id,
      owner_role_id: user_id,
      device_id: device_id,
      device_public_material: device_public_material,
      device_hybrid_encryption_public_key_material: device_encryption_material,
      client_nonce: Encoding.encode_base64url(client_nonce),
      registration_challenge_hash: registration_challenge_hash,
      identity_signing_key_id: Signature.compute_signing_key_id!(identity_public_material),
      user_identity_public_key_hash: user_identity_public_key_hash,
      user_device_key_added_event_hash: fixture.user_device_event_hash,
      workspace_device_key_added_event_hash: fixture.workspace_device_event_hash,
      owner_member_added_event_hash: fixture.owner_member_event_hash,
      workspace_member_envelope_commitment_hash: fixture.member_envelope_hash,
      user_audit_checkpoint: fixture.user_audit_checkpoint,
      workspace_audit_checkpoint: fixture.workspace_audit_checkpoint
    }
  end

  defp genesis_device_bootstrap_fixture(device_id, user_id) do
    %{
      compound_intent_id: device_id,
      mutation_id: device_id,
      compound_context_hash: Hash.blake3_base64url("genesis-context:" <> device_id),
      user_device_event_hash: Hash.blake3_base64url("user-device-event:" <> device_id),
      workspace_device_event_hash: Hash.blake3_base64url("workspace-device-event:" <> device_id),
      owner_member_event_hash: Hash.blake3_base64url("owner-member-event:" <> device_id),
      member_envelope_hash: Hash.blake3_base64url("member-envelope:" <> device_id),
      user_audit_checkpoint: %{
        "sequence" => 2,
        "checkpoint_hash" => Hash.blake3_base64url("user-audit:" <> user_id <> device_id)
      },
      workspace_audit_checkpoint: %{
        "sequence" => 1,
        "checkpoint_hash" => Hash.blake3_base64url("workspace-audit:" <> user_id <> device_id)
      }
    }
  end

  defp device_approval_transcript(
         user_id,
         approver_device_id,
         device_id,
         device_public_material,
         device_hybrid_encryption_public_key_material,
         client_nonce,
         commitments
       ) do
    Signature.build_device_approval_transcript!(
      user_id,
      approver_device_id,
      device_id,
      device_public_material,
      device_hybrid_encryption_public_key_material,
      Encoding.encode_base64url(client_nonce),
      Map.merge(
        default_device_approval_binding_context(
          user_id,
          approver_device_id,
          device_id,
          device_public_material,
          device_hybrid_encryption_public_key_material,
          client_nonce
        ),
        commitments
      )
    )
  end

  def device_approval_proof(
        user_id,
        approver_device_id,
        device_id,
        device_public_material,
        device_hybrid_encryption_public_key_material,
        client_nonce,
        commitments
      ) do
    transcript =
      device_approval_transcript(
        user_id,
        approver_device_id,
        device_id,
        device_public_material,
        device_hybrid_encryption_public_key_material,
        client_nonce,
        commitments
      )

    Signature.build_device_approval_proof!(
      "device_approval",
      transcript,
      %{
        "kind" => "device_approval",
        "pending_registration_id" => device_id,
        "pending_registration_challenge_hash" =>
          Hash.blake3_base64url("pending-registration-challenge"),
        "trust_transfer_delivery_commitment" =>
          Map.get(commitments, "trust_transfer_delivery_commitment", %{}),
        "umk_distribution_delivery_commitment" =>
          Map.get(commitments, "umk_distribution_delivery_commitment", %{}),
        "device_approval_kek_initial_delivery_commitments" =>
          Map.get(commitments, "device_approval_kek_initial_delivery_commitments", []),
        "approving_device_key_directory_proof_hash" =>
          Hash.blake3_base64url("approving-device-key-directory-proof"),
        "approved_device_registration_sas_hash" => Hash.blake3_base64url("sas")
      }
    )
  end

  defp device_approval_signature_transcript(
         user_id,
         approver_device_id,
         device_id,
         device_public_material,
         device_hybrid_encryption_public_key_material,
         client_nonce,
         commitments
       ) do
    device_approval_transcript(
      user_id,
      approver_device_id,
      device_id,
      device_public_material,
      device_hybrid_encryption_public_key_material,
      client_nonce,
      commitments
    )
  end

  def device_approval_signature(
        user_id,
        approver_device_id,
        device_id,
        device_public_material,
        device_hybrid_encryption_public_key_material,
        client_nonce,
        commitments
      ) do
    private_material = hybrid_signing_private_key_material("device", approver_device_id)
    public_material = hybrid_signing_public_key_material(private_material)

    transcript =
      device_approval_signature_transcript(
        user_id,
        approver_device_id,
        device_id,
        device_public_material,
        device_hybrid_encryption_public_key_material,
        client_nonce,
        commitments
      )

    sign_transcript(private_material, public_material, "device_approval", transcript)
  end

  def device_approval_signature_and_proof(
        user_id,
        approver_device_id,
        device_id,
        device_public_material,
        device_hybrid_encryption_public_key_material,
        client_nonce,
        commitments,
        binding_context
      ) do
    private_material = hybrid_signing_private_key_material("device", approver_device_id)
    public_material = hybrid_signing_public_key_material(private_material)

    transcript =
      Signature.build_device_approval_transcript!(
        user_id,
        approver_device_id,
        device_id,
        device_public_material,
        device_hybrid_encryption_public_key_material,
        Encoding.encode_base64url(client_nonce),
        Map.merge(commitments, binding_context)
      )

    surface_details = %{
      "kind" => "device_approval",
      "pending_registration_id" => device_id,
      "pending_registration_challenge_hash" =>
        Map.fetch!(binding_context, "pending_registration_challenge_hash"),
      "trust_transfer_delivery_commitment" =>
        Map.fetch!(commitments, "trust_transfer_delivery_commitment"),
      "umk_distribution_delivery_commitment" =>
        Map.fetch!(commitments, "umk_distribution_delivery_commitment"),
      "device_approval_kek_initial_delivery_commitments" =>
        Map.fetch!(commitments, "device_approval_kek_initial_delivery_commitments"),
      "approving_device_key_directory_proof_hash" =>
        Map.fetch!(binding_context, "approving_device_key_directory_proof_hash"),
      "approved_device_registration_sas_hash" =>
        Map.fetch!(binding_context, "approved_device_registration_sas_hash")
    }

    %{
      signature:
        sign_transcript(private_material, public_material, "device_approval", transcript),
      proof:
        Signature.build_device_approval_proof!("device_approval", transcript, surface_details)
    }
  end

  defp default_device_approval_binding_context(
         _user_id,
         approver_device_id,
         device_id,
         device_public_material,
         device_hybrid_encryption_public_key_material,
         client_nonce
       ) do
    %{
      "approved_device_registration_sas_hash" => Hash.blake3_base64url("sas"),
      "pending_registration_id" => device_id,
      "pending_registration_challenge_hash" => Hash.blake3_base64url("challenge"),
      "approving_owner_kind" => "device",
      "approving_owner_id" => approver_device_id,
      "approving_signing_key_id" => Hash.blake3_base64url("approver-signing-key"),
      "approving_key_checkpoint_sequence" => 1,
      "approving_key_checkpoint_hash" => Hash.blake3_base64url("approver-checkpoint"),
      "approving_device_key_directory_proof_hash" => Hash.blake3_base64url("approver-proof"),
      "target_device_id" => device_id,
      "target_device_signing_key_id" => Signature.compute_signing_key_id!(device_public_material),
      "target_device_hybrid_signing_public_key_material_hash" =>
        Hash.blake3_base64url(JCS.canonical_bytes!(device_public_material)),
      "target_device_hybrid_encryption_public_key_material_hash" =>
        Hash.blake3_base64url(JCS.canonical_bytes!(device_hybrid_encryption_public_key_material)),
      "target_device_encryption_key_id" =>
        HybridEncryptionMaterial.compute_key_id!(device_hybrid_encryption_public_key_material),
      "target_device_client_nonce_hash" => Hash.blake3_base64url(client_nonce),
      "target_key_checkpoint_sequence" => 2,
      "target_key_checkpoint_hash" => Hash.blake3_base64url("target-checkpoint")
    }
  end

  def sign_recipient_bound_authorization(
        device_private_material,
        guest_user_id,
        authorization_payload
      ) do
    device_public_material = hybrid_signing_public_key_material(device_private_material)
    signing_key_id = Signature.compute_signing_key_id!(device_public_material)
    authorization_payload = stringify_keys(authorization_payload)

    transcript =
      Signature.build_recipient_bound_authorization_transcript!(
        device_private_material["owner_id"],
        guest_user_id,
        device_private_material["owner_id"],
        signing_key_id,
        Map.put(authorization_payload, "redeem_authority_signing_key_id", signing_key_id)
      )

    sign_transcript(
      device_private_material,
      device_public_material,
      "recipient_bound_authorization",
      transcript
    )
  end

  def initial_key_directory_bootstrap(
        user_id,
        workspace_id,
        workspace_owner_role_id,
        identity_private_material,
        identity_hybrid_encryption_public_key_material,
        device_private_material,
        device_hybrid_encryption_public_key_material
      ) do
    identity_public_material = hybrid_signing_public_key_material(identity_private_material)
    device_public_material = hybrid_signing_public_key_material(device_private_material)
    identity_signing_key_id = Signature.compute_signing_key_id!(identity_public_material)
    device_signing_key_id = Signature.compute_signing_key_id!(device_public_material)

    device_encryption_key_id =
      HybridEncryptionMaterial.compute_key_id!(device_hybrid_encryption_public_key_material)

    issued_at = DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()

    user_identity_event =
      key_directory_event(%{
        "scope_kind" => "user",
        "scope_id" => user_id,
        "sequence" => 1,
        "event_type" => "identity_key_added",
        "actor" => identity_actor(user_id, identity_signing_key_id),
        "body" => %{
          "key_kind" => "signing",
          "key_id" => identity_signing_key_id,
          "key_material_hash" =>
            Hash.blake3_base64url(JCS.canonical_bytes!(identity_public_material))
        }
      })

    user_device_event =
      key_directory_event(%{
        "scope_kind" => "user",
        "scope_id" => user_id,
        "sequence" => 2,
        "event_type" => "device_key_added",
        "actor" => identity_actor(user_id, identity_signing_key_id),
        "previous_event_hash" => KeyDirectory.event_hash(user_identity_event),
        "body" => %{
          "user_id" => user_id,
          "device_id" => device_private_material["owner_id"],
          "signing_key_id" => device_signing_key_id,
          "encryption_key_id" => device_encryption_key_id
        }
      })

    user_checkpoint =
      key_directory_checkpoint_payload!(%{
        "scope_kind" => "user",
        "scope_id" => user_id,
        "sequence" => 1,
        "issued_at" => issued_at,
        "authority_boundary" =>
          test_key_directory_checkpoint_authority_boundary(%{"sequence" => 1}),
        "covered_event_head" => event_head(user_device_event),
        "identity_keys" => [
          Payload.key_entry!(
            identity_public_material,
            event_ref("user", user_id, user_identity_event)
          ),
          Payload.key_entry!(
            identity_hybrid_encryption_public_key_material,
            event_ref("user", user_id, user_identity_event)
          )
        ],
        "device_keys" => [
          Payload.key_entry!(
            device_public_material,
            event_ref("user", user_id, user_device_event)
          ),
          Payload.key_entry!(
            device_hybrid_encryption_public_key_material,
            event_ref("user", user_id, user_device_event)
          )
        ]
      })

    workspace_device_event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => 1,
        "event_type" => "device_key_added",
        "actor" =>
          device_actor(user_id, device_private_material["owner_id"], device_signing_key_id),
        "body" => %{
          "user_id" => user_id,
          "device_id" => device_private_material["owner_id"],
          "signing_key_id" => device_signing_key_id,
          "encryption_key_id" => device_encryption_key_id
        }
      })

    workspace_identity_signing_event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => 2,
        "event_type" => "identity_key_added",
        "actor" =>
          device_actor(user_id, device_private_material["owner_id"], device_signing_key_id),
        "previous_event_hash" => KeyDirectory.event_hash(workspace_device_event),
        "body" => %{
          "key_kind" => "signing",
          "key_id" => identity_signing_key_id,
          "key_material_hash" =>
            Hash.blake3_base64url(JCS.canonical_bytes!(identity_public_material))
        }
      })

    identity_encryption_key_id =
      HybridEncryptionMaterial.compute_key_id!(identity_hybrid_encryption_public_key_material)

    workspace_identity_encryption_event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => 3,
        "event_type" => "identity_key_added",
        "actor" =>
          device_actor(user_id, device_private_material["owner_id"], device_signing_key_id),
        "previous_event_hash" => KeyDirectory.event_hash(workspace_identity_signing_event),
        "body" => %{
          "key_kind" => "encryption",
          "key_id" => identity_encryption_key_id,
          "key_material_hash" =>
            Hash.blake3_base64url(
              JCS.canonical_bytes!(identity_hybrid_encryption_public_key_material)
            )
        }
      })

    workspace_member_event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => 4,
        "event_type" => "member_added",
        "actor" =>
          device_actor(user_id, device_private_material["owner_id"], device_signing_key_id),
        "previous_event_hash" => KeyDirectory.event_hash(workspace_identity_encryption_event),
        "body" => %{
          "workspace_id" => workspace_id,
          "user_id" => user_id,
          "role_id" => workspace_owner_role_id,
          "base_role" => "owner",
          "workspace_member_envelope_hash" =>
            Hash.blake3_base64url("member-envelope:" <> workspace_id <> ":" <> user_id)
        }
      })

    workspace_checkpoint =
      key_directory_checkpoint_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => 1,
        "issued_at" => issued_at,
        "authority_boundary" =>
          test_key_directory_checkpoint_authority_boundary(%{"sequence" => 1}),
        "covered_event_head" => event_head(workspace_member_event),
        "identity_keys" => [
          Payload.key_entry!(
            identity_public_material,
            event_ref("workspace", workspace_id, workspace_identity_signing_event)
          ),
          Payload.key_entry!(
            identity_hybrid_encryption_public_key_material,
            event_ref("workspace", workspace_id, workspace_identity_encryption_event)
          )
        ],
        "device_keys" => [
          Payload.key_entry!(
            device_public_material,
            event_ref("workspace", workspace_id, workspace_device_event)
          ),
          Payload.key_entry!(
            device_hybrid_encryption_public_key_material,
            event_ref("workspace", workspace_id, workspace_device_event)
          )
        ]
      })

    %{
      user_events: [
        signed_key_directory_event(user_identity_event, identity_private_material),
        signed_key_directory_event(user_device_event, identity_private_material)
      ],
      user_checkpoint:
        signed_key_directory_checkpoint(
          user_checkpoint,
          "identity_initial",
          identity_private_material
        ),
      workspace_events: [
        signed_key_directory_event(workspace_device_event, device_private_material),
        signed_key_directory_event(workspace_identity_signing_event, device_private_material),
        signed_key_directory_event(workspace_identity_encryption_event, device_private_material),
        signed_key_directory_event(workspace_member_event, device_private_material)
      ],
      workspace_checkpoint:
        signed_key_directory_checkpoint(
          workspace_checkpoint,
          "workspace_initial",
          device_private_material,
          user_id
        )
    }
  end

  def signed_key_directory_event_envelope(payload, private_material),
    do: signed_key_directory_event(payload, private_material)

  def signed_key_directory_checkpoint_envelope(
        payload,
        variant,
        private_material,
        signer_user_id \\ nil
      ),
      do: signed_key_directory_checkpoint(payload, variant, private_material, signer_user_id)

  def key_directory_event_ref(scope_kind, scope_id, event),
    do: event_ref(scope_kind, scope_id, event)

  def key_directory_event_head(event), do: event_head(event)

  def device_approval_key_directory_append(
        user_id,
        target_device_id,
        target_signing_public,
        target_encryption_public,
        identity_private,
        sender_device_private,
        workspace_ids
      ) do
    target_signing_key_id = Signature.compute_signing_key_id!(target_signing_public)
    target_encryption_key_id = HybridEncryptionMaterial.compute_key_id!(target_encryption_public)

    target = %{
      user_id: user_id,
      device_id: target_device_id,
      signing_key_id: target_signing_key_id,
      encryption_key_id: target_encryption_key_id,
      signing_public: target_signing_public,
      encryption_public: target_encryption_public
    }

    user_append =
      device_key_added_append(
        "user",
        user_id,
        target,
        identity_private,
        "identity_active"
      )

    workspace_appends =
      Enum.map(workspace_ids, fn workspace_id ->
        append =
          device_key_added_append(
            "workspace",
            workspace_id,
            target,
            sender_device_private,
            "workspace_authorized"
          )

        %{
          "workspace_id" => workspace_id,
          "events" => append.events,
          "checkpoint" => append.checkpoint
        }
      end)

    %{
      "user_events" => user_append.events,
      "user_checkpoint" => user_append.checkpoint,
      "workspace_appends" => workspace_appends
    }
  end

  defp device_key_added_append(
         scope_kind,
         scope_id,
         target,
         signer_private,
         checkpoint_variant
       ) do
    pin = KeyDirectory.current_pin(scope_kind, scope_id)
    current = KeyDirectory.current_checkpoint(scope_kind, scope_id)
    signer_public = hybrid_signing_public_key_material(signer_private)
    signer_key_id = Signature.compute_signing_key_id!(signer_public)

    actor =
      if scope_kind == "user" do
        identity_actor(target.user_id, signer_key_id)
      else
        device_actor(target.user_id, signer_private["owner_id"], signer_key_id)
      end

    event =
      key_directory_event(%{
        "scope_kind" => scope_kind,
        "scope_id" => scope_id,
        "sequence" => pin.event_head_sequence + 1,
        "event_type" => "device_key_added",
        "actor" => actor,
        "previous_event_hash" => pin.event_head_hash,
        "body" => %{
          "user_id" => target.user_id,
          "device_id" => target.device_id,
          "signing_key_id" => target.signing_key_id,
          "encryption_key_id" => target.encryption_key_id
        }
      })

    event_ref = event_ref(scope_kind, scope_id, event)

    checkpoint_payload =
      current.payload
      |> Map.put("sequence", current.sequence + 1)
      |> Map.put(
        "issued_at",
        DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
      )
      |> Map.put("previous_checkpoint_hash", current.checkpoint_hash)
      |> Map.put("covered_event_head", event_head(event))
      |> Map.update!("device_keys", fn keys ->
        keys ++
          [
            Payload.key_entry!(target.signing_public, event_ref),
            Payload.key_entry!(target.encryption_public, event_ref)
          ]
      end)
      |> key_directory_checkpoint_payload!()

    %{
      events: [signed_key_directory_event(event, signer_private)],
      checkpoint:
        signed_key_directory_checkpoint(
          checkpoint_payload,
          checkpoint_variant,
          signer_private,
          if(scope_kind == "workspace", do: target.user_id)
        )
    }
  end

  def with_test_share_security_artifacts(attrs, %RefMD.Documents.Document{} = document, owner_id)
      when is_map(attrs) do
    with_test_share_security_artifacts(document, owner_id, attrs)
  end

  def with_test_share_security_artifacts(document, owner_id, attrs) do
    ensure_test_workspace_actor_material!(document.workspace_id, owner_id)

    attrs =
      attrs
      |> put_test_share_key_versions(document.min_dek_version)
      |> Map.put(
        "authenticated_workspace_pin_bootstrap",
        test_workspace_pin_bootstrap!(document.workspace_id)
      )
      |> Map.put(
        "authenticated_workspace_pin_bootstrap_hash",
        test_workspace_pin_bootstrap_hash!(document.workspace_id)
      )

    {actor_device, actor_private} = test_share_actor_device!(owner_id)
    share_id = fetch_attr!(attrs, "id")
    share_slug = fetch_attr!(attrs, "share_slug")
    token_hash = Blake3.hash_base64url(Base.url_decode64!(share_slug, padding: false))
    password_protected = fetch_attr!(attrs, "password_protected")

    password_capability_secret_commitment =
      Map.get(attrs, "password_capability_secret_commitment") ||
        if(password_protected,
          do: Hash.blake3_base64url("test-password-capability:" <> share_id),
          else: "none"
        )

    max_views = share_positive_integer_or_default!(attrs, "max_views")
    expires_event_sequence = share_positive_integer_or_default!(attrs, "expires_event_sequence")

    password_auth_metadata_hash = password_auth_metadata_hash(attrs, password_protected)

    redeem_authority_policy =
      if(password_protected, do: "password_challenge", else: "capability_url")

    capability_context_hash =
      Capability.hash!(%{
        workspace_id: document.workspace_id,
        share_id: share_id,
        scope_kind: fetch_attr!(attrs, "scope"),
        scope_id: document.id,
        token_hash: token_hash,
        permission: fetch_attr!(attrs, "permission"),
        password_protected: password_protected,
        share_capability_secret_commitment:
          fetch_attr!(attrs, "share_capability_secret_commitment"),
        password_auth_metadata_hash: password_auth_metadata_hash,
        password_capability_secret_commitment: password_capability_secret_commitment,
        workspace_pin_bootstrap_hash:
          fetch_attr!(attrs, "authenticated_workspace_pin_bootstrap_hash"),
        authenticated_bootstrap_source: "url-fragment",
        max_views: max_views,
        redeem_authority_policy: redeem_authority_policy
      })

    body = %{
      "workspace_id" => document.workspace_id,
      "share_id" => share_id,
      "scope_kind" => fetch_attr!(attrs, "scope"),
      "scope_id" => document.id,
      "permission" => fetch_attr!(attrs, "permission"),
      "share_key_version" => 1,
      "password_protected" => password_protected,
      "authorization_public_key_material" =>
        fetch_attr!(attrs, "authorization_public_key_material"),
      "authorization_public_key_material_hash" =>
        Hash.blake3_base64url(
          JCS.canonical_bytes!(fetch_attr!(attrs, "authorization_public_key_material"))
        ),
      "share_capability_secret_commitment" =>
        fetch_attr!(attrs, "share_capability_secret_commitment"),
      "password_capability_secret_commitment" => password_capability_secret_commitment,
      "password_auth_metadata_hash" => password_auth_metadata_hash,
      "max_views" => max_views,
      "expires_event_sequence" => expires_event_sequence,
      "redeem_authority_policy" => redeem_authority_policy,
      "capability_context_hash" => capability_context_hash
    }

    append =
      share_created_key_directory_append(
        document.workspace_id,
        owner_id,
        actor_device,
        actor_private,
        body
      )

    {backup_wraps, wrap_events, final_checkpoint} =
      document.workspace_id
      |> test_share_link_secret_backup_recipient_devices()
      |> Enum.reduce(
        {[], [], append["workspace_key_directory_checkpoint"]},
        fn recipient_device, {wrap_acc, event_acc, checkpoint} ->
          {backup_wrap_attrs, wrap_event} =
            share_link_secret_backup_wrap(%{
              document: document,
              attrs: attrs,
              body: body,
              token_hash: token_hash,
              actor_device: actor_device,
              actor_private: actor_private,
              recipient_device: recipient_device,
              share_created_event: hd(append["workspace_key_directory_events"]),
              checkpoint: checkpoint,
              password_capability_secret_commitment: password_capability_secret_commitment
            })

          next_checkpoint =
            checkpoint["payload"]
            |> Map.put("covered_event_head", event_head(wrap_event["payload"]))
            |> Map.put(
              "authority_boundary",
              test_key_directory_checkpoint_authority_boundary(%{
                "sequence" => checkpoint["payload"]["sequence"] + 1
              })
            )
            |> key_directory_checkpoint_payload!()
            |> signed_key_directory_checkpoint(
              "workspace_authorized",
              actor_private,
              owner_id
            )

          backup_wrap =
            backup_wrap_attrs
            |> put_operation_checkpoint!(next_checkpoint["payload"])
            |> put_signed_pq_wrap_signature(
              actor_private,
              hybrid_signing_public_key_material(actor_private)
            )
            |> SignedPQ.response_fields()
            |> Jason.encode!()
            |> Jason.decode!()

          {[backup_wrap | wrap_acc], [wrap_event | event_acc], next_checkpoint}
        end
      )

    final_events = append["workspace_key_directory_events"] ++ Enum.reverse(wrap_events)

    attrs
    |> Map.put("actor_device_id", actor_device.id)
    |> Map.put("max_views", max_views)
    |> Map.put("expires_event_sequence", expires_event_sequence)
    |> Map.put("password_capability_secret_commitment", password_capability_secret_commitment)
    |> Map.put("workspace_key_directory_events", final_events)
    |> Map.put("workspace_key_directory_checkpoint", final_checkpoint)
    |> Map.put("share_link_secret_backup_wraps", Enum.reverse(backup_wraps))
  end

  defp put_test_share_key_versions(attrs, key_version) do
    attrs
    |> put_default_test_key_version(key_version)
    |> update_test_folder_share_key_versions(key_version)
  end

  defp put_default_test_key_version(attrs, key_version) do
    if Map.has_key?(attrs, "key_version") or Map.has_key?(attrs, :key_version) do
      attrs
    else
      Map.put(attrs, "key_version", key_version)
    end
  end

  defp update_test_folder_share_key_versions(attrs, key_version) do
    cond do
      Map.has_key?(attrs, "share_keys") ->
        Map.update!(
          attrs,
          "share_keys",
          &Enum.map(&1, fn entry ->
            put_default_test_key_version(entry, key_version)
          end)
        )

      Map.has_key?(attrs, :share_keys) ->
        Map.update!(
          attrs,
          :share_keys,
          &Enum.map(&1, fn entry ->
            put_default_test_key_version(entry, key_version)
          end)
        )

      true ->
        attrs
    end
  end

  defp test_share_link_secret_backup_recipient_devices(workspace_id) do
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)

    checkpoint_device_key_ids =
      checkpoint.payload
      |> Map.get("device_keys", [])
      |> Enum.map(& &1["key_id"])
      |> MapSet.new()

    role_by_id =
      workspace_id
      |> RefMD.Workspaces.list_workspace_roles()
      |> Map.new(&{&1.id, &1})

    from(d in RefMD.Devices.Device,
      join: wm in RefMD.Workspaces.WorkspaceMember,
      on: wm.user_id == d.user_id and wm.workspace_id == ^workspace_id,
      where: is_nil(d.revoked_at),
      select: %{device: d, role_id: wm.role_id}
    )
    |> Repo.all()
    |> Enum.filter(fn %{device: device, role_id: role_id} ->
      permissions =
        role_by_id
        |> Map.fetch!(role_id)
        |> RefMD.Workspaces.effective_permissions()

      MapSet.member?(checkpoint_device_key_ids, device.encryption_key_id) and
        (MapSet.member?(permissions, "document:manage_share") or
           MapSet.member?(permissions, "workspace:admin"))
    end)
    |> Enum.map(& &1.device)
  end

  def with_test_share_management_append(
        %RefMD.Sharing.Share{} = share,
        event_type,
        attrs \\ %{}
      ) do
    workspace_id = share_workspace_id!(share)
    ensure_test_workspace_actor_material!(workspace_id, share.created_by)

    events =
      [
        %{
          "event_type" => event_type,
          "body" => fn sequence ->
            share_management_event_body(workspace_id, share.id, event_type, attrs, sequence)
          end
        }
      ] ++ share_scope_removed_events(workspace_id, share.id, event_type, attrs)

    attrs
    |> Map.merge(signed_workspace_key_directory_append(workspace_id, share.created_by, events))
  end

  def with_test_share_scope_key_directory_append(%RefMD.Sharing.Share{} = share, attrs) do
    with_test_share_scope_key_directory_append(share, attrs, nil)
  end

  def with_test_share_scope_key_directory_append(
        %RefMD.Sharing.Share{} = share,
        attrs,
        base_checkpoint
      ) do
    workspace_id = share_workspace_id!(share)
    ensure_test_workspace_actor_material!(workspace_id, share.created_by)

    events =
      share_scope_entries(attrs, "add_keys", :add_keys)
      |> Enum.map(fn entry ->
        %{
          "event_type" => "share_key_scope_added",
          "body" => fn sequence ->
            share_scope_event_body(
              workspace_id,
              share.id,
              "share_key_scope_added",
              entry,
              sequence
            )
          end
        }
      end)
      |> Kernel.++(
        attrs
        |> share_scope_entries("replace_keys", :replace_keys)
        |> Enum.map(fn entry ->
          %{
            "event_type" => "share_key_scope_replaced",
            "body" => fn sequence ->
              share_scope_event_body(
                workspace_id,
                share.id,
                "share_key_scope_replaced",
                entry,
                sequence
              )
            end
          }
        end)
      )

    append =
      if base_checkpoint do
        signed_workspace_key_directory_append_after(
          workspace_id,
          share.created_by,
          base_checkpoint,
          events
        )
      else
        signed_workspace_key_directory_append(workspace_id, share.created_by, events)
      end

    Map.merge(attrs, append)
  end

  defp share_scope_entries(attrs, string_key, atom_key) do
    case Map.get(attrs, string_key) || Map.get(attrs, atom_key) do
      entries when is_list(entries) -> entries
      _ -> []
    end
  end

  defp share_management_event_body(workspace_id, share_id, "share_revoked", _attrs, sequence) do
    %{
      "workspace_id" => workspace_id,
      "share_id" => share_id,
      "revoked_at_event_sequence" => sequence,
      "reason" => "manual"
    }
  end

  defp share_management_event_body(
         workspace_id,
         share_id,
         "share_exclusion_changed",
         attrs,
         sequence
       ) do
    %{
      "workspace_id" => workspace_id,
      "share_id" => share_id,
      "added_scope_hashes" => scope_hashes(workspace_id, attrs, "add", :add),
      "removed_scope_hashes" => scope_hashes(workspace_id, attrs, "remove", :remove),
      "changed_at_event_sequence" => sequence,
      "exclusion_change_nonce" => Encoding.encode_base64url(:crypto.strong_rand_bytes(32))
    }
  end

  defp share_management_event_body(
         workspace_id,
         share_id,
         "share_metadata_updated",
         attrs,
         sequence
       ) do
    %{
      "workspace_id" => workspace_id,
      "share_id" => share_id,
      "expires_event_sequence" => share_update_expires_sequence(attrs),
      "max_views" => share_positive_integer_or_default!(attrs, "max_views"),
      "updated_at_event_sequence" => sequence,
      "metadata_update_nonce" => Encoding.encode_base64url(:crypto.strong_rand_bytes(32))
    }
  end

  defp share_scope_removed_events(workspace_id, share_id, "share_exclusion_changed", attrs) do
    attrs
    |> scope_ids("add", :add)
    |> Enum.map(fn document_id ->
      %{
        "event_type" => "share_key_scope_removed",
        "body" => fn sequence ->
          share_scope_removed_event_body(workspace_id, share_id, document_id, sequence)
        end
      }
    end)
  end

  defp share_scope_removed_events(_workspace_id, _share_id, _event_type, _attrs), do: []

  defp share_scope_removed_event_body(workspace_id, share_id, document_id, sequence) do
    document = document_for_share_scope(document_id)

    %{
      "workspace_id" => workspace_id,
      "share_id" => share_id,
      "share_key_version" => 1,
      "scope_kind" => (document && document.doc_type) || "document",
      "scope_id" => document_id,
      "document_scope_hash" => document_scope_hash(workspace_id, document_id),
      "removed_reason" => "share_exclusion_added",
      "removed_at_event_sequence" => sequence,
      "previous_share_scope_event_hash" => document_scope_hash(workspace_id, document_id)
    }
  end

  defp share_scope_event_body(workspace_id, parent_share_id, event_type, entry, sequence)
       when is_map(entry) do
    document_id = share_scope_entry_value(entry, "document_id", :document_id)
    document = document_for_share_scope(document_id)
    key_version = share_scope_entry_value(entry, "key_version", :key_version, 1)

    base = %{
      "workspace_id" => workspace_id,
      "share_id" => share_scope_entry_value(entry, "share_id", :share_id),
      "scope_kind" => (document && document.doc_type) || "document",
      "scope_id" => document_id || Ecto.UUID.generate(),
      "document_scope_hash" => document_scope_hash(workspace_id, document_id),
      "share_metadata_hash" => share_scope_metadata_hash(entry),
      "share_key_version" => key_version
    }

    case event_type do
      "share_key_scope_added" ->
        base
        |> Map.put("parent_share_id", parent_share_id)
        |> Map.put("added_at_event_sequence", sequence)

      "share_key_scope_replaced" ->
        base
        |> Map.put("previous_share_key_version", max(key_version - 1, 1))
        |> Map.put("replaced_at_event_sequence", sequence)
    end
  end

  defp share_scope_event_body(workspace_id, parent_share_id, event_type, _entry, sequence) do
    share_scope_event_body(
      workspace_id,
      parent_share_id,
      event_type,
      %{"share_id" => nil, "document_id" => nil},
      sequence
    )
  end

  defp share_scope_entry_value(entry, string_key, atom_key, default \\ nil) do
    case Map.get(entry, string_key) do
      nil -> Map.get(entry, atom_key, default)
      value -> value
    end
  end

  defp scope_hashes(workspace_id, attrs, string_key, atom_key) do
    attrs
    |> share_scope_entries(string_key, atom_key)
    |> Enum.map(&document_scope_hash(workspace_id, &1))
  end

  defp scope_ids(attrs, string_key, atom_key) do
    share_scope_entries(attrs, string_key, atom_key)
  end

  defp document_for_share_scope(document_id) when is_binary(document_id) do
    Repo.get(Document, document_id)
  end

  defp document_for_share_scope(_document_id), do: nil

  defp document_scope_hash(workspace_id, document_id) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "workspace_id" => workspace_id,
        "document_id" => document_id || "unknown"
      })
    )
  end

  defp share_scope_metadata_hash(entry) do
    encrypted_dek = Map.get(entry, "encrypted_dek") || Map.get(entry, :encrypted_dek)
    nonce = Map.get(entry, "nonce") || Map.get(entry, :nonce)

    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "share_id" => Map.get(entry, "share_id") || Map.get(entry, :share_id),
        "encrypted_dek_hash" => encode_test_binary_hash(encrypted_dek, 48),
        "nonce_hash" => encode_test_binary_hash(nonce, 24)
      })
    )
  end

  defp encode_test_binary_hash(value, expected_bytes) when is_binary(value) do
    decoded =
      try do
        Encoding.decode_base64url!(value, expected_bytes)
      rescue
        _ -> value
      end

    Hash.blake3_base64url(decoded)
  end

  defp encode_test_binary_hash(_value, _expected_bytes), do: "missing"

  defp share_update_expires_sequence(attrs) do
    case Map.get(attrs, "expires_event_sequence") || Map.get(attrs, :expires_event_sequence) do
      nil ->
        @max_safe_integer

      value when is_integer(value) ->
        if value > 0, do: value, else: raise(ArgumentError, "expires_event_sequence_invalid")

      _ ->
        raise ArgumentError, "expires_event_sequence_invalid"
    end
  end

  defp share_positive_integer_or_default!(attrs, field) do
    case Map.get(attrs, field) || Map.get(attrs, String.to_existing_atom(field)) do
      nil -> @max_safe_integer
      value when is_integer(value) and value > 0 -> value
      _ -> raise ArgumentError, "#{field}_invalid"
    end
  end

  def test_dek_rotation_start_key_directory_append(
        workspace_id,
        actor_user_id,
        document_id,
        old_key_version,
        new_key_version,
        reason \\ "time_based"
      ) do
    ensure_test_workspace_actor_material!(workspace_id, actor_user_id)

    signed_workspace_key_directory_append(workspace_id, actor_user_id, [
      %{
        "event_type" => "rotation_started",
        "body" => fn sequence ->
          %{
            "event_type" => "rotation_started",
            "rotation_kind" => "dek",
            "scope_kind" => "document",
            "scope_id" => document_id,
            "old_key_version" => old_key_version,
            "new_key_version" => new_key_version,
            "not_before_event_sequence" => sequence,
            "reason" => reason
          }
        end
      }
    ])
  end

  defp signed_workspace_key_directory_append(workspace_id, actor_user_id, event_specs) do
    {actor_device, actor_private} = test_share_actor_device!(actor_user_id)
    actor_public = hybrid_signing_public_key_material(actor_private)
    actor_signing_key_id = Signature.compute_signing_key_id!(actor_public)
    actor = device_actor(actor_user_id, actor_device.id, actor_signing_key_id)

    {events, _previous_hash, _sequence} =
      Enum.reduce(
        event_specs,
        {[], current_workspace_event_hash(workspace_id),
         current_workspace_event_sequence(workspace_id)},
        fn
          %{"event_type" => event_type, "body" => body}, {acc, previous_hash, sequence} ->
            event_sequence = sequence + 1
            body = if is_function(body, 1), do: body.(event_sequence), else: body

            event =
              key_directory_event(%{
                "scope_kind" => "workspace",
                "scope_id" => workspace_id,
                "sequence" => event_sequence,
                "event_type" => event_type,
                "actor" => actor,
                "previous_event_hash" => previous_hash,
                "body" => body
              })

            {[event | acc], KeyDirectory.event_hash(event), event_sequence}
        end
      )

    signed_workspace_key_directory_append_from_events(
      workspace_id,
      actor_user_id,
      actor_private,
      Enum.reverse(events)
    )
  end

  defp signed_workspace_key_directory_append_after(
         workspace_id,
         actor_user_id,
         %{"payload" => checkpoint_payload},
         event_specs
       ) do
    {actor_device, actor_private} = test_share_actor_device!(actor_user_id)
    actor_public = hybrid_signing_public_key_material(actor_private)
    actor_signing_key_id = Signature.compute_signing_key_id!(actor_public)
    actor = device_actor(actor_user_id, actor_device.id, actor_signing_key_id)
    head = checkpoint_payload["covered_event_head"]

    {events, _previous_hash, _sequence} =
      Enum.reduce(
        event_specs,
        {[], head["head_hash"], head["head_sequence"]},
        fn %{"event_type" => event_type, "body" => body}, {acc, previous_hash, sequence} ->
          event_sequence = sequence + 1
          body = if is_function(body, 1), do: body.(event_sequence), else: body

          event =
            key_directory_event(%{
              "scope_kind" => "workspace",
              "scope_id" => workspace_id,
              "sequence" => event_sequence,
              "event_type" => event_type,
              "actor" => actor,
              "previous_event_hash" => previous_hash,
              "body" => body
            })

          {[event | acc], KeyDirectory.event_hash(event), event_sequence}
        end
      )

    events = Enum.reverse(events)
    last_event = List.last(events)

    next_checkpoint_payload =
      checkpoint_payload
      |> Map.put("sequence", checkpoint_payload["sequence"] + 1)
      |> Map.put(
        "issued_at",
        DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
      )
      |> Map.put("previous_checkpoint_hash", KeyDirectory.checkpoint_hash(checkpoint_payload))
      |> Map.put("covered_event_head", event_head(last_event))
      |> key_directory_checkpoint_payload!()

    %{
      "workspace_key_directory_events" =>
        Enum.map(events, &signed_key_directory_event(&1, actor_private)),
      "workspace_key_directory_checkpoint" =>
        signed_key_directory_checkpoint(
          next_checkpoint_payload,
          "workspace_authorized",
          actor_private,
          actor_user_id
        )
    }
  end

  defp signed_workspace_key_directory_append_from_events(
         workspace_id,
         _actor_user_id,
         _actor_private,
         []
       ) do
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)

    %{
      "workspace_key_directory_events" => [],
      "workspace_key_directory_checkpoint" => %{
        "payload" => checkpoint.payload,
        "signatures" => checkpoint.signatures
      }
    }
  end

  defp signed_workspace_key_directory_append_from_events(
         workspace_id,
         actor_user_id,
         actor_private,
         events
       ) do
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    last_event = List.last(events)

    checkpoint_payload =
      key_directory_checkpoint_payload!(
        checkpoint.payload
        |> Map.put("sequence", checkpoint.sequence + 1)
        |> Map.put(
          "issued_at",
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
        )
        |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
        |> Map.put("covered_event_head", event_head(last_event))
      )

    %{
      "workspace_key_directory_events" =>
        Enum.map(events, &signed_key_directory_event(&1, actor_private)),
      "workspace_key_directory_checkpoint" =>
        signed_key_directory_checkpoint(
          checkpoint_payload,
          "workspace_authorized",
          actor_private,
          actor_user_id
        )
    }
  end

  defp current_workspace_event_hash(workspace_id) do
    KeyDirectory.current_pin("workspace", workspace_id).event_head_hash
  end

  defp current_workspace_event_sequence(workspace_id) do
    KeyDirectory.current_pin("workspace", workspace_id).event_head_sequence
  end

  defp share_workspace_id!(%RefMD.Sharing.Share{document_id: document_id}) do
    Repo.get!(Document, document_id).workspace_id
  end

  defp ensure_test_workspace_actor_material!(workspace_id, user_id) do
    case Process.get({:test_workspace_actor_material, user_id}) do
      nil -> provision_test_workspace_actor_material!(workspace_id, user_id)
      _material -> :ok
    end
  end

  defp provision_test_workspace_actor_material!(workspace_id, user_id) do
    signer =
      Process.get({:test_workspace_signer_material, workspace_id}) ||
        raise "test workspace signer material missing"

    {_member, role} = RefMD.Workspaces.get_member_with_role(workspace_id, user_id)
    device_id = Ecto.UUID.generate()
    device_private = hybrid_signing_private_key_material("device", device_id)
    {device_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)

    device_encryption_public =
      hybrid_encryption_public_key_material("device", device_id, device_x25519_public).public

    actor_material = %{
      user_id: user_id,
      device_id: device_id,
      signing_private: device_private,
      signing_public: hybrid_signing_public_key_material(device_private),
      encryption_public: device_encryption_public,
      x25519_public_key: device_x25519_public,
      mlkem768_public_key:
        Encoding.decode_base64url!(device_encryption_public["mlkem768_public"], 1184),
      encryption_key_id: HybridEncryptionMaterial.compute_key_id!(device_encryption_public)
    }

    append_test_workspace_actor_material!(workspace_id, user_id, role, actor_material, signer)
    Process.put({:test_workspace_actor_material, user_id}, actor_material)
    :ok
  end

  defp append_test_workspace_actor_material!(workspace_id, user_id, role, material, signer) do
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    signer_signing_key_id = Signature.compute_signing_key_id!(signer.signing_public)
    actor = device_actor(signer.user_id, signer.device_id, signer_signing_key_id)
    device_signing_key_id = Signature.compute_signing_key_id!(material.signing_public)

    device_event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => pin.event_head_sequence + 1,
        "event_type" => "device_key_added",
        "actor" => actor,
        "previous_event_hash" => pin.event_head_hash,
        "body" => %{
          "user_id" => user_id,
          "device_id" => material.device_id,
          "signing_key_id" => device_signing_key_id,
          "encryption_key_id" => material.encryption_key_id
        }
      })

    member_event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => pin.event_head_sequence + 2,
        "event_type" => "member_added",
        "actor" => actor,
        "previous_event_hash" => KeyDirectory.event_hash(device_event),
        "body" => %{
          "workspace_id" => workspace_id,
          "user_id" => user_id,
          "role_id" => role.id,
          "base_role" => role.base_role,
          "workspace_member_envelope_hash" =>
            Hash.blake3_base64url("test-member-envelope:#{workspace_id}:#{user_id}")
        }
      })

    checkpoint_payload =
      key_directory_checkpoint_payload!(
        checkpoint.payload
        |> Map.put("sequence", checkpoint.sequence + 1)
        |> Map.put(
          "issued_at",
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
        )
        |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
        |> Map.put("covered_event_head", event_head(member_event))
        |> Map.put("device_keys", [
          Payload.key_entry!(
            material.signing_public,
            event_ref("workspace", workspace_id, device_event)
          ),
          Payload.key_entry!(
            material.encryption_public,
            event_ref("workspace", workspace_id, device_event)
          )
          | Map.get(checkpoint.payload, "device_keys", [])
        ])
      )

    KeyDirectory.append_signed_scope!(
      "workspace",
      workspace_id,
      [
        signed_key_directory_event(device_event, signer.signing_private),
        signed_key_directory_event(member_event, signer.signing_private)
      ],
      signed_key_directory_checkpoint(
        checkpoint_payload,
        "workspace_authorized",
        signer.signing_private,
        signer.user_id
      ),
      checkpoint_signer_kind: "device"
    )
  end

  defp fetch_attr!(attrs, key), do: Map.fetch!(attrs, key)

  defp password_auth_metadata_hash(_attrs, false), do: "none"

  defp password_auth_metadata_hash(attrs, true) do
    share_id = Map.fetch!(attrs, "id")

    server_auth_key_wrap_aad_hash =
      Hash.blake3_base64url(
        JCS.canonical_bytes!(%{
          "protocol" => "refmd",
          "version" => 1,
          "purpose" => "server_auth_key_wrap",
          "share_id" => share_id
        })
      )

    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "protocol" => "refmd.password-auth-metadata-public",
        "version" => 1,
        "share_id" => share_id,
        "auth_scheme" => "argon2id-hmac-authkey",
        "salt" => Encoding.encode_base64url(test_salt_bytes!(Map.fetch!(attrs, "salt"))),
        "kdf_params" => Map.fetch!(attrs, "kdf_params"),
        "server_auth_key_wrap_aad_hash" => server_auth_key_wrap_aad_hash
      })
    )
  end

  defp test_salt_bytes!(salt) when is_binary(salt) and byte_size(salt) == 16, do: salt
  defp test_salt_bytes!(salt) when is_binary(salt), do: Encoding.decode_base64url!(salt, 16)

  defp test_share_actor_device!(user_id) do
    case Process.get({:test_share_actor_device, user_id}) do
      {%RefMD.Devices.Device{} = device, private} ->
        {device, private}

      _ ->
        material =
          Process.get({:test_workspace_actor_material, user_id}) ||
            raise "test workspace actor material missing"

        device_id = material.device_id
        client_nonce = :crypto.strong_rand_bytes(16)

        device =
          RefMD.Devices.get_device(device_id) ||
            case RefMD.Devices.create_device(%{
                   id: device_id,
                   user_id: user_id,
                   name: "Share test actor",
                   device_type: "browser",
                   hybrid_encryption_public_key_material: material.encryption_public,
                   encryption_key_id: material.encryption_key_id,
                   hybrid_signing_public_key_material: material.signing_public,
                   signing_key_id: Signature.compute_signing_key_id!(material.signing_public),
                   approval_signature:
                     genesis_device_bootstrap_signature(
                       user_id,
                       device_id,
                       material.signing_public,
                       material.x25519_public_key,
                       material.encryption_public,
                       client_nonce
                     ),
                   approval_signature_surface: "genesis_device_bootstrap",
                   approval_proof:
                     genesis_device_approval_proof(
                       user_id,
                       device_id,
                       material.signing_public,
                       material.x25519_public_key,
                       material.encryption_public,
                       client_nonce
                     ),
                   client_nonce: client_nonce
                 }) do
              {:ok, created} -> created
              {:error, changeset} -> raise inspect(changeset)
            end

        Process.put({:test_share_actor_device, user_id}, {device, material.signing_private})
        {device, material.signing_private}
    end
  end

  defp share_created_key_directory_append(
         workspace_id,
         actor_user_id,
         actor_device,
         actor_private,
         body
       ) do
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    actor_public = hybrid_signing_public_key_material(actor_private)
    actor_signing_key_id = Signature.compute_signing_key_id!(actor_public)

    event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => pin.event_head_sequence + 1,
        "event_type" => "share_created",
        "actor" => device_actor(actor_user_id, actor_device.id, actor_signing_key_id),
        "previous_event_hash" => pin.event_head_hash,
        "body" => body
      })

    checkpoint_payload =
      key_directory_checkpoint_payload!(
        checkpoint.payload
        |> Map.put("sequence", checkpoint.sequence + 1)
        |> Map.put(
          "issued_at",
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
        )
        |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
        |> Map.put("covered_event_head", event_head(event))
      )

    %{
      "workspace_key_directory_events" => [signed_key_directory_event(event, actor_private)],
      "workspace_key_directory_checkpoint" =>
        signed_key_directory_checkpoint(
          checkpoint_payload,
          "workspace_authorized",
          actor_private,
          actor_user_id
        )
    }
  end

  def signed_workspace_device_kek_request(
        workspace_id,
        sender_device,
        sender_private,
        target_device,
        key_version
      ) do
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    sender_public = hybrid_signing_public_key_material(sender_private)
    sender_signing_key_id = Signature.compute_signing_key_id!(sender_public)
    checkpoint_hash = checkpoint.checkpoint_hash

    sender =
      device_actor(sender_device.user_id, sender_device.id, sender_signing_key_id)
      |> Map.put("key_scope_kind", "workspace")
      |> Map.put("key_scope_id", workspace_id)
      |> Map.put("key_checkpoint_sequence", checkpoint.sequence)
      |> Map.put("key_checkpoint_hash", checkpoint_hash)

    recipient = %{
      "recipient_kind" => "device",
      "user_id" => target_device.user_id,
      "device_id" => target_device.id,
      "encryption_key_id" => target_device.encryption_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id,
      "key_checkpoint_sequence" => checkpoint.sequence,
      "key_checkpoint_hash" => checkpoint_hash
    }

    attrs =
      %{
        wrap_protocol: "refmd.signed-pq-hybrid-wrap",
        wrap_version: 1,
        suite_id: @signed_pq_wrap_suite_id,
        suite_rank: @suite_rank,
        kem_id: 0x647A,
        kdf_id: 0x0001,
        aead_id: 0x0003,
        purpose: "workspace_device_kek_wrap",
        resource: %{
          "workspace_id" => workspace_id,
          "target_user_id" => target_device.user_id,
          "target_device_id" => target_device.id,
          "kek_version" => key_version
        },
        sender: sender,
        recipient: recipient,
        event_scope: %{"scope_kind" => "workspace", "scope_id" => workspace_id},
        recipient_key_id: Encoding.decode_base64url!(target_device.encryption_key_id, 32),
        sender_signing_key_id: Encoding.decode_base64url!(sender_signing_key_id, 32),
        hpke_enc: :crypto.strong_rand_bytes(1120),
        hpke_ciphertext: :crypto.strong_rand_bytes(48),
        signature_protocol: @signature_protocol,
        signature_version: @protocol_version,
        signature_suite_id: @suite_id,
        signature_suite_rank: @suite_rank,
        operation_checkpoint_sequence: checkpoint.sequence,
        operation_checkpoint_hash: Encoding.decode_base64url!(checkpoint_hash, 32),
        operation_checkpoint_covered_head_sequence:
          checkpoint.payload["covered_event_head"]["head_sequence"],
        operation_checkpoint_covered_head_hash:
          Encoding.decode_base64url!(
            checkpoint.payload["covered_event_head"]["head_hash"],
            32
          ),
        wrap_event_sequence: checkpoint.payload["covered_event_head"]["head_sequence"] + 1
      }
      |> put_signed_pq_wrap_hashes()

    event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => attrs.wrap_event_sequence,
        "event_type" => "wrap_issued",
        "actor" => attrs.sender,
        "authority_boundary" => signed_pq_wrap_event_authority_boundary(attrs),
        "previous_event_hash" =>
          Encoding.encode_base64url(attrs.operation_checkpoint_covered_head_hash),
        "body" => signed_pq_wrap_event_body(attrs)
      })

    signed_event = signed_key_directory_event(event, sender_private)

    checkpoint_payload =
      checkpoint.payload
      |> Map.put("sequence", checkpoint.sequence + 1)
      |> Map.put(
        "issued_at",
        DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
      )
      |> Map.put("previous_checkpoint_hash", checkpoint_hash)
      |> Map.put("covered_event_head", event_head(event))
      |> key_directory_checkpoint_payload!()

    signed_checkpoint =
      signed_key_directory_checkpoint(
        checkpoint_payload,
        "workspace_authorized",
        sender_private,
        sender_device.user_id
      )

    attrs
    |> put_operation_checkpoint!(signed_checkpoint["payload"])
    |> put_signed_pq_wrap_signature(sender_private, sender_public)
    |> SignedPQ.response_fields()
    |> Map.merge(%{
      target_user_id: target_device.user_id,
      device_id: target_device.id,
      sender_device_id: sender_device.id,
      key_version: key_version,
      is_active: true,
      workspace_key_directory_events: [signed_event],
      workspace_key_directory_checkpoint: signed_checkpoint
    })
    |> Jason.encode!()
    |> Jason.decode!()
  end

  def append_test_workspace_member_device!(workspace_id, user_id, device) do
    {_member, role} = RefMD.Workspaces.get_member_with_role(workspace_id, user_id)

    append_test_workspace_actor_material!(
      workspace_id,
      user_id,
      role,
      %{
        user_id: user_id,
        device_id: device.id,
        signing_public: device.hybrid_signing_public_key_material,
        encryption_public: device.hybrid_encryption_public_key_material,
        encryption_key_id: device.encryption_key_id
      },
      Process.get({:test_workspace_signer_material, workspace_id}) ||
        raise("test workspace signer material missing")
    )
  end

  defp share_link_secret_backup_wrap(params) do
    actor_device = params.actor_device
    actor_private = params.actor_private
    recipient_device = Map.get(params, :recipient_device, actor_device)
    actor_public = hybrid_signing_public_key_material(actor_private)
    sender_signing_key_id = Signature.compute_signing_key_id!(actor_public)
    recipient_key_id = Encoding.decode_base64url!(recipient_device.encryption_key_id, 32)
    checkpoint = params.checkpoint["payload"]
    share_event = params.share_created_event["payload"]
    event_scope = %{"scope_kind" => "workspace", "scope_id" => params.document.workspace_id}

    resource = %{
      "workspace_id" => params.document.workspace_id,
      "share_id" => params.body["share_id"],
      "token_hash" => params.token_hash,
      "scope_kind" => params.body["scope_kind"],
      "scope_id" => params.document.id,
      "permission" => params.body["permission"],
      "password_protected" => params.body["password_protected"],
      "created_event_hash" => KeyDirectory.event_hash(share_event),
      "share_capability_secret_commitment" => params.body["share_capability_secret_commitment"],
      "password_capability_secret_commitment" => params.password_capability_secret_commitment,
      "workspace_pin_bootstrap_hash" =>
        params.body["capability_context_hash"] &&
          params.attrs["authenticated_workspace_pin_bootstrap_hash"],
      "key_checkpoint_hash" => KeyDirectory.checkpoint_hash(checkpoint),
      "recipient_user_id" => recipient_device.user_id,
      "recipient_device_id" => recipient_device.id,
      "recipient_encryption_key_id" => recipient_device.encryption_key_id
    }

    sender =
      device_actor(actor_device.user_id, actor_device.id, sender_signing_key_id)
      |> Map.put("key_scope_kind", "workspace")
      |> Map.put("key_scope_id", params.document.workspace_id)
      |> Map.put("key_checkpoint_sequence", checkpoint["sequence"])
      |> Map.put("key_checkpoint_hash", KeyDirectory.checkpoint_hash(checkpoint))

    recipient = %{
      "recipient_kind" => "device",
      "user_id" => recipient_device.user_id,
      "device_id" => recipient_device.id,
      "encryption_key_id" => recipient_device.encryption_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => params.document.workspace_id,
      "key_checkpoint_sequence" => checkpoint["sequence"],
      "key_checkpoint_hash" => KeyDirectory.checkpoint_hash(checkpoint)
    }

    attrs =
      %{
        wrap_protocol: "refmd.signed-pq-hybrid-wrap",
        wrap_version: 1,
        suite_id: @signed_pq_wrap_suite_id,
        suite_rank: @suite_rank,
        kem_id: 0x647A,
        kdf_id: 0x0001,
        aead_id: 0x0003,
        purpose: "share_link_secret_backup_wrap",
        resource: resource,
        sender: sender,
        recipient: recipient,
        event_scope: event_scope,
        recipient_key_id: recipient_key_id,
        sender_signing_key_id: Encoding.decode_base64url!(sender_signing_key_id, 32),
        hpke_enc: :crypto.strong_rand_bytes(1120),
        hpke_ciphertext: :crypto.strong_rand_bytes(48),
        signature_protocol: @signature_protocol,
        signature_version: @protocol_version,
        signature_suite_id: @suite_id,
        signature_suite_rank: @suite_rank,
        operation_checkpoint_sequence: checkpoint["sequence"],
        operation_checkpoint_hash:
          Encoding.decode_base64url!(
            KeyDirectory.checkpoint_hash(checkpoint),
            32
          ),
        operation_checkpoint_covered_head_sequence:
          checkpoint["covered_event_head"]["head_sequence"],
        operation_checkpoint_covered_head_hash:
          Encoding.decode_base64url!(checkpoint["covered_event_head"]["head_hash"], 32),
        wrap_event_sequence: checkpoint["covered_event_head"]["head_sequence"] + 1
      }
      |> put_signed_pq_wrap_hashes()

    wrap_event =
      key_directory_event(%{
        "scope_kind" => attrs.event_scope["scope_kind"],
        "scope_id" => attrs.event_scope["scope_id"],
        "sequence" => attrs.wrap_event_sequence,
        "event_type" => "wrap_issued",
        "actor" => attrs.sender,
        "authority_boundary" => signed_pq_wrap_event_authority_boundary(attrs),
        "previous_event_hash" =>
          Encoding.encode_base64url(attrs.operation_checkpoint_covered_head_hash),
        "body" => signed_pq_wrap_event_body(attrs)
      })

    {attrs, signed_key_directory_event(wrap_event, actor_private)}
  end

  defp put_operation_checkpoint!(attrs, checkpoint) do
    attrs
    |> Map.put(:operation_checkpoint_sequence, checkpoint["sequence"])
    |> Map.put(
      :operation_checkpoint_hash,
      Encoding.decode_base64url!(KeyDirectory.checkpoint_hash(checkpoint), 32)
    )
    |> Map.put(
      :operation_checkpoint_covered_head_sequence,
      checkpoint["covered_event_head"]["head_sequence"]
    )
    |> Map.put(
      :operation_checkpoint_covered_head_hash,
      Encoding.decode_base64url!(checkpoint["covered_event_head"]["head_hash"], 32)
    )
  end

  defp put_signed_pq_wrap_signature(attrs, actor_private, actor_public) do
    transcript =
      Signature.build_pq_wrap_transcript!(
        attrs.sender["device_id"],
        attrs.sender,
        signed_pq_wrap_authority_boundary(attrs),
        signed_pq_wrap_subject_hashes(attrs)
      )

    signature = sign_transcript(actor_private, actor_public, "pq_wrap", transcript)

    attrs
    |> Map.put(:transcript_hash, Encoding.decode_base64url!(signature["transcript_hash"], 32))
    |> Map.put(:ed25519_signature, Encoding.decode_base64url!(signature["ed25519"], 64))
    |> Map.put(:mldsa65_signature, Encoding.decode_base64url!(signature["mldsa65"], 3309))
  end

  defp put_signed_pq_wrap_hashes(attrs) do
    body = signed_pq_wrap_body(attrs)
    wrap_body_hash = Hash.blake3_base64url(JCS.canonical_bytes!(body))
    attrs = Map.put(attrs, :wrap_body_hash, Encoding.decode_base64url!(wrap_body_hash, 32))
    event_body = signed_pq_wrap_event_body(attrs)
    event_body_hash = Hash.blake3_base64url(JCS.canonical_bytes!(event_body))

    event =
      key_directory_event(%{
        "scope_kind" => attrs.event_scope["scope_kind"],
        "scope_id" => attrs.event_scope["scope_id"],
        "sequence" => attrs.wrap_event_sequence,
        "event_type" => "wrap_issued",
        "actor" => attrs.sender,
        "authority_boundary" => signed_pq_wrap_event_authority_boundary(attrs),
        "previous_event_hash" =>
          Encoding.encode_base64url(attrs.operation_checkpoint_covered_head_hash),
        "body" => event_body
      })

    attrs
    |> Map.put(:wrap_event_body_hash, Encoding.decode_base64url!(event_body_hash, 32))
    |> Map.put(
      :wrap_event_hash,
      Encoding.decode_base64url!(Hash.blake3_base64url(JCS.canonical_bytes!(event)), 32)
    )
  end

  defp signed_pq_wrap_body(attrs) do
    %{
      "label" => "RefMD PQ wrap body v1",
      "protocol" => "refmd.signed-pq-hybrid-wrap",
      "version" => attrs.wrap_version,
      "suite_id" => attrs.suite_id,
      "suite_rank" => attrs.suite_rank,
      "purpose" => attrs.purpose,
      "resource" => attrs.resource,
      "sender" => attrs.sender,
      "recipient" => attrs.recipient,
      "event_scope" => attrs.event_scope,
      "hpke" => %{
        "mode" => "base",
        "kem_id" => attrs.kem_id,
        "kdf_id" => attrs.kdf_id,
        "aead_id" => attrs.aead_id,
        "enc" => Encoding.encode_base64url(attrs.hpke_enc),
        "ciphertext" => Encoding.encode_base64url(attrs.hpke_ciphertext)
      },
      "hpke_info_hash" => Hash.blake3_base64url(signed_pq_wrap_hpke_info(attrs)),
      "aad_hash" => Hash.blake3_base64url(signed_pq_wrap_aad(attrs))
    }
  end

  defp signed_pq_wrap_event_body(attrs) do
    %{
      "purpose" => attrs.purpose,
      "recipient" => attrs.recipient,
      "resource" => attrs.resource,
      "resource_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(attrs.resource)),
      "sender" => attrs.sender,
      "wrap_body_hash" => Encoding.encode_base64url(attrs.wrap_body_hash),
      "wrap_protocol" => attrs.wrap_protocol,
      "wrap_suite_id" => attrs.suite_id,
      "wrap_suite_rank" => attrs.suite_rank,
      "wrap_version" => attrs.wrap_version
    }
  end

  defp signed_pq_wrap_event_authority_boundary(attrs) do
    %{
      "scope_kind" => attrs.event_scope["scope_kind"],
      "scope_id" => attrs.event_scope["scope_id"],
      "checkpoint_sequence" => attrs.operation_checkpoint_sequence,
      "checkpoint_hash" => Encoding.encode_base64url(attrs.operation_checkpoint_hash),
      "required_authority" => "event_type_authorized_actor"
    }
  end

  defp signed_pq_wrap_authority_boundary(attrs) do
    %{
      "scope_kind" => attrs.event_scope["scope_kind"],
      "scope_id" => attrs.event_scope["scope_id"],
      "event_hash" => Encoding.encode_base64url(attrs.wrap_event_hash),
      "operation_checkpoint_sequence" => attrs.operation_checkpoint_sequence,
      "operation_checkpoint_hash" => Encoding.encode_base64url(attrs.operation_checkpoint_hash),
      "covered_event_head_sequence" => attrs.operation_checkpoint_covered_head_sequence,
      "covered_event_head_hash" =>
        Encoding.encode_base64url(attrs.operation_checkpoint_covered_head_hash)
    }
  end

  defp signed_pq_wrap_subject_hashes(attrs) do
    %{
      "resource_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(attrs.resource)),
      "wrap_body_hash" => Encoding.encode_base64url(attrs.wrap_body_hash),
      "wrap_event_body_hash" => Encoding.encode_base64url(attrs.wrap_event_body_hash),
      "wrap_event_hash" => Encoding.encode_base64url(attrs.wrap_event_hash),
      "hpke_info_hash" => Hash.blake3_base64url(signed_pq_wrap_hpke_info(attrs)),
      "aad_hash" => Hash.blake3_base64url(signed_pq_wrap_aad(attrs))
    }
  end

  defp signed_pq_wrap_hpke_info(attrs) do
    JCS.canonical_bytes!(%{
      "label" => "RefMD HPKE info v1",
      "protocol" => "refmd.signed-pq-hybrid-wrap",
      "protocol_version" => attrs.wrap_version,
      "suite_id" => attrs.suite_id,
      "suite_rank" => attrs.suite_rank,
      "purpose" => attrs.purpose,
      "resource_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(attrs.resource)),
      "sender_user_id" => attrs.sender["user_id"],
      "sender_device_id" => attrs.sender["device_id"],
      "sender_signing_key_id" => attrs.sender["signing_key_id"],
      "sender_key_scope_kind" => attrs.sender["key_scope_kind"],
      "sender_key_scope_id" => attrs.sender["key_scope_id"],
      "sender_key_checkpoint_hash" => attrs.sender["key_checkpoint_hash"],
      "recipient_kind" => attrs.recipient["recipient_kind"],
      "recipient_key_id" => attrs.recipient["encryption_key_id"],
      "recipient_key_scope_kind" => attrs.recipient["key_scope_kind"],
      "recipient_key_scope_id" => attrs.recipient["key_scope_id"],
      "recipient_key_checkpoint_hash" => attrs.recipient["key_checkpoint_hash"],
      "event_scope_kind" => attrs.event_scope["scope_kind"],
      "event_scope_id" => attrs.event_scope["scope_id"]
    })
  end

  defp signed_pq_wrap_aad(attrs) do
    JCS.canonical_bytes!(%{
      "label" => "RefMD PQ wrap AAD v1",
      "protocol" => "refmd.signed-pq-hybrid-wrap",
      "protocol_version" => attrs.wrap_version,
      "suite_id" => attrs.suite_id,
      "suite_rank" => attrs.suite_rank,
      "purpose" => attrs.purpose,
      "resource" => attrs.resource,
      "sender" => attrs.sender,
      "recipient" => attrs.recipient,
      "event_scope" => attrs.event_scope,
      "hpke" => %{
        "mode" => "base",
        "kem_id" => attrs.kem_id,
        "kdf_id" => attrs.kdf_id,
        "aead_id" => attrs.aead_id,
        "enc" => Encoding.encode_base64url(attrs.hpke_enc)
      }
    })
  end

  def workspace_member_removal_key_directory_append(
        workspace_id,
        target_user_id,
        actor_user_id,
        actor_device_id,
        actor_private_material
      ) do
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    actor_public_material = hybrid_signing_public_key_material(actor_private_material)
    actor_signing_key_id = Signature.compute_signing_key_id!(actor_public_material)

    member_removed_event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => pin.event_head_sequence + 1,
        "event_type" => "member_removed",
        "actor" => device_actor(actor_user_id, actor_device_id, actor_signing_key_id),
        "previous_event_hash" => pin.event_head_hash,
        "body" => %{
          "workspace_id" => workspace_id,
          "user_id" => target_user_id,
          "removed_at_event_sequence" => pin.event_head_sequence + 1
        }
      })

    workspace = RefMD.Repo.get!(RefMD.Workspaces.Workspace, workspace_id)

    documents =
      RefMD.Repo.all(
        from(document in RefMD.Documents.Document,
          where: document.workspace_id == ^workspace_id,
          order_by: [asc: document.id]
        )
      )

    rotation_specs =
      [
        %{
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "old_key_version" => workspace.current_kek_version,
          "new_key_version" => workspace.current_kek_version + 1
        }
      ] ++
        Enum.map(documents, fn document ->
          %{
            "rotation_kind" => "dek",
            "scope_kind" => "document",
            "scope_id" => document.id,
            "old_key_version" => document.min_dek_version,
            "new_key_version" => document.min_dek_version + 1
          }
        end)

    {rotation_events, _sequence, _previous_hash} =
      Enum.reduce(
        rotation_specs,
        {[], member_removed_event["sequence"], KeyDirectory.event_hash(member_removed_event)},
        fn spec, {events, previous_sequence, previous_hash} ->
          sequence = previous_sequence + 1

          event =
            key_directory_event(%{
              "scope_kind" => "workspace",
              "scope_id" => workspace_id,
              "sequence" => sequence,
              "event_type" => "rotation_started",
              "actor" => device_actor(actor_user_id, actor_device_id, actor_signing_key_id),
              "previous_event_hash" => previous_hash,
              "body" =>
                spec
                |> Map.put("event_type", "rotation_started")
                |> Map.put("not_before_event_sequence", sequence)
                |> Map.put("reason", "membership_change")
            })

          {[event | events], sequence, KeyDirectory.event_hash(event)}
        end
      )

    events = [member_removed_event | Enum.reverse(rotation_events)]
    last_event = List.last(events)

    checkpoint_payload =
      key_directory_checkpoint_payload!(
        checkpoint.payload
        |> Map.put("sequence", checkpoint.sequence + 1)
        |> Map.put(
          "issued_at",
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
        )
        |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
        |> Map.put("covered_event_head", event_head(last_event))
      )

    %{
      "workspace_key_directory_events" =>
        Enum.map(events, &signed_key_directory_event(&1, actor_private_material)),
      "workspace_key_directory_checkpoint" =>
        signed_key_directory_checkpoint(
          checkpoint_payload,
          "workspace_authorized",
          actor_private_material,
          actor_user_id
        )
    }
  end

  def workspace_member_role_changes_key_directory_append(
        workspace_id,
        actor_user_id,
        actor_device_id,
        actor_private_material,
        changes
      ) do
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    actor_public_material = hybrid_signing_public_key_material(actor_private_material)
    actor_signing_key_id = Signature.compute_signing_key_id!(actor_public_material)
    actor = device_actor(actor_user_id, actor_device_id, actor_signing_key_id)

    {events, _sequence, _hash} =
      Enum.reduce(changes, {[], pin.event_head_sequence, pin.event_head_hash}, fn change,
                                                                                  {events,
                                                                                   sequence,
                                                                                   previous_hash} ->
        sequence = sequence + 1

        event =
          key_directory_event(%{
            "scope_kind" => "workspace",
            "scope_id" => workspace_id,
            "sequence" => sequence,
            "event_type" => "member_role_changed",
            "actor" => actor,
            "previous_event_hash" => previous_hash,
            "body" =>
              change
              |> Map.put("workspace_id", workspace_id)
              |> Map.put("changed_at_event_sequence", sequence)
          })

        {events ++ [event], sequence, Hash.blake3_base64url(JCS.canonical_bytes!(event))}
      end)

    final_event = List.last(events)

    checkpoint_payload =
      key_directory_checkpoint_payload!(
        checkpoint.payload
        |> Map.put("sequence", checkpoint.sequence + 1)
        |> Map.put(
          "issued_at",
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
        )
        |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
        |> Map.put("covered_event_head", event_head(final_event))
      )

    %{
      "workspace_key_directory_events" =>
        Enum.map(events, &signed_key_directory_event(&1, actor_private_material)),
      "workspace_key_directory_checkpoint" =>
        signed_key_directory_checkpoint(
          checkpoint_payload,
          "workspace_authorized",
          actor_private_material,
          actor_user_id
        )
    }
  end

  def guest_invitation_created_key_directory_append(attrs) do
    workspace_id = Map.fetch!(attrs, :workspace_id)
    actor_user_id = Map.fetch!(attrs, :actor_user_id)
    actor_device_id = Map.fetch!(attrs, :actor_device_id)
    actor_private_material = Map.fetch!(attrs, :actor_private_material)
    invitation_id = Map.fetch!(attrs, :invitation_id)
    permission = Map.fetch!(attrs, :permission)
    expires_at = Map.fetch!(attrs, :expires_at)
    bootstrap_key_commitment = Map.fetch!(attrs, :bootstrap_key_commitment)
    bootstrap_package_hash = Map.fetch!(attrs, :bootstrap_package_hash)
    capability_context_hash = Map.fetch!(attrs, :capability_context_hash)
    redeem_authority_private_material = Map.fetch!(attrs, :redeem_authority_private_material)
    scope_kind = Map.get(attrs, :scope_kind, "workspace")
    scope_id = Map.get(attrs, :scope_id, "none")
    share_id = Map.get(attrs, :share_id)
    kek_version = Map.get(attrs, :kek_version)
    share_key_version = Map.get(attrs, :share_key_version, "NOT_APPLICABLE")
    dek_version = Map.get(attrs, :dek_version, "NOT_APPLICABLE")
    delivery_mode = Map.get(attrs, :delivery_mode, "unknown_fragment")
    recipient_user_id = Map.get(attrs, :recipient_user_id) || "NOT_APPLICABLE"
    recipient_device_ids = Map.get(attrs, :recipient_device_ids, [])
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    actor_public_material = hybrid_signing_public_key_material(actor_private_material)
    actor_signing_key_id = Signature.compute_signing_key_id!(actor_public_material)
    redeem_public_material = hybrid_signing_public_key_material(redeem_authority_private_material)
    redeem_signing_key_id = Signature.compute_signing_key_id!(redeem_public_material)

    event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => pin.event_head_sequence + 1,
        "event_type" => "guest_invitation_created",
        "actor" => device_actor(actor_user_id, actor_device_id, actor_signing_key_id),
        "previous_event_hash" => pin.event_head_hash,
        "body" => %{
          "workspace_id" => workspace_id,
          "guest_invitation_id" => invitation_id,
          "guest_grant_template_hash" =>
            context_hash(%{
              "guest_invitation_id" => invitation_id,
              "permission" => permission,
              "scope_id" => scope_id,
              "scope_kind" => scope_kind,
              "workspace_id" => workspace_id
            }),
          "scope_kind" => scope_kind,
          "scope_id" => scope_id,
          "permission" => permission,
          "delivery_mode" => delivery_mode,
          "recipient_user_id" => recipient_user_id,
          "recipient_device_ids" => recipient_device_ids,
          "key_version_context" => %{
            "workspace_kek_version" => kek_version || "NOT_APPLICABLE",
            "share_key_version" => share_key_version,
            "dek_version" => dek_version
          },
          "allowed_share_ids_hash" =>
            context_hash(%{"allowed_share_ids" => if(share_id, do: [share_id], else: [])}),
          "expires_event_sequence" => DateTime.to_unix(expires_at),
          "redeem_authority" => %{
            "signer_kind" => "invitation_redeem_authority",
            "signing_key_id" => redeem_signing_key_id,
            "hybrid_signing_public_key_material" => redeem_public_material
          },
          "bootstrap_key_commitment" => bootstrap_key_commitment,
          "bootstrap_package_hash" => bootstrap_package_hash,
          "bootstrap_suite_id" => "refmd-v2-invitation-bootstrap-xchacha20poly1305",
          "capability_context_hash" => capability_context_hash
        }
      })

    checkpoint_payload =
      key_directory_checkpoint_payload!(
        checkpoint.payload
        |> Map.put("sequence", checkpoint.sequence + 1)
        |> Map.put(
          "issued_at",
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
        )
        |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
        |> Map.put("covered_event_head", event_head(event))
      )

    %{
      events: [signed_key_directory_event(event, actor_private_material)],
      checkpoint:
        signed_key_directory_checkpoint(
          checkpoint_payload,
          "workspace_authorized",
          actor_private_material,
          actor_user_id
        )
    }
  end

  def guest_invitation_redeemed_key_directory_append(
        invitation,
        device_attrs,
        redeem_authority_private_material,
        recipient_account \\ nil
      ) do
    workspace_id = invitation.workspace_id
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    redeem_public_material = hybrid_signing_public_key_material(redeem_authority_private_material)
    redeem_signing_key_id = Signature.compute_signing_key_id!(redeem_public_material)

    device_signing_key_id =
      Signature.compute_signing_key_id!(device_attrs.device_hybrid_signing_public_key_material)

    device_encryption_key_id =
      HybridEncryptionMaterial.compute_key_id!(
        device_attrs.device_hybrid_encryption_public_key_material
      )

    identity_encryption_key_id =
      HybridEncryptionMaterial.compute_key_id!(
        device_attrs.identity_hybrid_encryption_public_key_material
      )

    event_ref = fn event ->
      %{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "event_sequence" => event["sequence"],
        "event_hash" => KeyDirectory.event_hash(event)
      }
    end

    event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => pin.event_head_sequence + 1,
        "event_type" => "guest_invitation_redeemed",
        "actor" => %{
          "signer_kind" => "invitation_redeem_authority",
          "invitation_id" => invitation.id,
          "signing_key_id" => redeem_signing_key_id
        },
        "previous_event_hash" => pin.event_head_hash,
        "body" => %{
          "workspace_id" => workspace_id,
          "guest_invitation_id" => invitation.id,
          "guest_grant_id" => Ecto.UUID.generate(),
          "guest_user_id" => device_attrs.guest_user_id,
          "guest_device_id" => device_attrs.device_id,
          "guest_encryption_key_id" => device_encryption_key_id,
          "guest_signing_key_id" => device_signing_key_id,
          "scope_kind" => invitation.scope_kind,
          "scope_id" => invitation.scope_id || "none",
          "permission" => invitation.permission,
          "recipient_account_user_id" =>
            if(recipient_account, do: recipient_account.user_id, else: "NOT_APPLICABLE"),
          "recipient_account_device_id" =>
            if(recipient_account, do: recipient_account.device_id, else: "NOT_APPLICABLE"),
          "redeemed_at_event_sequence" => pin.event_head_sequence + 1
        }
      })

    event_valid_from = event_ref.(event)

    checkpoint_payload =
      key_directory_checkpoint_payload!(
        checkpoint.payload
        |> Map.put("sequence", checkpoint.sequence + 1)
        |> Map.put(
          "issued_at",
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
        )
        |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
        |> Map.put("covered_event_head", event_head(event))
        |> Map.update!("identity_keys", fn keys ->
          append_key_entry_if_missing(
            keys,
            %{
              "key_id" => identity_encryption_key_id,
              "key_material" => device_attrs.identity_hybrid_encryption_public_key_material,
              "valid_from" => event_valid_from
            }
          )
        end)
        |> Map.update!("device_keys", fn keys ->
          keys
          |> append_key_entry_if_missing(%{
            "key_id" => device_signing_key_id,
            "key_material" => device_attrs.device_hybrid_signing_public_key_material,
            "valid_from" => event_valid_from
          })
          |> append_key_entry_if_missing(%{
            "key_id" => device_encryption_key_id,
            "key_material" => device_attrs.device_hybrid_encryption_public_key_material,
            "valid_from" => event_valid_from
          })
        end)
      )

    %{
      events: [signed_key_directory_event(event, redeem_authority_private_material)],
      checkpoint:
        signed_key_directory_checkpoint(
          checkpoint_payload,
          "invitation_redeem_authority",
          redeem_authority_private_material
        )
    }
  end

  def insert_test_workspace_key_directory!(
        workspace_id,
        user_id,
        role_id,
        identity_private_material,
        identity_hybrid_encryption_public_key_material,
        device_private_material,
        device_hybrid_encryption_public_key_material
      ) do
    actor_material = %{
      user_id: user_id,
      device_id: device_private_material["owner_id"],
      signing_private: device_private_material,
      signing_public: hybrid_signing_public_key_material(device_private_material),
      encryption_public: device_hybrid_encryption_public_key_material,
      x25519_public_key:
        Encoding.decode_base64url!(
          device_hybrid_encryption_public_key_material["x25519_public"],
          32
        ),
      mlkem768_public_key:
        Encoding.decode_base64url!(
          device_hybrid_encryption_public_key_material["mlkem768_public"],
          1184
        ),
      encryption_key_id:
        HybridEncryptionMaterial.compute_key_id!(device_hybrid_encryption_public_key_material)
    }

    Process.put({:test_workspace_actor_material, user_id}, actor_material)
    Process.put({:test_workspace_signer_material, workspace_id}, actor_material)

    key_directory =
      initial_key_directory_bootstrap(
        user_id,
        workspace_id,
        role_id,
        identity_private_material,
        identity_hybrid_encryption_public_key_material,
        device_private_material,
        device_hybrid_encryption_public_key_material
      )

    KeyDirectory.insert_signed_initial_scope!(
      "workspace",
      workspace_id,
      key_directory.workspace_events,
      key_directory.workspace_checkpoint,
      checkpoint_signer_kind: "device"
    )
  end

  def insert_test_workspace_key_directory!(workspace_id, user_id, role_id) do
    device_id = Ecto.UUID.generate()
    identity_private_material = hybrid_signing_private_key_material("identity", user_id)
    device_private_material = hybrid_signing_private_key_material("device", device_id)
    {identity_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)
    {device_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)

    insert_test_workspace_key_directory!(
      workspace_id,
      user_id,
      role_id,
      identity_private_material,
      hybrid_encryption_public_key_material("identity", user_id, identity_x25519_public).public,
      device_private_material,
      hybrid_encryption_public_key_material("device", device_id, device_x25519_public).public
    )
  end

  def test_workspace_pin_bootstrap_hash!(workspace_id) do
    PinBootstrap.hash!(workspace_id, test_workspace_pin_bootstrap!(workspace_id))
  end

  def test_workspace_pin_bootstrap!(workspace_id) do
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    payload = checkpoint.payload
    covered_head = Map.fetch!(payload, "covered_event_head")

    signer =
      checkpoint.signatures
      |> Enum.find_value(fn
        %{"signer" => %{"signer_kind" => "device"} = signer} -> signer
        _ -> nil
      end)

    checkpoint_hash = RefMD.Encryption.KeyDirectory.Protocol.checkpoint_hash(payload)

    bootstrap_payload = %{
      "protocol" => "refmd.workspace-pin-bootstrap",
      "version" => 1,
      "workspace_id" => workspace_id,
      "checkpoint_sequence" => Map.fetch!(payload, "sequence"),
      "checkpoint_hash" => checkpoint_hash,
      "event_head_sequence" => Map.fetch!(covered_head, "head_sequence"),
      "event_head_hash" => Map.fetch!(covered_head, "head_hash"),
      "suite_policy_version" => Map.fetch!(payload, "suite_policy_version"),
      "min_suite_rank" => Map.fetch!(payload, "min_suite_rank"),
      "allowed_suite_ids_hash" =>
        Hash.blake3_base64url(
          JCS.canonical_bytes!(%{
            "allowed_suite_ids" => Map.fetch!(payload, "allowed_suite_ids")
          })
        ),
      "issuer" => %{
        "signer_kind" => "device",
        "user_id" => Map.fetch!(signer, "user_id"),
        "device_id" => Map.fetch!(signer, "device_id"),
        "signing_key_id" => Map.fetch!(signer, "signing_key_id"),
        "key_scope_kind" => "workspace",
        "key_scope_id" => workspace_id,
        "key_checkpoint_sequence" => Map.fetch!(payload, "sequence"),
        "key_checkpoint_hash" => checkpoint_hash
      },
      "issuing_event_hash" => Map.fetch!(covered_head, "head_hash"),
      "expires_event_sequence" => 9_007_199_254_740_991,
      "bootstrap_nonce" => Hash.blake3_base64url("test-workspace-pin-bootstrap:" <> workspace_id)
    }

    device_private =
      hybrid_signing_private_key_material("device", Map.fetch!(signer, "device_id"))

    device_public = public_signing_material_from_private(device_private)

    transcript =
      Signature.build_workspace_pin_bootstrap_transcript!(
        Map.fetch!(signer, "device_id"),
        workspace_id,
        bootstrap_payload
      )

    %{
      "payload" => bootstrap_payload,
      "signatures" => [
        %{
          "signer" => bootstrap_payload["issuer"],
          "signature" =>
            Signature.__test_sign_hybrid_signature__(
              "workspace_pin_bootstrap",
              transcript,
              device_private,
              device_public
            )
        }
      ]
    }
  end

  defp public_signing_material_from_private(private) do
    %{
      "protocol" => "refmd.hybrid-signing-key-material",
      "version" => @protocol_version,
      "owner_kind" => private["owner_kind"],
      "owner_id" => private["owner_id"],
      "ed25519_public" => private["ed25519_public"],
      "mldsa65_public" => private["mldsa65_public"],
      "suite_id" => @suite_id,
      "suite_rank" => @suite_rank
    }
  end

  def document_operation_admission(params) when is_map(params) do
    workspace_id = Map.fetch!(params, :workspace_id)
    document_id = Map.fetch!(params, :document_id)
    user_id = Map.fetch!(params, :user_id)
    device_id = Map.fetch!(params, :device_id)
    private_material = Map.fetch!(params, :private_material)
    event_type = Map.fetch!(params, :event_type)

    signature_hash =
      cond do
        event_type == "document_write_session_admitted" ->
          nil

        Map.has_key?(params, :signature) ->
          params
          |> Map.fetch!(:signature)
          |> JCS.canonical_bytes!()
          |> Blake3.hash_base64url()

        Map.has_key?(params, :signature_b64) ->
          params
          |> Map.fetch!(:signature_b64)
          |> Encoding.decode_base64url!()
          |> Blake3.hash_base64url()

        true ->
          raise KeyError, key: :signature, term: params
      end

    key_version = Map.fetch!(params, :key_version)
    min_dek_version = Map.fetch!(params, :min_dek_version)

    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    public_material = hybrid_signing_public_key_material(private_material)
    signing_key_id = Signature.compute_signing_key_id!(public_material)

    actor =
      device_actor(user_id, device_id, signing_key_id)
      |> Map.merge(%{
        "key_scope_kind" => "workspace",
        "key_scope_id" => workspace_id,
        "key_checkpoint_sequence" => checkpoint.sequence,
        "key_checkpoint_hash" => checkpoint.checkpoint_hash
      })

    event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => pin.event_head_sequence + 1,
        "event_type" => event_type,
        "actor" => actor,
        "previous_event_hash" => pin.event_head_hash,
        "body" =>
          document_operation_admission_body(%{
            params: params,
            event_type: event_type,
            workspace_id: workspace_id,
            document_id: document_id,
            signing_key_id: signing_key_id,
            actor_hash: Hash.blake3_base64url(JCS.canonical_bytes!(actor)),
            key_version: key_version,
            min_dek_version: min_dek_version,
            previous_event_hash: pin.event_head_hash,
            previous_event_sequence: pin.event_head_sequence,
            signature_hash: signature_hash
          })
      })

    checkpoint_payload =
      key_directory_checkpoint_payload!(
        checkpoint.payload
        |> Map.put("sequence", checkpoint.sequence + 1)
        |> Map.put(
          "issued_at",
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
        )
        |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
        |> Map.put("covered_event_head", event_head(event))
      )

    %{
      "workspaceKeyDirectoryEvents" => [signed_key_directory_event(event, private_material)],
      "workspaceKeyDirectoryCheckpoint" =>
        signed_key_directory_checkpoint(
          checkpoint_payload,
          "workspace_authorized",
          private_material,
          user_id
        )
    }
  end

  defp document_operation_admission_body(%{event_type: "document_write_session_admitted"} = input) do
    %{
      "actor_hash" => Map.fetch!(input, :actor_hash),
      "authority_kind" => "workspace_device",
      "authority_scope_id" => Map.fetch!(input, :workspace_id),
      "document_id" => Map.fetch!(input, :document_id),
      "document_permission_proof_hash" =>
        document_permission_proof_hash(
          Map.fetch!(input, :workspace_id),
          Map.fetch!(input, :document_id),
          "workspace_device",
          Map.fetch!(input, :workspace_id),
          Map.fetch!(input, :signing_key_id),
          Map.fetch!(input, :workspace_id),
          1
        ),
      "event_type" => "document_write_session_admitted",
      "expires_at_ms" => Map.fetch!(input.params, :expires_at_ms),
      "issued_at_ms" => Map.fetch!(input.params, :issued_at_ms),
      "max_ciphertext_bytes" => Map.fetch!(input.params, :max_ciphertext_bytes),
      "max_update_count" => Map.fetch!(input.params, :max_update_count),
      "min_dek_version" => Map.fetch!(input, :min_dek_version),
      "previous_workspace_event_hash" => Map.fetch!(input, :previous_event_hash),
      "previous_workspace_event_sequence" => Map.fetch!(input, :previous_event_sequence),
      "session_id" => Map.fetch!(input.params, :session_id),
      "session_nonce" =>
        Map.get_lazy(input.params, :session_nonce, fn ->
          Encoding.encode_base64url(:crypto.strong_rand_bytes(32))
        end),
      "workspace_id" => Map.fetch!(input, :workspace_id)
    }
  end

  defp document_operation_admission_body(input) do
    %{
      "actor_hash" => Map.fetch!(input, :actor_hash),
      "admission_nonce" => Encoding.encode_base64url(:crypto.strong_rand_bytes(32)),
      "dek_version" => Map.fetch!(input, :key_version),
      "document_id" => Map.fetch!(input, :document_id),
      "document_permission_proof_hash" =>
        document_permission_proof_hash(
          Map.fetch!(input, :workspace_id),
          Map.fetch!(input, :document_id),
          "workspace_device",
          Map.fetch!(input, :workspace_id),
          Map.fetch!(input, :signing_key_id),
          Map.fetch!(input, :workspace_id),
          1
        ),
      "event_type" => Map.fetch!(input, :event_type),
      "min_dek_version" => Map.fetch!(input, :min_dek_version),
      "operation_hash" => Map.fetch!(input.params, :operation_hash),
      "operation_signature_hash" => Map.fetch!(input, :signature_hash),
      "previous_workspace_event_hash" => Map.fetch!(input, :previous_event_hash),
      "previous_workspace_event_sequence" => Map.fetch!(input, :previous_event_sequence),
      "workspace_id" => Map.fetch!(input, :workspace_id)
    }
  end

  defp document_permission_proof_hash(
         workspace_id,
         document_id,
         authority_kind,
         authority_id,
         authority_context_key,
         authority_scope_id,
         authority_permission_version
       ) do
    %{
      "protocol" => "refmd.document-permission-proof",
      "version" => 1,
      "workspace_id" => workspace_id,
      "document_id" => document_id,
      "authority_kind" => authority_kind,
      "authority_id" => authority_id,
      "authority_context_key" => authority_context_key,
      "authority_scope_id" => authority_scope_id,
      "authority_permission_version" => authority_permission_version,
      "permission" => "edit"
    }
    |> JCS.canonical_bytes!()
    |> Hash.blake3_base64url()
  end

  def document_write_state_key_directory_append(
        workspace_id,
        actor_user_id,
        actor_device_id,
        actor_private_material,
        changes,
        reason
      )
      when is_list(changes) and is_binary(reason) do
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)

    signing_key_id =
      Signature.compute_signing_key_id!(
        hybrid_signing_public_key_material(actor_private_material)
      )

    actor =
      device_actor(actor_user_id, actor_device_id, signing_key_id)
      |> Map.merge(%{
        "key_scope_kind" => "workspace",
        "key_scope_id" => workspace_id,
        "key_checkpoint_sequence" => checkpoint.sequence,
        "key_checkpoint_hash" => checkpoint.checkpoint_hash
      })

    {events, _sequence, _previous_hash} =
      Enum.reduce(changes, {[], pin.event_head_sequence + 1, pin.event_head_hash}, fn change,
                                                                                      {events,
                                                                                       sequence,
                                                                                       previous_hash} ->
        event =
          key_directory_event(%{
            "scope_kind" => "workspace",
            "scope_id" => workspace_id,
            "sequence" => sequence,
            "event_type" => "document_write_state_changed",
            "actor" => actor,
            "previous_event_hash" => previous_hash,
            "body" => %{
              "document_id" => Map.fetch!(change, :document_id),
              "event_type" => "document_write_state_changed",
              "issued_at_ms" => System.system_time(:millisecond),
              "previous_workspace_event_hash" => previous_hash,
              "previous_workspace_event_sequence" => sequence - 1,
              "previous_write_state" => Map.fetch!(change, :previous_write_state),
              "reason" => reason,
              "workspace_id" => workspace_id,
              "write_state" => Map.fetch!(change, :write_state)
            }
          })

        {[event | events], sequence + 1, KeyDirectory.event_hash(event)}
      end)

    events = Enum.reverse(events)
    last_event = List.last(events)

    checkpoint_payload =
      key_directory_checkpoint_payload!(
        checkpoint.payload
        |> Map.put("sequence", checkpoint.sequence + 1)
        |> Map.put(
          "issued_at",
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
        )
        |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
        |> Map.put("covered_event_head", event_head(last_event))
      )

    %{
      "workspace_key_directory_events" =>
        Enum.map(events, &signed_key_directory_event(&1, actor_private_material)),
      "workspace_key_directory_checkpoint" =>
        signed_key_directory_checkpoint(
          checkpoint_payload,
          "workspace_authorized",
          actor_private_material,
          actor_user_id
        )
    }
  end

  def kek_rotation_start_key_directory_append(
        workspace_id,
        actor_user_id,
        actor_device_id,
        actor_private_material,
        old_key_version,
        new_key_version
      ) do
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)

    signing_key_id =
      Signature.compute_signing_key_id!(
        hybrid_signing_public_key_material(actor_private_material)
      )

    event_sequence = pin.event_head_sequence + 1

    event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => event_sequence,
        "event_type" => "rotation_started",
        "actor" => device_actor(actor_user_id, actor_device_id, signing_key_id),
        "previous_event_hash" => pin.event_head_hash,
        "body" => %{
          "event_type" => "rotation_started",
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "old_key_version" => old_key_version,
          "new_key_version" => new_key_version,
          "not_before_event_sequence" => event_sequence,
          "reason" => "manual"
        }
      })

    checkpoint_payload =
      key_directory_checkpoint_payload!(
        checkpoint.payload
        |> Map.put("sequence", checkpoint.sequence + 1)
        |> Map.put(
          "issued_at",
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
        )
        |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
        |> Map.put("covered_event_head", event_head(event))
      )

    %{
      "workspace_key_directory_events" => [
        signed_key_directory_event(event, actor_private_material)
      ],
      "workspace_key_directory_checkpoint" =>
        signed_key_directory_checkpoint(
          checkpoint_payload,
          "workspace_authorized",
          actor_private_material,
          actor_user_id
        )
    }
  end

  def kek_rotation_complete_key_directory_append(
        workspace_id,
        actor_user_id,
        actor_device_id,
        actor_private_material,
        old_key_version,
        new_key_version,
        opts \\ []
      ) do
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)

    actor_public_material = hybrid_signing_public_key_material(actor_private_material)
    signing_key_id = Signature.compute_signing_key_id!(actor_public_material)
    completed_sequence = pin.event_head_sequence + 1

    completed_event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => completed_sequence,
        "event_type" => "rotation_completed",
        "actor" => device_actor(actor_user_id, actor_device_id, signing_key_id),
        "previous_event_hash" => pin.event_head_hash,
        "body" => %{
          "event_type" => "rotation_completed",
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "old_key_version" => old_key_version,
          "new_key_version" => new_key_version,
          "completed_at_event_sequence" => completed_sequence,
          "completion_manifest_hash" =>
            kek_rotation_completion_manifest_hash(
              workspace_id,
              old_key_version,
              new_key_version,
              pin.event_head_hash
            )
        }
      })

    rotation_completed_event_hash = KeyDirectory.event_hash(completed_event)

    deletion_proofs =
      Keyword.get_lazy(opts, :device_key_deletion_proofs, fn ->
        [
          signed_device_key_deletion_proof(
            workspace_id,
            actor_user_id,
            actor_device_id,
            actor_private_material,
            old_key_version,
            rotation_completed_event_hash
          )
        ]
      end)

    wipe_required_device_ids = Keyword.get(opts, :wipe_required_device_ids, [])
    deleted_sequence = completed_sequence + 1

    deleted_event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => deleted_sequence,
        "event_type" => "old_key_deleted",
        "actor" => device_actor(actor_user_id, actor_device_id, signing_key_id),
        "previous_event_hash" => rotation_completed_event_hash,
        "body" => %{
          "event_type" => "old_key_deleted",
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "old_key_version" => old_key_version,
          "deleted_at_event_sequence" => deleted_sequence,
          "deletion_manifest_hash" =>
            kek_old_key_deletion_manifest_hash(
              workspace_id,
              old_key_version,
              rotation_completed_event_hash,
              deletion_proofs,
              wipe_required_device_ids,
              deleted_sequence
            )
        }
      })

    checkpoint_payload =
      key_directory_checkpoint_payload!(
        checkpoint.payload
        |> Map.put("sequence", checkpoint.sequence + 1)
        |> Map.put(
          "issued_at",
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
        )
        |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
        |> Map.put("covered_event_head", event_head(deleted_event))
      )

    %{
      "workspace_key_directory_events" => [
        signed_key_directory_event(completed_event, actor_private_material),
        signed_key_directory_event(deleted_event, actor_private_material)
      ],
      "workspace_key_directory_checkpoint" =>
        signed_key_directory_checkpoint(
          checkpoint_payload,
          "workspace_authorized",
          actor_private_material,
          actor_user_id
        ),
      "device_key_deletion_proofs" => deletion_proofs,
      "wipe_required_device_ids" => wipe_required_device_ids
    }
  end

  def signed_device_key_deletion_proof(
        workspace_id,
        actor_user_id,
        actor_device_id,
        actor_private_material,
        old_key_version,
        rotation_completed_event_hash
      ) do
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    actor_public_material = hybrid_signing_public_key_material(actor_private_material)
    signing_key_id = Signature.compute_signing_key_id!(actor_public_material)

    payload = %{
      "protocol" => "refmd.device-key-deletion-proof",
      "version" => 1,
      "workspace_id" => workspace_id,
      "device_id" => actor_device_id,
      "rotation_kind" => "kek",
      "scope_kind" => "workspace",
      "scope_id" => workspace_id,
      "old_key_version" => old_key_version,
      "rotation_completed_event_hash" => rotation_completed_event_hash,
      "deleted_secret_ids_hash" =>
        DeletionProofs.deleted_workspace_kek_secret_ids_hash(
          workspace_id,
          old_key_version
        ),
      "deleted_storage_classes" => @kek_deletion_storage_classes,
      "local_cache_epoch" => 1,
      "proof_nonce" => Encoding.encode_base64url(:crypto.strong_rand_bytes(32))
    }

    actor = %{
      "signer_kind" => "workspace_device",
      "user_id" => actor_user_id,
      "device_id" => actor_device_id,
      "signing_key_id" => signing_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id,
      "key_checkpoint_sequence" => checkpoint.sequence,
      "key_checkpoint_hash" => checkpoint.checkpoint_hash
    }

    transcript = Signature.build_device_key_deletion_proof_transcript!(payload, actor)

    %{
      "payload" => payload,
      "transcript" => transcript,
      "signature" =>
        sign_transcript(
          actor_private_material,
          actor_public_material,
          "device_key_deletion_proof",
          transcript
        )
    }
  end

  def signed_document_dek_deletion_proof(
        workspace_id,
        document_id,
        actor_user_id,
        actor_device_id,
        actor_private_material,
        old_key_version,
        rotation_completed_event_hash
      ) do
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    actor_public_material = hybrid_signing_public_key_material(actor_private_material)
    signing_key_id = Signature.compute_signing_key_id!(actor_public_material)

    payload = %{
      "protocol" => "refmd.device-key-deletion-proof",
      "version" => 1,
      "workspace_id" => workspace_id,
      "device_id" => actor_device_id,
      "rotation_kind" => "dek",
      "scope_kind" => "document",
      "scope_id" => document_id,
      "old_key_version" => old_key_version,
      "rotation_completed_event_hash" => rotation_completed_event_hash,
      "deleted_secret_ids_hash" =>
        DeletionProofs.deleted_document_dek_secret_ids_hash(document_id, old_key_version),
      "deleted_storage_classes" => @kek_deletion_storage_classes,
      "local_cache_epoch" => 1,
      "proof_nonce" => Encoding.encode_base64url(:crypto.strong_rand_bytes(32))
    }

    actor = %{
      "signer_kind" => "workspace_device",
      "user_id" => actor_user_id,
      "device_id" => actor_device_id,
      "signing_key_id" => signing_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id,
      "key_checkpoint_sequence" => checkpoint.sequence,
      "key_checkpoint_hash" => checkpoint.checkpoint_hash
    }

    transcript = Signature.build_device_key_deletion_proof_transcript!(payload, actor)

    %{
      "payload" => payload,
      "transcript" => transcript,
      "signature" =>
        sign_transcript(
          actor_private_material,
          actor_public_material,
          "device_key_deletion_proof",
          transcript
        )
    }
  end

  def dek_rotation_complete_key_directory_append(
        workspace_id,
        document_id,
        actor_user_id,
        actor_device_id,
        actor_private_material,
        materials,
        opts \\ []
      ) do
    pin = KeyDirectory.current_pin("workspace", workspace_id)
    checkpoint = KeyDirectory.current_checkpoint("workspace", workspace_id)
    actor_public = hybrid_signing_public_key_material(actor_private_material)
    signing_key_id = Signature.compute_signing_key_id!(actor_public)
    actor = device_actor(actor_user_id, actor_device_id, signing_key_id)

    completed_event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => materials.completed_at_event_sequence,
        "event_type" => "rotation_completed",
        "actor" => actor,
        "previous_event_hash" => pin.event_head_hash,
        "body" => %{
          "event_type" => "rotation_completed",
          "rotation_kind" => "dek",
          "scope_kind" => "document",
          "scope_id" => document_id,
          "old_key_version" => materials.old_key_version,
          "new_key_version" => materials.new_key_version,
          "completed_at_event_sequence" => materials.completed_at_event_sequence,
          "completion_manifest_hash" => materials.completion_manifest_hash
        }
      })

    completed_hash = KeyDirectory.event_hash(completed_event)

    proofs =
      Keyword.get_lazy(opts, :device_key_deletion_proofs, fn ->
        [
          signed_document_dek_deletion_proof(
            workspace_id,
            document_id,
            actor_user_id,
            actor_device_id,
            actor_private_material,
            materials.old_key_version,
            completed_hash
          )
        ]
      end)

    wipe_ids = Keyword.get(opts, :wipe_required_device_ids, [])
    proof_hashes = Enum.map(proofs, &Hash.blake3_base64url(JCS.canonical_bytes!(&1["payload"])))

    deletion_manifest = %{
      "protocol" => "refmd.old-key-deletion-manifest",
      "version" => 1,
      "rotation_kind" => "dek",
      "scope_kind" => "document",
      "scope_id" => document_id,
      "old_key_version" => materials.old_key_version,
      "rotation_completed_event_hash" => completed_hash,
      "deleted_secret_ids_hash" => materials.deleted_secret_ids_hash,
      "deleted_wrap_ids_hash" => materials.deleted_wrap_ids_hash,
      "active_device_deletion_proofs_hash" =>
        DeletionProofs.active_device_deletion_proofs_hash(proof_hashes),
      "wipe_required_device_ids_hash" => DeletionProofs.wipe_required_device_ids_hash(wipe_ids),
      "server_rejects_old_key_uploads_after_sequence" =>
        materials.server_rejects_old_key_uploads_after_sequence
    }

    deleted_event =
      key_directory_event(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => materials.deleted_at_event_sequence,
        "event_type" => "old_key_deleted",
        "actor" => actor,
        "previous_event_hash" => completed_hash,
        "body" => %{
          "event_type" => "old_key_deleted",
          "rotation_kind" => "dek",
          "scope_kind" => "document",
          "scope_id" => document_id,
          "old_key_version" => materials.old_key_version,
          "deleted_at_event_sequence" => materials.deleted_at_event_sequence,
          "deletion_manifest_hash" =>
            Hash.blake3_base64url(JCS.canonical_bytes!(deletion_manifest))
        }
      })

    checkpoint_payload =
      checkpoint.payload
      |> Map.put("sequence", checkpoint.sequence + 1)
      |> Map.put(
        "issued_at",
        DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
      )
      |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
      |> Map.put("covered_event_head", event_head(deleted_event))
      |> key_directory_checkpoint_payload!()

    %{
      "workspace_key_directory_events" =>
        Enum.map(
          [completed_event, deleted_event],
          &signed_key_directory_event(&1, actor_private_material)
        ),
      "workspace_key_directory_checkpoint" =>
        signed_key_directory_checkpoint(
          checkpoint_payload,
          "workspace_authorized",
          actor_private_material,
          actor_user_id
        ),
      "device_key_deletion_proofs" => proofs,
      "wipe_required_device_ids" => wipe_ids
    }
  end

  defp kek_rotation_completion_manifest_hash(
         workspace_id,
         old_key_version,
         new_key_version,
         started_event_hash
       ) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "protocol" => "refmd.rotation-completion-manifest",
        "version" => 1,
        "rotation_kind" => "kek",
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "old_key_version" => old_key_version,
        "new_key_version" => new_key_version,
        "started_event_hash" => started_event_hash,
        "active_recipient_devices_hash" => active_recipient_devices_hash(workspace_id),
        "member_envelope_records_hash" =>
          member_envelope_records_hash(workspace_id, new_key_version),
        "new_key_records_hash" => workspace_kek_records_hash(workspace_id, new_key_version),
        "old_key_records_hash" => workspace_kek_records_hash(workspace_id, old_key_version),
        "semantic_state_proof_hash" =>
          kek_rotation_completion_state_hash(workspace_id, old_key_version, new_key_version)
      })
    )
  end

  defp kek_old_key_deletion_manifest_hash(
         workspace_id,
         old_key_version,
         rotation_completed_event_hash,
         deletion_proofs,
         wipe_required_device_ids,
         server_rejects_old_key_uploads_after_sequence
       ) do
    proof_hashes =
      Enum.map(deletion_proofs, fn proof ->
        Hash.blake3_base64url(JCS.canonical_bytes!(Map.fetch!(proof, "payload")))
      end)

    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "protocol" => "refmd.old-key-deletion-manifest",
        "version" => 1,
        "rotation_kind" => "kek",
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "old_key_version" => old_key_version,
        "rotation_completed_event_hash" => rotation_completed_event_hash,
        "deleted_secret_ids_hash" =>
          DeletionProofs.deleted_workspace_kek_secret_ids_hash(
            workspace_id,
            old_key_version
          ),
        "deleted_wrap_ids_hash" => workspace_kek_records_hash(workspace_id, old_key_version),
        "active_device_deletion_proofs_hash" =>
          DeletionProofs.active_device_deletion_proofs_hash(proof_hashes),
        "wipe_required_device_ids_hash" =>
          DeletionProofs.wipe_required_device_ids_hash(wipe_required_device_ids),
        "server_rejects_old_key_uploads_after_sequence" =>
          server_rejects_old_key_uploads_after_sequence
      })
    )
  end

  defp active_recipient_devices_hash(workspace_id) do
    records =
      active_workspace_device_ids(workspace_id)
      |> Enum.map(&%{"recipient_kind" => "workspace_device", "recipient_id" => &1})

    Hash.blake3_base64url(JCS.canonical_bytes!(%{"records" => records}))
  end

  defp member_envelope_records_hash(workspace_id, key_version) do
    records =
      from(e in RefMD.Encryption.WorkspaceMemberEnvelope,
        where: e.workspace_id == ^workspace_id and e.key_version == ^key_version,
        order_by: [asc: e.target_user_id],
        select: {e.target_user_id, e.wrap_body_hash}
      )
      |> Repo.all()
      |> Enum.map(fn {user_id, wrap_body_hash} ->
        %{
          "recipient_kind" => "workspace_member",
          "recipient_id" => user_id,
          "wrap_hash" => encode_kek_manifest_hash(wrap_body_hash)
        }
      end)

    Hash.blake3_base64url(JCS.canonical_bytes!(%{"records" => records}))
  end

  defp workspace_kek_records_hash(workspace_id, key_version) do
    records =
      from(k in RefMD.Encryption.WorkspaceEncryptedKey,
        where: k.workspace_id == ^workspace_id and k.key_version == ^key_version,
        order_by: [asc: k.device_id],
        select: {k.device_id, k.wrap_body_hash}
      )
      |> Repo.all()
      |> Enum.map(fn {device_id, wrap_body_hash} ->
        %{
          "recipient_kind" => "workspace_device",
          "recipient_id" => device_id,
          "wrap_hash" => encode_kek_manifest_hash(wrap_body_hash)
        }
      end)

    Hash.blake3_base64url(JCS.canonical_bytes!(%{"records" => records}))
  end

  defp kek_rotation_completion_state_hash(workspace_id, old_key_version, new_key_version) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "workspace_id" => workspace_id,
        "old_kek_version" => old_key_version,
        "new_kek_version" => new_key_version,
        "active_device_ids" => active_workspace_device_ids(workspace_id)
      })
    )
  end

  defp active_workspace_device_ids(workspace_id) do
    DeletionProofs.active_workspace_device_ids(workspace_id)
  end

  defp encode_kek_manifest_hash(value) when is_binary(value) and byte_size(value) == 32,
    do: Encoding.encode_base64url(value)

  defp encode_kek_manifest_hash(value) when is_binary(value), do: value

  defp key_directory_event(attrs) do
    attrs
    |> put_initial_event_actor_authority()
    |> Map.put_new("authority_boundary", test_key_directory_event_authority_boundary(attrs))
    |> KeyDirectory.build_event_payload!()
  end

  defp put_initial_event_actor_authority(
         %{
           "actor" => actor,
           "sequence" => sequence,
           "scope_kind" => scope_kind,
           "scope_id" => scope_id
         } =
           attrs
       )
       when is_map(actor) and is_integer(sequence) and sequence > 1 do
    if Map.has_key?(actor, "key_checkpoint_sequence") and
         Map.has_key?(actor, "key_checkpoint_hash") do
      attrs
    else
      Map.put(
        attrs,
        "actor",
        Map.merge(actor, initial_event_actor_authority(scope_kind, scope_id))
      )
    end
  end

  defp put_initial_event_actor_authority(attrs), do: attrs

  defp initial_event_actor_authority(scope_kind, scope_id) do
    %{
      "key_scope_kind" => scope_kind,
      "key_scope_id" => scope_id,
      "key_checkpoint_sequence" => 1,
      "key_checkpoint_hash" =>
        Hash.blake3_base64url(
          JCS.canonical_bytes!(%{
            "protocol" => "refmd.initial-key-directory-authority",
            "version" => 1,
            "scope_kind" => scope_kind,
            "scope_id" => scope_id
          })
        )
    }
  end

  defp key_directory_checkpoint_payload!(attrs) do
    attrs
    |> Map.put("authority_boundary", test_key_directory_checkpoint_authority_boundary(attrs))
    |> KeyDirectory.build_checkpoint_payload!()
  end

  defp signed_key_directory_event(payload, private_material) do
    public_material = hybrid_signing_public_key_material(private_material)

    transcript =
      Signature.build_key_directory_event_transcript!(
        payload["event_type"],
        public_material["owner_kind"],
        public_material["owner_id"],
        payload
      )

    %{
      "payload" => payload,
      "signatures" => [
        %{
          "signer" =>
            public_material
            |> key_directory_signer(payload["actor"])
            |> key_directory_event_signer_authority(payload),
          "signature" =>
            sign_transcript(private_material, public_material, "key_directory_event", transcript)
        }
      ]
    }
  end

  defp signed_key_directory_checkpoint(payload, variant, private_material, signer_user_id \\ nil) do
    public_material = hybrid_signing_public_key_material(private_material)

    signer =
      public_material
      |> key_directory_signer(%{"user_id" => signer_user_id})
      |> key_directory_checkpoint_signer_authority(payload)

    transcript =
      Signature.build_key_directory_checkpoint_transcript!(
        variant,
        public_material["owner_kind"],
        public_material["owner_id"],
        payload,
        signer
      )

    %{
      "payload" => payload,
      "signatures" => [
        %{
          "signer" => signer,
          "signature" =>
            sign_transcript(
              private_material,
              public_material,
              "key_directory_checkpoint",
              transcript
            )
        }
      ]
    }
  end

  defp key_directory_checkpoint_signer_authority(
         signer,
         %{
           "scope_kind" => scope_kind,
           "scope_id" => scope_id,
           "sequence" => sequence,
           "previous_checkpoint_hash" => previous_checkpoint_hash
         }
       )
       when is_integer(sequence) and sequence > 1 and is_binary(previous_checkpoint_hash) do
    Map.merge(signer, %{
      "key_scope_kind" => scope_kind,
      "key_scope_id" => scope_id,
      "key_checkpoint_sequence" => sequence - 1,
      "key_checkpoint_hash" => previous_checkpoint_hash,
      "authorizing_checkpoint_sequence" => sequence - 1,
      "authorizing_checkpoint_hash" => previous_checkpoint_hash
    })
  end

  defp key_directory_checkpoint_signer_authority(signer, %{"sequence" => 1}), do: signer

  defp key_directory_event_signer_authority(signer, %{
         "actor" => actor,
         "sequence" => sequence
       })
       when is_map(actor) and is_integer(sequence) and sequence > 1 do
    Map.merge(
      signer,
      Map.take(actor, [
        "key_scope_kind",
        "key_scope_id",
        "key_checkpoint_sequence",
        "key_checkpoint_hash",
        "authorizing_checkpoint_sequence",
        "authorizing_checkpoint_hash",
        "role_at_event"
      ])
    )
  end

  defp key_directory_event_signer_authority(signer, _), do: signer

  defp test_key_directory_event_authority_boundary(attrs) do
    %{
      "scope_kind" => Map.fetch!(attrs, "scope_kind"),
      "scope_id" => Map.fetch!(attrs, "scope_id"),
      "checkpoint_sequence" =>
        Map.get(attrs, "checkpoint_sequence", Map.fetch!(attrs, "sequence")),
      "checkpoint_hash" =>
        Map.get(attrs, "checkpoint_hash", Hash.blake3_base64url("test-checkpoint")),
      "required_authority" => "event_type_authorized_actor"
    }
  end

  defp test_key_directory_checkpoint_authority_boundary(%{"sequence" => 1}) do
    %{"required_authority" => "tofu_root"}
  end

  defp test_key_directory_checkpoint_authority_boundary(_payload) do
    %{"required_authority" => "checkpoint_authorized"}
  end

  defp key_directory_signer(
         %{"owner_kind" => "identity", "owner_id" => user_id} = material,
         _context
       ) do
    %{
      "signer_kind" => "identity",
      "user_id" => user_id,
      "signing_key_id" => Signature.compute_signing_key_id!(material)
    }
  end

  defp key_directory_signer(
         %{"owner_kind" => "device", "owner_id" => device_id} = material,
         context
       ) do
    %{
      "signer_kind" => "device",
      "user_id" => Map.fetch!(context, "user_id"),
      "device_id" => device_id,
      "signing_key_id" => Signature.compute_signing_key_id!(material)
    }
  end

  defp key_directory_signer(
         %{"owner_kind" => "invitation_redeem_authority", "owner_id" => invitation_id} = material,
         _context
       ) do
    %{
      "signer_kind" => "invitation_redeem_authority",
      "invitation_id" => invitation_id,
      "signing_key_id" => Signature.compute_signing_key_id!(material)
    }
  end

  defp identity_actor(user_id, signing_key_id) do
    %{"signer_kind" => "identity", "user_id" => user_id, "signing_key_id" => signing_key_id}
  end

  defp device_actor(user_id, device_id, signing_key_id) do
    %{
      "signer_kind" => "device",
      "user_id" => user_id,
      "device_id" => device_id,
      "signing_key_id" => signing_key_id
    }
  end

  defp context_hash(value), do: value |> JCS.canonical_bytes!() |> Hash.blake3_base64url()

  defp event_ref(scope_kind, scope_id, event) do
    %{
      "scope_kind" => scope_kind,
      "scope_id" => scope_id,
      "event_sequence" => event["sequence"],
      "event_hash" => KeyDirectory.event_hash(event)
    }
  end

  defp append_key_entry_if_missing(entries, entry) do
    if Enum.any?(entries, &(&1["key_id"] == entry["key_id"])) do
      entries
    else
      entries ++ [entry]
    end
  end

  defp event_head(event) do
    %{
      "head_sequence" => event["sequence"],
      "head_hash" => KeyDirectory.event_hash(event)
    }
  end

  defp stringify_keys(map) do
    for {key, value} <- map, into: %{}, do: {to_string(key), value}
  end

  defp sign_transcript(private_material, public_material, signing_purpose, transcript) do
    transcript_bytes = JCS.canonical_bytes!(transcript)

    %{
      "protocol" => @signature_protocol,
      "version" => @protocol_version,
      "suite_id" => @suite_id,
      "suite_rank" => @suite_rank,
      "signing_key_id" => Signature.compute_signing_key_id!(public_material),
      "transcript_hash" => Hash.blake3_base64url(transcript_bytes),
      "ed25519" =>
        private_material["ed25519_private"]
        |> Encoding.decode_base64url!(32)
        |> then(&:crypto.sign(:eddsa, :none, transcript_bytes, [&1, :ed25519]))
        |> Encoding.encode_base64url(),
      "mldsa65" =>
        mldsa65_sign(
          transcript_bytes,
          @mldsa_context_prefix <> signing_purpose,
          Encoding.decode_base64url!(private_material["mldsa65_private"], 4032)
        )
        |> Encoding.encode_base64url()
    }
  end
end
