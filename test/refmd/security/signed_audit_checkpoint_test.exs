defmodule RefMD.Security.SignedAuditCheckpointTest do
  use RefMD.DataCase, async: false

  import Ecto.Query

  alias RefMD.Crypto.{Hash, Signature}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Repo
  alias RefMD.Security
  alias RefMD.Security.{AuditChainEvent, AuditEvent, SignedAuditCheckpoint}
  alias RefMD.TestCrypto

  test "persists an identity-signed genesis checkpoint with its audit event atomically" do
    user_id = Ecto.UUID.generate()
    private_material = TestCrypto.hybrid_signing_private_key_material("identity", user_id)
    public_material = TestCrypto.hybrid_signing_public_key_material(private_material)
    account_attrs = audit_attrs(user_id, "user.account.genesis")
    device_attrs = audit_attrs(user_id, "user.device.genesis_bootstrapped")
    account_hash = candidate_event_hash("user", user_id, 1, "GENESIS", account_attrs)
    event_hash = candidate_event_hash("user", user_id, 2, account_hash, device_attrs)

    payload =
      genesis_payload(
        "user",
        user_id,
        event_hash,
        "user.device.genesis_bootstrapped",
        user_id,
        Signature.compute_signing_key_id!(public_material)
      )

    transcript =
      Audit.build_audit_checkpoint_transcript!("user_identity", "identity", user_id, payload)

    signature =
      Signature.__test_sign_hybrid_signature__(
        "audit_checkpoint",
        transcript,
        private_material,
        public_material
      )

    envelope = %{
      "payload" => payload,
      "signature" => signature,
      "checkpoint_hash" => Audit.checkpoint_hash!("user_identity", payload)
    }

    assert {:ok, %{audit_events: [account_event, device_event], signed_checkpoint: checkpoint}} =
             Security.record_signed_audit_events([account_attrs, device_attrs], envelope, [],
               genesis_candidate_authority: genesis_authority(user_id, public_material)
             )

    assert account_event.event_hash == account_hash
    assert device_event.event_hash == event_hash
    assert checkpoint.checkpoint_hash == envelope["checkpoint_hash"]

    assert %{
             signed_checkpoint: ^envelope,
             ancestry: [
               %{"sequence" => 1, "event_hash" => ^account_hash},
               %{"sequence" => 2, "event_hash" => ^event_hash}
             ],
             unsigned_tail: [],
             current_event_head: %{sequence: 2, event_hash: ^event_hash}
           } = Security.current_signed_audit_checkpoint("user", user_id)
  end

  test "invalid checkpoint signature rolls back the event and checkpoint" do
    user_id = Ecto.UUID.generate()
    private_material = TestCrypto.hybrid_signing_private_key_material("identity", user_id)
    public_material = TestCrypto.hybrid_signing_public_key_material(private_material)
    account_attrs = audit_attrs(user_id, "user.account.genesis")
    device_attrs = audit_attrs(user_id, "user.device.genesis_bootstrapped")
    account_hash = candidate_event_hash("user", user_id, 1, "GENESIS", account_attrs)
    event_hash = candidate_event_hash("user", user_id, 2, account_hash, device_attrs)

    payload =
      genesis_payload(
        "user",
        user_id,
        event_hash,
        "user.device.genesis_bootstrapped",
        user_id,
        Signature.compute_signing_key_id!(public_material)
      )

    transcript =
      Audit.build_audit_checkpoint_transcript!("user_identity", "identity", user_id, payload)

    signature =
      Signature.__test_sign_hybrid_signature__(
        "audit_checkpoint",
        transcript,
        private_material,
        public_material
      )
      |> Map.put("ed25519", Base.url_encode64(:binary.copy(<<0>>, 64), padding: false))

    envelope = %{
      "payload" => payload,
      "signature" => signature,
      "checkpoint_hash" => Audit.checkpoint_hash!("user_identity", payload)
    }

    assert {:error, reason} =
             Security.record_signed_audit_events([account_attrs, device_attrs], envelope, [],
               genesis_candidate_authority: genesis_authority(user_id, public_material)
             )

    assert to_string(reason) =~ "audit_checkpoint_signature_invalid"
    refute Repo.exists?(from(e in AuditEvent, where: e.chain_scope == ^"user:#{user_id}"))
    refute Repo.exists?(from(c in SignedAuditCheckpoint, where: c.chain_scope_id == ^user_id))
  end

  test "rejects scope and head substitution before persistence" do
    user_id = Ecto.UUID.generate()

    public_material =
      "identity"
      |> TestCrypto.hybrid_signing_private_key_material(user_id)
      |> TestCrypto.hybrid_signing_public_key_material()

    account_attrs = audit_attrs(user_id, "user.account.genesis")
    device_attrs = audit_attrs(user_id, "user.device.genesis_bootstrapped")
    account_hash = candidate_event_hash("user", user_id, 1, "GENESIS", account_attrs)
    event_hash = candidate_event_hash("user", user_id, 2, account_hash, device_attrs)
    wrong_scope_id = Ecto.UUID.generate()

    payload =
      genesis_payload(
        "user",
        wrong_scope_id,
        event_hash,
        "user.device.genesis_bootstrapped",
        user_id,
        Signature.compute_signing_key_id!(public_material)
      )

    envelope = %{
      "payload" => payload,
      "signature" => empty_signature(payload["signing_key_id"]),
      "checkpoint_hash" => Audit.checkpoint_hash!("user_identity", payload)
    }

    assert {:error, "audit_checkpoint_event_head_mismatch"} =
             Security.record_signed_audit_events([account_attrs, device_attrs], envelope, [],
               genesis_candidate_authority:
                 genesis_authority(user_id, public_material)
                 |> Map.put(:chain_scope_id, wrong_scope_id)
             )

    refute Repo.exists?(from(e in AuditEvent, where: e.chain_scope == ^"user:#{user_id}"))
  end

  test "genesis checkpoint may cover multiple initial audit events without a previous checkpoint" do
    user_id = Ecto.UUID.generate()

    public_material =
      "identity"
      |> TestCrypto.hybrid_signing_private_key_material(user_id)
      |> TestCrypto.hybrid_signing_public_key_material()

    payload =
      genesis_payload(
        "user",
        user_id,
        Hash.blake3_base64url("second-genesis-event"),
        "user.device.genesis_bootstrapped",
        user_id,
        Signature.compute_signing_key_id!(public_material)
      )
      |> Map.put("sequence", 2)

    transcript =
      Audit.build_audit_checkpoint_transcript!("user_identity", "identity", user_id, payload)

    refute Map.has_key?(transcript["checkpoint"], "previous_signed_checkpoint_sequence")
    refute Map.has_key?(transcript["checkpoint"], "previous_signed_checkpoint_hash")

    assert transcript["authority_boundary"] == %{
             "scope_kind" => "user",
             "scope_id" => user_id,
             "checkpoint_protocol" => "refmd.signed-key-directory-checkpoint",
             "checkpoint_version" => 1,
             "checkpoint_hash_domain" => "BLAKE3-256(JCS(payload))",
             "checkpoint_sequence" => 0,
             "checkpoint_hash" => "GENESIS",
             "required_authority" => "audit_event_authorized_actor"
           }
  end

  test "persists a workspace genesis checkpoint from the exact candidate device authority" do
    user_id = Ecto.UUID.generate()
    device_id = Ecto.UUID.generate()
    workspace_id = Ecto.UUID.generate()
    private_material = TestCrypto.hybrid_signing_private_key_material("device", device_id)
    public_material = TestCrypto.hybrid_signing_public_key_material(private_material)
    attrs = workspace_genesis_attrs(workspace_id, user_id, device_id)
    event_hash = candidate_event_hash("workspace", workspace_id, 1, "GENESIS", attrs)

    payload =
      genesis_payload(
        "workspace",
        workspace_id,
        event_hash,
        "workspace.genesis",
        user_id,
        Signature.compute_signing_key_id!(public_material)
      )
      |> Map.put("sequence", 1)
      |> Map.put("signer_device_id", device_id)

    transcript =
      Audit.build_audit_checkpoint_transcript!("workspace_device", "device", device_id, payload)

    envelope = %{
      "payload" => payload,
      "signature" =>
        Signature.__test_sign_hybrid_signature__(
          "audit_checkpoint",
          transcript,
          private_material,
          public_material
        ),
      "checkpoint_hash" => Audit.checkpoint_hash!("workspace_device", payload)
    }

    authority = %{
      chain_scope_kind: "workspace",
      chain_scope_id: workspace_id,
      signer_user_id: user_id,
      signer_device_id: device_id,
      public_key_material: public_material
    }

    assert {:ok, %{audit_events: [event], signed_checkpoint: checkpoint}} =
             Security.record_signed_audit_events([attrs], envelope, [],
               genesis_candidate_authority: authority
             )

    assert event.event_hash == event_hash
    assert checkpoint.variant == "workspace_device"
  end

  test "rejects high-risk events without a signed checkpoint" do
    user_id = Ecto.UUID.generate()

    assert {:error, :signed_audit_checkpoint_required} =
             Security.record_audit_event(audit_attrs(user_id, "user.account.genesis"))

    refute Repo.exists?(from(e in AuditEvent, where: e.chain_scope == ^"user:#{user_id}"))
  end

  test "returns low-risk events only in the unsigned tail" do
    user_id = Ecto.UUID.generate()
    private_material = TestCrypto.hybrid_signing_private_key_material("identity", user_id)
    public_material = TestCrypto.hybrid_signing_public_key_material(private_material)
    account_attrs = audit_attrs(user_id, "user.account.genesis")
    device_attrs = audit_attrs(user_id, "user.device.genesis_bootstrapped")
    account_hash = candidate_event_hash("user", user_id, 1, "GENESIS", account_attrs)
    event_hash = candidate_event_hash("user", user_id, 2, account_hash, device_attrs)
    signing_key_id = Signature.compute_signing_key_id!(public_material)

    payload =
      genesis_payload("user", user_id, event_hash, device_attrs.type, user_id, signing_key_id)

    transcript =
      Audit.build_audit_checkpoint_transcript!("user_identity", "identity", user_id, payload)

    envelope = %{
      "payload" => payload,
      "signature" =>
        Signature.__test_sign_hybrid_signature__(
          "audit_checkpoint",
          transcript,
          private_material,
          public_material
        ),
      "checkpoint_hash" => Audit.checkpoint_hash!("user_identity", payload)
    }

    assert {:ok, _} =
             Security.record_signed_audit_events([account_attrs, device_attrs], envelope, [],
               genesis_candidate_authority: genesis_authority(user_id, public_material)
             )

    low_risk_attrs = runtime_audit_attrs(user_id)
    assert {:ok, _} = Security.record_audit_event(low_risk_attrs)

    assert %{
             ancestry: [%{"sequence" => 1}, %{"sequence" => 2}],
             unsigned_tail: [%{"sequence" => 3, "event_type" => "plugin.ui.invocation.rejected"}],
             current_event_head: %{sequence: 3}
           } = Security.current_signed_audit_checkpoint("user", user_id)
  end

  defp genesis_payload(scope_kind, scope_id, event_hash, event_type, user_id, signing_key_id) do
    %{
      "protocol" => "refmd.signed-audit-checkpoint",
      "version" => 1,
      "chain_scope_kind" => scope_kind,
      "chain_scope_id" => scope_id,
      "sequence" => 2,
      "event_hash" => event_hash,
      "signer_user_id" => user_id,
      "signing_key_id" => signing_key_id,
      "authorization_checkpoint_scope_kind" => scope_kind,
      "authorization_checkpoint_scope_id" => scope_id,
      "authorization_checkpoint_sequence" => 0,
      "authorization_checkpoint_hash" => "GENESIS",
      "covered_event_class" => "authority",
      "covered_event_type" => event_type
    }
  end

  defp runtime_audit_attrs(user_id) do
    audit_attrs(user_id, "plugin.ui.invocation.rejected")
    |> Map.drop([:event_body, :event_id])
    |> Map.put(:class, "security_runtime")
    |> put_in([:resource, "kind"], "plugin")
    |> put_in([:action, "operation"], "invoke")
    |> put_in([:action, "result"], "denied")
    |> put_in([:action, "reason_code"], "policy")
  end

  defp genesis_authority(user_id, public_material) do
    %{
      chain_scope_kind: "user",
      chain_scope_id: user_id,
      signer_user_id: user_id,
      signer_device_id: nil,
      public_key_material: public_material
    }
  end

  defp workspace_genesis_attrs(workspace_id, user_id, device_id) do
    type = "workspace.genesis"

    %{
      event_id: Ecto.UUID.generate(),
      class: "authority",
      type: type,
      event_body: %{
        "protocol" => "refmd.audit.high-risk-mutation",
        "version" => 1,
        "event_type" => type,
        "mutation_id" => Ecto.UUID.generate(),
        "chain_scope_kind" => "workspace",
        "chain_scope_id" => workspace_id,
        "actor" => %{"kind" => "device", "user_id" => user_id, "device_id" => device_id},
        "subject_kind" => "workspace",
        "subject_id" => workspace_id,
        "canonical_request_hash" => Hash.blake3_base64url("canonical-request"),
        "key_directory_effects_hash" => Hash.blake3_base64url("key-directory-effects")
      },
      actor: %{
        "user_id" => user_id,
        "device_id" => device_id,
        "session_id" => nil,
        "principal_kind" => "user",
        "principal_id" => user_id
      },
      scope: %{"workspace_id" => workspace_id, "document_id" => nil, "share_id" => nil},
      resource: %{"kind" => "workspace", "id" => workspace_id, "version_hash" => nil},
      action: %{"operation" => type, "result" => "completed", "reason_code" => nil},
      sensitivity: Security.empty_sensitivity(),
      correlation: %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => nil
      }
    }
  end

  defp candidate_event_hash(scope_kind, scope_id, sequence, previous_hash, attrs) do
    %{
      event_id: attrs.event_id,
      chain_scope_kind: scope_kind,
      chain_scope_id: scope_id,
      sequence: sequence,
      previous_event_hash: previous_hash,
      event_type: attrs.type,
      event_body: attrs.event_body
    }
    |> AuditChainEvent.build!()
    |> AuditChainEvent.hash!()
  end

  defp audit_attrs(user_id, type) do
    event_id = Ecto.UUID.generate()

    %{
      event_id: event_id,
      class: "authority",
      type: type,
      event_body: %{
        "protocol" => "refmd.audit.high-risk-mutation",
        "version" => 1,
        "event_type" => type,
        "mutation_id" => Ecto.UUID.generate(),
        "chain_scope_kind" => "user",
        "chain_scope_id" => user_id,
        "actor" => %{"kind" => "identity", "user_id" => user_id},
        "subject_kind" => "account",
        "subject_id" => user_id,
        "canonical_request_hash" => Hash.blake3_base64url("canonical-request"),
        "key_directory_effects_hash" => Hash.blake3_base64url("key-directory-effects")
      },
      actor: %{
        "user_id" => user_id,
        "device_id" => nil,
        "session_id" => nil,
        "principal_kind" => "user",
        "principal_id" => user_id
      },
      scope: %{"workspace_id" => nil, "document_id" => nil, "share_id" => nil},
      resource: %{"kind" => "user", "id" => user_id, "version_hash" => nil},
      action: %{"operation" => type, "result" => "completed", "reason_code" => nil},
      sensitivity: Security.empty_sensitivity(),
      correlation: %{
        "request_id" => nil,
        "capability_id" => nil,
        "execution_context_id" => nil,
        "authority_event_ref" => nil
      }
    }
  end

  defp empty_signature(signing_key_id) do
    %{
      "protocol" => "refmd.hybrid-signature",
      "version" => 1,
      "suite_id" => "refmd-v2-hybrid-signature-ed25519-mldsa65",
      "suite_rank" => 1000,
      "signing_key_id" => signing_key_id,
      "transcript_hash" => Hash.blake3_base64url("invalid"),
      "ed25519" => Base.url_encode64(:binary.copy(<<0>>, 64), padding: false),
      "mldsa65" => Base.url_encode64(:binary.copy(<<0>>, 3309), padding: false)
    }
  end
end
