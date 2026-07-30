defmodule RefMD.Devices.Revocations.CompoundTest do
  use RefMD.DataCase, async: false

  alias RefMD.Crypto.{Hash, HybridEncryptionMaterial, Signature}
  alias RefMD.Crypto.Signature.Audit
  alias RefMD.Devices
  alias RefMD.Devices.Device
  alias RefMD.Devices.Revocations.{Intent, Prepare}
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.KeyDirectory.Payload
  alias RefMD.Repo
  alias RefMD.Security.CompoundAppend
  alias RefMD.TestCrypto
  alias RefMD.Users.User

  test "retire uses an exact signed compound commit and exact receipt replay" do
    user_id = insert_user!()
    actor = insert_device!(user_id)
    target = insert_device!(user_id)
    actor = install_user_security_state!(user_id, actor)
    append_target_device!(user_id, target)

    command = %{"device_id" => target.device.id, "revocation_mode" => "retire"}

    assert {:ok, intent} =
             Devices.prepare_device_revocation(
               user_id,
               actor.device.id,
               target.device.id,
               command
             )

    assert is_nil(Repo.get!(Device, target.device.id).revoked_at)

    authorization = authorize!(intent, user_id, actor, target)

    assert {:ok, %{response: response, replay?: false}} =
             Devices.commit_device_revocation(
               user_id,
               actor.device.id,
               target.device.id,
               authorization
             )

    assert response["status"] == "committed"
    assert response["revoked_device_id"] == target.device.id
    assert response["workspaces_needing_kek_rotation"] == []
    assert Repo.get!(Device, target.device.id).revoked_at

    assert KeyDirectory.current_checkpoint("user", user_id).checkpoint_hash ==
             response["user_key_directory_checkpoint_hash"]

    assert {:ok, %{response: ^response, replay?: true}} =
             Devices.commit_device_revocation(
               user_id,
               actor.device.id,
               target.device.id,
               authorization
             )

    tampered =
      put_in(authorization, ["effect_authorizations", Access.at(0), "approval_proof"], %{})

    assert {:error, "audit_checkpoint_intent_reuse"} =
             Devices.commit_device_revocation(
               user_id,
               actor.device.id,
               target.device.id,
               tampered
             )
  end

  test "security mode fails closed until its cross-scope complete set is implemented" do
    user_id = insert_user!()
    actor = insert_device!(user_id) |> then(&install_user_security_state!(user_id, &1))
    target = insert_device!(user_id)

    assert {:error, "security_device_revocation_complete_set_not_implemented"} =
             Devices.prepare_device_revocation(
               user_id,
               actor.device.id,
               target.device.id,
               %{"device_id" => target.device.id, "revocation_mode" => "security"}
             )

    assert is_nil(Repo.get!(Device, target.device.id).revoked_at)
  end

  defp authorize!(intent, user_id, actor, target) do
    [scope] = intent["scopes"]
    [audit_event] = scope["candidate_events"]
    identity_private = TestCrypto.hybrid_signing_private_key_material("identity", user_id)
    identity_public = TestCrypto.hybrid_signing_public_key_material(identity_private)

    audit_payload =
      prepared_for_payload(user_id, actor.device.id, target.device.id)
      |> Intent.audit_checkpoint_payload(audit_event)

    audit_transcript =
      Audit.build_audit_checkpoint_transcript!(
        "user_device",
        "device",
        actor.device.id,
        audit_payload
      )

    scope_signature =
      Signature.__test_sign_hybrid_signature__(
        "audit_checkpoint",
        audit_transcript,
        actor.private,
        actor.public
      )

    effect_authorizations =
      Enum.map(scope["effect_signature_requirements"], fn requirement ->
        {transcript, private, public} =
          authorization_transcript(
            requirement,
            scope,
            user_id,
            actor,
            target,
            identity_private,
            identity_public
          )

        signature =
          Signature.__test_sign_hybrid_signature__(
            requirement["signing_purpose"],
            transcript,
            private,
            public
          )

        Map.merge(requirement, %{"signature" => signature, "approval_proof" => "NONE"})
      end)

    %{
      "protocol" => "refmd.audit.compound-append-authorization",
      "version" => 1,
      "compound_intent_id" => intent["compound_intent_id"],
      "mutation_id" => intent["mutation_id"],
      "intent_hash" => CompoundAppend.hash(intent),
      "scope_signatures" => [
        %{
          "chain_scope_kind" => "user",
          "chain_scope_id" => user_id,
          "checkpoint_hash" => scope["checkpoint_payload_hash"],
          "checkpoint_variant" => "user_device",
          "signature" => scope_signature
        }
      ],
      "effect_authorizations" => effect_authorizations
    }
  end

  defp authorization_transcript(
         %{"authorization_kind" => "key_directory_event"} = requirement,
         scope,
         user_id,
         _actor,
         _target,
         identity_private,
         identity_public
       ) do
    effect =
      Enum.at(scope["candidate_key_directory_effects"], requirement["requirement_order"] - 1)

    payload = effect["event_payload"]

    {Signature.build_key_directory_event_transcript!(
       payload["event_type"],
       "identity",
       user_id,
       payload
     ), identity_private, identity_public}
  end

  defp authorization_transcript(
         %{"authorization_kind" => "key_directory_checkpoint"},
         scope,
         user_id,
         _actor,
         _target,
         identity_private,
         identity_public
       ) do
    checkpoint = KeyDirectory.current_checkpoint("user", user_id)

    signer = %{
      "signer_kind" => "identity",
      "user_id" => user_id,
      "signing_key_id" => Signature.compute_signing_key_id!(identity_public),
      "authorizing_checkpoint_sequence" => checkpoint.sequence,
      "authorizing_checkpoint_hash" => checkpoint.checkpoint_hash
    }

    {Signature.build_key_directory_checkpoint_transcript!(
       "identity_active",
       "identity",
       user_id,
       scope["candidate_key_directory_checkpoint_payload"],
       signer
     ), identity_private, identity_public}
  end

  defp authorization_transcript(
         %{"authorization_kind" => "device_revocation"},
         scope,
         user_id,
         actor,
         target,
         _identity_private,
         _identity_public
       ) do
    [event] = scope["candidate_events"]
    checkpoint = KeyDirectory.current_checkpoint("user", user_id)

    transcript =
      Signature.build_device_revocation_transcript!(
        actor.device.id,
        %{
          "user_id" => user_id,
          "device_id" => actor.device.id,
          "signing_key_id" => actor.device.signing_key_id,
          "key_scope_kind" => "user",
          "key_scope_id" => user_id,
          "key_checkpoint_sequence" => checkpoint.sequence,
          "key_checkpoint_hash" => checkpoint.checkpoint_hash
        },
        %{
          "user_id" => user_id,
          "device_id" => target.device.id,
          "encryption_key_id" => target.device.encryption_key_id,
          "signing_key_id" => target.device.signing_key_id
        },
        %{
          "revocation_event_sequence" => event["sequence"],
          "revocation_event_hash" => event["event_hash"]
        }
      )

    {transcript, actor.private, actor.public}
  end

  defp prepared_for_payload(user_id, actor_device_id, target_device_id) do
    command = %{"device_id" => target_device_id, "revocation_mode" => "retire"}

    Prepare.validate!(
      user_id,
      actor_device_id,
      target_device_id,
      command
    )
  end

  defp install_user_security_state!(user_id, actor) do
    actor_device = TestCrypto.ensure_test_user_rrp_key_directory!(user_id, actor.device)
    TestCrypto.install_signed_audit_genesis!("user", user_id, user_id)
    %{actor | device: actor_device}
  end

  defp append_target_device!(user_id, target) do
    checkpoint = KeyDirectory.current_checkpoint("user", user_id)
    head = checkpoint.payload["covered_event_head"]
    identity_private = TestCrypto.hybrid_signing_private_key_material("identity", user_id)
    identity_public = TestCrypto.hybrid_signing_public_key_material(identity_private)

    actor = %{
      "signer_kind" => "identity",
      "user_id" => user_id,
      "signing_key_id" => Signature.compute_signing_key_id!(identity_public),
      "key_scope_kind" => "user",
      "key_scope_id" => user_id,
      "key_checkpoint_sequence" => checkpoint.sequence,
      "key_checkpoint_hash" => checkpoint.checkpoint_hash
    }

    event =
      KeyDirectory.build_event_payload!(%{
        "scope_kind" => "user",
        "scope_id" => user_id,
        "sequence" => head["head_sequence"] + 1,
        "previous_event_hash" => head["head_hash"],
        "event_type" => "device_key_added",
        "actor" => actor,
        "body" => %{
          "user_id" => user_id,
          "device_id" => target.device.id,
          "signing_key_id" => target.device.signing_key_id,
          "encryption_key_id" => target.device.encryption_key_id
        }
      })

    event_ref = %{
      "scope_kind" => "user",
      "scope_id" => user_id,
      "event_sequence" => event["sequence"],
      "event_hash" => KeyDirectory.event_hash(event)
    }

    payload =
      checkpoint.payload
      |> Map.put("sequence", checkpoint.sequence + 1)
      |> Map.put(
        "issued_at",
        DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601()
      )
      |> Map.put("previous_checkpoint_hash", checkpoint.checkpoint_hash)
      |> Map.put("covered_event_head", %{
        "head_sequence" => event["sequence"],
        "head_hash" => KeyDirectory.event_hash(event)
      })
      |> Map.update!("device_keys", fn entries ->
        entries ++
          [
            Payload.key_entry!(target.public, event_ref),
            Payload.key_entry!(target.encryption, event_ref)
          ]
      end)

    event_transcript =
      Signature.build_key_directory_event_transcript!(
        "device_key_added",
        "identity",
        user_id,
        event
      )

    signer = %{
      "signer_kind" => "identity",
      "user_id" => user_id,
      "signing_key_id" => Signature.compute_signing_key_id!(identity_public),
      "authorizing_checkpoint_sequence" => checkpoint.sequence,
      "authorizing_checkpoint_hash" => checkpoint.checkpoint_hash
    }

    checkpoint_transcript =
      Signature.build_key_directory_checkpoint_transcript!(
        "identity_active",
        "identity",
        user_id,
        payload,
        signer
      )

    KeyDirectory.append_signed_scope!(
      "user",
      user_id,
      [
        %{
          "payload" => event,
          "signatures" => [
            %{
              "signer" => actor,
              "signature" =>
                sign("key_directory_event", event_transcript, identity_private, identity_public)
            }
          ]
        }
      ],
      %{
        "payload" => payload,
        "signatures" => [
          %{
            "signer" => signer,
            "signature" =>
              sign(
                "key_directory_checkpoint",
                checkpoint_transcript,
                identity_private,
                identity_public
              )
          }
        ]
      },
      checkpoint_signer_kind: "identity"
    )
  end

  defp insert_user! do
    id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: id,
      email: "revocation-#{id}@example.com",
      name: "Revocation",
      account_type: "registered"
    })

    id
  end

  defp insert_device!(user_id) do
    id = Ecto.UUID.generate()
    private = TestCrypto.hybrid_signing_private_key_material("device", id)
    public = TestCrypto.hybrid_signing_public_key_material(private)
    {x25519, _} = :crypto.generate_key(:ecdh, :x25519)
    encryption = TestCrypto.hybrid_encryption_public_key_material("device", id, x25519).public
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    device =
      Repo.insert!(%Device{
        id: id,
        user_id: user_id,
        name: "Browser",
        device_type: "browser",
        hybrid_signing_public_key_material: public,
        signing_key_id: Signature.compute_signing_key_id!(public),
        hybrid_encryption_public_key_material: encryption,
        encryption_key_id: HybridEncryptionMaterial.compute_key_id!(encryption),
        key_checkpoint_sequence: 1,
        key_checkpoint_hash: Hash.blake3_base64url("pending-checkpoint:#{id}"),
        client_nonce: :crypto.strong_rand_bytes(16),
        last_seen_at: now,
        created_at: now
      })

    %{device: device, private: private, public: public, encryption: encryption}
  end

  defp sign(purpose, transcript, private, public),
    do: Signature.__test_sign_hybrid_signature__(purpose, transcript, private, public)
end
