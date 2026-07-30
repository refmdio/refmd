defmodule RefMD.Workspaces.InvitationRecipientTest do
  use RefMD.DataCase, async: true

  import Ecto.Query

  alias Ecto.Adapters.SQL.Sandbox
  alias RefMD.Crypto.{Encoding, Hash, JCS, Signature}
  alias RefMD.Devices.Device
  alias RefMD.Encryption
  alias RefMD.Encryption.KeyDirectory.PinBootstrap
  alias RefMD.Encryption.RotationPolicy
  alias RefMD.Encryption.UserIdentityPublicKey
  alias RefMD.Encryption.Wraps.SignedPQ
  alias RefMD.Repo
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMD.Workspaces.{InvitationDeliveryAttempt, WorkspaceInvitation, WorkspaceMember}

  test "known workspace invitation accepts only the bound active recipient device" do
    Sandbox.unboxed_run(Repo, fn ->
      owner = insert_user("workspace-invite-owner")
      recipient = insert_user("workspace-invite-recipient")
      {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Invitation Recipient")

      {1, _} =
        from(w in Workspaces.Workspace, where: w.id == ^workspace.id)
        |> Repo.update_all(
          set: [
            current_kek_version: 1,
            min_kek_version: 1,
            kek_rotation_due_at: RotationPolicy.next_kek_due_at()
          ]
        )

      role =
        Repo.get_by!(Workspaces.WorkspaceRole, workspace_id: workspace.id, base_role: "viewer")

      device = insert_device(recipient.id)
      invitation = insert_invitation(workspace.id, owner.id, recipient, device.id, role.id)

      assert {:error, :recipient_mismatch} =
               Workspaces.accept_invitation(
                 invitation.token_hash,
                 owner.id,
                 owner.email,
                 device.id,
                 nil
               )

      assert {:error, :recipient_device_mismatch} =
               Workspaces.accept_invitation(
                 invitation.token_hash,
                 recipient.id,
                 recipient.email,
                 Ecto.UUID.generate(),
                 nil
               )

      assert {:error, :recipient_delivery_required} =
               Workspaces.accept_invitation(
                 invitation.token_hash,
                 recipient.id,
                 recipient.email,
                 device.id,
                 nil
               )

      owner_device = insert_device(owner.id)

      existing_member_invitation =
        insert_invitation(workspace.id, owner.id, owner, owner_device.id, role.id)

      assert {:error, :recipient_already_member} =
               Workspaces.accept_invitation(
                 existing_member_invitation.token_hash,
                 owner.id,
                 owner.email,
                 owner_device.id,
                 nil
               )

      device
      |> Ecto.Changeset.change(revoked_at: DateTime.utc_now())
      |> Repo.update!()

      assert {:error, :recipient_device_revoked} =
               Workspaces.accept_invitation(
                 invitation.token_hash,
                 recipient.id,
                 recipient.email,
                 device.id,
                 nil
               )

      Repo.delete!(workspace)
      Repo.delete!(owner)
      Repo.delete!(recipient)
    end)
  end

  test "workspace and guest creation revalidate stale unknown recipient bindings" do
    Sandbox.unboxed_run(Repo, fn ->
      owner = insert_user("stale-recipient-owner")
      recipient = insert_user("stale-recipient-registered")
      {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Stale Recipient")

      {1, _} =
        from(w in Workspaces.Workspace, where: w.id == ^workspace.id)
        |> Repo.update_all(
          set: [
            current_kek_version: 1,
            min_kek_version: 1,
            guest_invites_enabled: true,
            kek_rotation_due_at: RotationPolicy.next_kek_due_at()
          ]
        )

      stale_binding = %{
        workspace_id: workspace.id,
        invited_by: owner.id,
        invited_email: recipient.email,
        delivery_mode: "unknown_fragment",
        recipient_user_id: nil,
        recipient_device_ids: [],
        scope_kind: "workspace",
        scope_id: nil,
        share_id: nil,
        kek_version: 1
      }

      assert {:error, :recipient_delivery_unavailable} =
               Workspaces.create_invitation(stale_binding)

      assert {:error, :recipient_delivery_unavailable} =
               Workspaces.create_guest_invitation(stale_binding)

      Repo.delete!(workspace)
      Repo.delete!(owner)
      Repo.delete!(recipient)
    end)
  end

  test "known workspace delivery attempt is bound to the registered recipient keys" do
    Sandbox.unboxed_run(Repo, fn ->
      owner = insert_user("workspace-delivery-owner")
      recipient = insert_user("workspace-delivery-recipient")
      other = insert_user("workspace-delivery-other")
      {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Invitation Delivery")

      role =
        Repo.get_by!(Workspaces.WorkspaceRole, workspace_id: workspace.id, base_role: "viewer")

      device = insert_device(recipient.id)
      identity = insert_identity_public_key(recipient.id)
      invitation = insert_invitation(workspace.id, owner.id, recipient, device.id, role.id)
      attrs = delivery_attempt_attrs(recipient.id, device, identity)

      assert {:error, :recipient_mismatch} =
               Workspaces.create_invitation_delivery_attempt(
                 invitation.token_hash,
                 other.id,
                 device.id,
                 attrs
               )

      tampered =
        put_in(
          attrs,
          ["target_registration", "device_hybrid_encryption_public_key_material"],
          identity.hybrid_encryption_public_key_material
        )

      assert {:error, :recipient_target_key_mismatch} =
               Workspaces.create_invitation_delivery_attempt(
                 invitation.token_hash,
                 recipient.id,
                 device.id,
                 tampered
               )

      assert {:ok, attempt} =
               Workspaces.create_invitation_delivery_attempt(
                 invitation.token_hash,
                 recipient.id,
                 device.id,
                 attrs
               )

      assert attempt.context_kind == "workspace_invitation"
      assert attempt.context_id == invitation.id
      assert attempt.recipient_user_id == recipient.id
      assert attempt.recipient_device_id == device.id
      assert attempt.target_encryption_key_id == device.encryption_key_id
      assert attempt.status == "pending"
      assert [listed] = Workspaces.list_pending_invitation_delivery_attempts(workspace.id)
      assert listed.id == attempt.id

      device
      |> Ecto.Changeset.change(revoked_at: DateTime.utc_now())
      |> Repo.update!()

      revoked_attrs = Map.put(attrs, "redeem_attempt_id", Ecto.UUID.generate())

      assert {:error, :recipient_device_revoked} =
               Workspaces.create_invitation_delivery_attempt(
                 invitation.token_hash,
                 recipient.id,
                 device.id,
                 revoked_attrs
               )

      Repo.delete!(workspace)
      Repo.delete!(owner)
      Repo.delete!(recipient)
      Repo.delete!(other)
    end)
  end

  test "guest delivery approval rolls back when covered checkpoint head diverges" do
    Sandbox.unboxed_run(Repo, fn ->
      owner = insert_user("guest-wrap-owner")
      recipient = insert_user("guest-wrap-recipient")
      {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Guest Wrap Binding")

      owner_role =
        Repo.get_by!(Workspaces.WorkspaceRole, workspace_id: workspace.id, base_role: "owner")

      owner_device = insert_device(owner.id)
      recipient_device = insert_device(recipient.id)
      insert_workspace_key_directory!(workspace.id, owner, owner_device, owner_role.id)

      attempt =
        %InvitationDeliveryAttempt{}
        |> InvitationDeliveryAttempt.create_changeset(%{
          id: Ecto.UUID.generate(),
          workspace_id: workspace.id,
          context_kind: "guest_invitation",
          context_id: Ecto.UUID.generate(),
          recipient_user_id: recipient.id,
          recipient_device_id: recipient_device.id,
          target_user_id: recipient.id,
          target_device_id: recipient_device.id,
          target_encryption_key_id: recipient_device.encryption_key_id,
          target_registration: %{"fixture" => "guest-wrap-binding"},
          target_registration_proof: %{"fixture" => "guest-wrap-binding"},
          recipient_redeem_nonce: Hash.blake3_base64url("guest-wrap-redeem-nonce"),
          live_redeem_challenge_hash: Hash.blake3_base64url("guest-wrap-live-challenge"),
          recipient_nonce_state_hash: Hash.blake3_base64url("guest-wrap-nonce-state"),
          request_binding_hash: Hash.blake3_base64url("guest-wrap-request-binding"),
          resource_hash: Hash.blake3_base64url("guest-wrap-resource"),
          context_snapshot: %{
            "scope_kind" => "workspace",
            "scope_id" => "none",
            "permission" => "view",
            "kek_version" => 1
          },
          status: "pending",
          expires_at: DateTime.add(DateTime.utc_now(), 300, :second)
        })
        |> Repo.insert!()

      checkpoint = Encryption.current_workspace_key_directory_checkpoint(workspace.id)
      checkpoint_payload = checkpoint.payload
      checkpoint_hash = checkpoint.checkpoint_hash
      covered_head = checkpoint_payload["covered_event_head"]
      freshness_proof = authoritative_freshness_proof(attempt, owner, owner_device, checkpoint)
      workspace_pin_bootstrap = test_workspace_pin_bootstrap!(workspace.id)

      authorization =
        recipient_bound_authorization(
          attempt,
          owner,
          owner_device,
          checkpoint,
          freshness_proof,
          workspace_pin_bootstrap
        )

      mismatches = [
        {covered_head["head_sequence"] + 1, covered_head["head_hash"]},
        {covered_head["head_sequence"], Hash.blake3_base64url("wrong-covered-head")}
      ]

      for {covered_sequence, covered_hash} <- mismatches do
        artifacts = %{
          "authorization" => authorization,
          "delivery_wrap" =>
            guest_delivery_wrap_container(
              checkpoint_payload["sequence"],
              checkpoint_hash,
              covered_sequence,
              covered_hash
            ),
          "redeem_freshness_proof" => freshness_proof,
          "workspace_key_directory_checkpoint" => %{
            "payload" => checkpoint_payload,
            "signatures" => checkpoint.signatures
          },
          "workspace_key_directory_events" => [],
          "workspace_key_directory_intermediate_checkpoint" => %{},
          "workspace_pin_bootstrap" => workspace_pin_bootstrap
        }

        assert {:error, :invalid_delivery_operation_checkpoint} =
                 Workspaces.approve_invitation_delivery_attempt(
                   workspace.id,
                   attempt.id,
                   owner.id,
                   owner_device.id,
                   artifacts
                 )

        reloaded = Repo.get!(InvitationDeliveryAttempt, attempt.id)
        assert reloaded.status == "pending"
        assert is_nil(reloaded.authorization_id)
        assert is_nil(reloaded.approved_artifacts)
        assert is_nil(reloaded.approved_at)
      end

      Repo.delete!(workspace)
      Repo.delete!(owner)
      Repo.delete!(recipient)
    end)
  end

  test "member gossip quorum requires distinct authorized users and exact proof hashes" do
    Sandbox.unboxed_run(Repo, fn ->
      owner = insert_user("gossip-quorum-owner")
      member = insert_user("gossip-quorum-member")
      recipient = insert_user("gossip-quorum-recipient")
      outsider = insert_user("gossip-quorum-outsider")
      {:ok, workspace} = Workspaces.create_default_workspace(owner.id, "Gossip Quorum")

      owner_role =
        Repo.get_by!(Workspaces.WorkspaceRole, workspace_id: workspace.id, base_role: "owner")

      viewer_role =
        Repo.get_by!(Workspaces.WorkspaceRole, workspace_id: workspace.id, base_role: "viewer")

      Repo.insert!(%WorkspaceMember{
        workspace_id: workspace.id,
        user_id: member.id,
        role_id: viewer_role.id,
        joined_at: DateTime.utc_now()
      })

      owner_device = insert_device(owner.id)
      member_device = insert_device(member.id)
      outsider_device = insert_device(outsider.id)
      recipient_device = insert_device(recipient.id)
      identity = insert_identity_public_key(recipient.id)

      insert_workspace_key_directory!(workspace.id, owner, owner_device, owner_role.id)

      invitation =
        insert_invitation(workspace.id, owner.id, recipient, recipient_device.id, viewer_role.id)

      assert {:ok, attempt} =
               Workspaces.create_invitation_delivery_attempt(
                 invitation.token_hash,
                 recipient.id,
                 recipient_device.id,
                 delivery_attempt_attrs(recipient.id, recipient_device, identity)
               )

      owner_statement = gossip_statement(attempt, owner, owner_device)
      member_statement = gossip_statement(attempt, member, member_device)
      outsider_statement = gossip_statement(attempt, outsider, outsider_device)
      valid_proof = gossip_quorum_proof(attempt, [owner_statement, member_statement])

      assert {:error, :invalid_recipient_bound_authorization} =
               approve_with_freshness(workspace.id, attempt.id, owner, owner_device, valid_proof)

      duplicate_user = gossip_quorum_proof(attempt, [owner_statement, owner_statement])

      assert {:error, :invalid_redeem_freshness_proof} =
               approve_with_freshness(
                 workspace.id,
                 attempt.id,
                 owner,
                 owner_device,
                 duplicate_user
               )

      unauthorized = gossip_quorum_proof(attempt, [owner_statement, outsider_statement])

      assert {:error, :invalid_redeem_freshness_proof} =
               approve_with_freshness(
                 workspace.id,
                 attempt.id,
                 owner,
                 owner_device,
                 unauthorized
               )

      [owner_hash, member_hash] = valid_proof["proof_hashes"]

      invalid_hash_sets = [
        [Hash.blake3_base64url("mismatched-proof") | tl(valid_proof["proof_hashes"])],
        [owner_hash],
        [owner_hash, member_hash, Hash.blake3_base64url("extra-proof")]
      ]

      for proof_hashes <- invalid_hash_sets do
        assert {:error, :invalid_redeem_freshness_proof} =
                 approve_with_freshness(
                   workspace.id,
                   attempt.id,
                   owner,
                   owner_device,
                   Map.put(valid_proof, "proof_hashes", proof_hashes)
                 )
      end

      duplicate_hashes = Map.put(valid_proof, "proof_hashes", [owner_hash, owner_hash])

      assert {:error, :invalid_redeem_freshness_proof} =
               approve_with_freshness(
                 workspace.id,
                 attempt.id,
                 owner,
                 owner_device,
                 duplicate_hashes
               )

      member_device |> Ecto.Changeset.change(revoked_at: DateTime.utc_now()) |> Repo.update!()

      assert {:error, :invalid_redeem_freshness_proof} =
               approve_with_freshness(workspace.id, attempt.id, owner, owner_device, valid_proof)

      member_device |> Ecto.Changeset.change(revoked_at: nil) |> Repo.update!()

      invalid_signature =
        put_in(
          valid_proof,
          ["gossip_statements", Access.at(1), "signature", "ed25519"],
          Base.url_encode64(:crypto.strong_rand_bytes(64), padding: false)
        )

      assert {:error, :invalid_redeem_freshness_proof} =
               approve_with_freshness(
                 workspace.id,
                 attempt.id,
                 owner,
                 owner_device,
                 invalid_signature
               )

      stale_nonce = Map.put(valid_proof, "recipient_redeem_nonce", "stale-nonce")

      assert {:error, :invalid_redeem_freshness_proof} =
               approve_with_freshness(
                 workspace.id,
                 attempt.id,
                 owner,
                 owner_device,
                 stale_nonce
               )

      stale_bindings = [
        Map.put(
          valid_proof,
          "current_checkpoint_hash",
          Hash.blake3_base64url("stale-checkpoint")
        ),
        Map.put(valid_proof, "current_event_head_hash", Hash.blake3_base64url("stale-head")),
        Map.put(
          valid_proof,
          "current_event_head_sequence",
          valid_proof["current_event_head_sequence"] + 1
        ),
        Map.put(
          valid_proof,
          "live_redeem_challenge_hash",
          Hash.blake3_base64url("stale-challenge")
        )
      ]

      for stale_proof <- stale_bindings do
        assert {:error, :invalid_redeem_freshness_proof} =
                 approve_with_freshness(
                   workspace.id,
                   attempt.id,
                   owner,
                   owner_device,
                   stale_proof
                 )
      end

      Repo.delete!(workspace)
      Enum.each([owner, member, recipient, outsider], &Repo.delete!/1)
    end)
  end

  defp insert_user(label) do
    id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: id,
      email: "#{label}-#{id}@example.com",
      name: label,
      account_type: "registered"
    })
  end

  defp guest_delivery_wrap_container(
         checkpoint_sequence,
         checkpoint_hash,
         covered_head_sequence,
         covered_head_hash
       ) do
    signing_key_id = :crypto.strong_rand_bytes(32)
    recipient_key_id = :crypto.strong_rand_bytes(32)

    %{
      wrap_protocol: "refmd.signed-pq-hybrid-wrap",
      wrap_version: 1,
      suite_id:
        "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
      suite_rank: 1000,
      kem_id: 0x647A,
      kdf_id: 0x0001,
      aead_id: 0x0003,
      purpose: "guest_invitation_workspace_kek_wrap",
      resource: %{},
      sender: %{},
      recipient: %{},
      event_scope: %{},
      wrap_event_sequence: covered_head_sequence,
      wrap_event_hash: :crypto.strong_rand_bytes(32),
      wrap_event_body_hash: :crypto.strong_rand_bytes(32),
      operation_checkpoint_sequence: checkpoint_sequence,
      operation_checkpoint_hash: Encoding.decode_base64url!(checkpoint_hash, 32),
      operation_checkpoint_covered_head_sequence: covered_head_sequence,
      operation_checkpoint_covered_head_hash: Encoding.decode_base64url!(covered_head_hash, 32),
      hpke_enc: :crypto.strong_rand_bytes(1120),
      hpke_ciphertext: :crypto.strong_rand_bytes(48),
      transcript_hash: :crypto.strong_rand_bytes(32),
      signature_protocol: "refmd.hybrid-signature",
      signature_version: 1,
      signature_suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
      signature_suite_rank: 1000,
      sender_signing_key_id: signing_key_id,
      recipient_key_id: recipient_key_id,
      ed25519_signature: :crypto.strong_rand_bytes(64),
      mldsa65_signature: :crypto.strong_rand_bytes(3309)
    }
    |> SignedPQ.response_fields()
    |> Jason.encode!()
    |> Jason.decode!()
  end

  defp authoritative_freshness_proof(attempt, owner, owner_device, checkpoint) do
    %{
      "protocol" => "refmd.redeem-freshness-proof",
      "version" => 1,
      "proof_kind" => "authoritative_device_live",
      "workspace_id" => attempt.workspace_id,
      "current_event_head_sequence" => checkpoint.covered_event_head_sequence,
      "current_event_head_hash" => checkpoint.covered_event_head_hash,
      "current_checkpoint_hash" => checkpoint.checkpoint_hash,
      "recipient_redeem_nonce" => attempt.recipient_redeem_nonce,
      "live_redeem_challenge_hash" => attempt.live_redeem_challenge_hash,
      "authoritative_device" => %{
        "user_id" => owner.id,
        "device_id" => owner_device.id
      }
    }
  end

  defp recipient_bound_authorization(
         attempt,
         owner,
         owner_device,
         checkpoint,
         freshness_proof,
         workspace_pin_bootstrap
       ) do
    private_material = hybrid_signing_private_key_material("device", owner_device.id)
    public_material = hybrid_signing_public_key_material(private_material)
    signing_key_id = Signature.compute_signing_key_id!(public_material)

    payload = %{
      "protocol" => "refmd.recipient-bound-authorization",
      "version" => 1,
      "authorization_id" => Ecto.UUID.generate(),
      "redeem_attempt_id" => attempt.id,
      "workspace_id" => attempt.workspace_id,
      "context_kind" => attempt.context_kind,
      "context_id" => attempt.context_id,
      "resource_hash" => attempt.resource_hash,
      "recipient" => %{
        "recipient_kind" => "guest",
        "recipient_principal_id" => attempt.target_user_id,
        "recipient_device_id" => attempt.target_device_id,
        "encryption_key_id" => attempt.target_encryption_key_id
      },
      "workspace_pin_bootstrap_hash" =>
        PinBootstrap.hash!(attempt.workspace_id, workspace_pin_bootstrap),
      "current_checkpoint_sequence" => checkpoint.sequence,
      "current_checkpoint_hash" => checkpoint.checkpoint_hash,
      "current_event_head_sequence" => checkpoint.covered_event_head_sequence,
      "current_event_head_hash" => checkpoint.covered_event_head_hash,
      "redeem_authority_signing_key_id" => signing_key_id,
      "recipient_redeem_nonce" => attempt.recipient_redeem_nonce,
      "recipient_nonce_state_hash" => attempt.recipient_nonce_state_hash,
      "live_redeem_challenge_hash" => attempt.live_redeem_challenge_hash,
      "redeem_freshness_proof_hash" =>
        Hash.blake3_base64url(JCS.canonical_bytes!(freshness_proof)),
      "not_after_event_sequence" => checkpoint.covered_event_head_sequence + 1
    }

    transcript =
      Signature.build_recipient_bound_authorization_transcript!(
        owner_device.id,
        owner.id,
        owner_device.id,
        signing_key_id,
        payload
      )

    %{
      "payload" => payload,
      "transcript" => transcript,
      "signature" =>
        Signature.__test_sign_hybrid_signature__(
          "recipient_bound_authorization",
          transcript,
          private_material,
          public_material
        ),
      "signing_key_id" => signing_key_id,
      "hybrid_signing_public_key_material" => public_material
    }
  end

  defp insert_device(user_id) do
    device_id = Ecto.UUID.generate()
    signing = hybrid_device_material(device_id)
    {x25519_public, _private} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, x25519_public)
    checkpoint_hash = Hash.blake3_base64url("workspace-invite-device:" <> device_id)
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)

    Repo.insert!(%Device{
      id: device_id,
      user_id: user_id,
      name: "Recipient browser",
      device_type: "browser",
      hybrid_encryption_public_key_material: encryption.public,
      encryption_key_id: encryption.encryption_key_id,
      hybrid_signing_public_key_material: signing.public,
      signing_key_id: signing.signing_key_id,
      approval_signature: %{"fixture" => "workspace-invite-device"},
      approval_signature_surface: "device_approval",
      approval_proof: %{
        "target_key_checkpoint_sequence" => 1,
        "target_key_checkpoint_hash" => checkpoint_hash
      },
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: checkpoint_hash,
      client_nonce: :crypto.strong_rand_bytes(16),
      last_seen_at: now,
      created_at: now
    })
  end

  defp insert_workspace_key_directory!(workspace_id, owner, device, role_id) do
    identity_private = hybrid_signing_private_key_material("identity", owner.id)
    device_private = hybrid_signing_private_key_material("device", device.id)
    {identity_x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)

    insert_test_workspace_key_directory!(
      workspace_id,
      owner.id,
      role_id,
      identity_private,
      hybrid_encryption_public_key_material("identity", owner.id, identity_x25519_public).public,
      device_private,
      device.hybrid_encryption_public_key_material
    )
  end

  defp gossip_statement(attempt, user, device) do
    checkpoint = Encryption.current_workspace_key_directory_checkpoint(attempt.workspace_id)
    private_material = hybrid_signing_private_key_material("device", device.id)
    public_material = hybrid_signing_public_key_material(private_material)

    payload = %{
      "protocol" => "refmd.pin.gossip.statement",
      "version" => 1,
      "workspace_id" => attempt.workspace_id,
      "current_event_head_sequence" => checkpoint.covered_event_head_sequence,
      "current_event_head_hash" => checkpoint.covered_event_head_hash,
      "current_checkpoint_hash" => checkpoint.checkpoint_hash,
      "user_id" => user.id,
      "device_id" => device.id,
      "recipient_redeem_nonce" => attempt.recipient_redeem_nonce,
      "live_redeem_challenge_hash" => attempt.live_redeem_challenge_hash
    }

    transcript = Signature.build_pin_gossip_statement_transcript!(device.id, payload)

    %{
      "payload" => payload,
      "transcript" => transcript,
      "signature" =>
        Signature.__test_sign_hybrid_signature__(
          "pin_gossip_statement",
          transcript,
          private_material,
          public_material
        ),
      "signing_key_id" => device.signing_key_id,
      "hybrid_signing_public_key_material" => public_material
    }
  end

  defp gossip_quorum_proof(attempt, statements) do
    checkpoint = Encryption.current_workspace_key_directory_checkpoint(attempt.workspace_id)

    %{
      "protocol" => "refmd.redeem-freshness-proof",
      "version" => 1,
      "proof_kind" => "member_gossip_quorum",
      "workspace_id" => attempt.workspace_id,
      "current_event_head_sequence" => checkpoint.covered_event_head_sequence,
      "current_event_head_hash" => checkpoint.covered_event_head_hash,
      "current_checkpoint_hash" => checkpoint.checkpoint_hash,
      "recipient_redeem_nonce" => attempt.recipient_redeem_nonce,
      "live_redeem_challenge_hash" => attempt.live_redeem_challenge_hash,
      "proof_hashes" =>
        Enum.map(statements, fn statement ->
          Hash.blake3_base64url(JCS.canonical_bytes!(statement["payload"]))
        end),
      "gossip_statements" => statements
    }
  end

  defp approve_with_freshness(workspace_id, attempt_id, actor, device, freshness_proof) do
    Workspaces.approve_invitation_delivery_attempt(
      workspace_id,
      attempt_id,
      actor.id,
      device.id,
      %{
        "authorization" => %{},
        "delivery_wrap" => %{},
        "member_envelope" => %{},
        "redeem_freshness_proof" => freshness_proof,
        "workspace_key_directory_checkpoint" => %{},
        "workspace_key_directory_events" => [],
        "workspace_pin_bootstrap" => %{}
      }
    )
  end

  defp insert_identity_public_key(user_id) do
    signing_private = hybrid_signing_private_key_material("identity", user_id)
    signing_public = hybrid_signing_public_key_material(signing_private)
    {x25519_public, _private} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("identity", user_id, x25519_public)

    %UserIdentityPublicKey{}
    |> UserIdentityPublicKey.changeset(%{
      user_id: user_id,
      hybrid_encryption_public_key_material: encryption.public,
      hybrid_signing_public_key_material: signing_public,
      pending_registration_challenge_hash:
        Hash.blake3_base64url("workspace-delivery-identity:" <> user_id),
      rotation_due_at: RotationPolicy.next_identity_due_at()
    })
    |> Repo.insert!()
  end

  defp delivery_attempt_attrs(user_id, device, identity) do
    attempt_id = Ecto.UUID.generate()

    %{
      "redeem_attempt_id" => attempt_id,
      "target_user_id" => user_id,
      "target_device_id" => device.id,
      "target_registration" => %{
        "identity_hybrid_encryption_public_key_material" =>
          identity.hybrid_encryption_public_key_material,
        "identity_hybrid_signing_public_key_material" =>
          identity.hybrid_signing_public_key_material,
        "device_hybrid_encryption_public_key_material" =>
          device.hybrid_encryption_public_key_material,
        "device_hybrid_signing_public_key_material" => device.hybrid_signing_public_key_material
      },
      "recipient_redeem_nonce" =>
        Hash.blake3_base64url("workspace-delivery-nonce:" <> attempt_id),
      "live_redeem_challenge_hash" =>
        Hash.blake3_base64url("workspace-delivery-challenge:" <> attempt_id)
    }
  end

  defp insert_invitation(workspace_id, owner_id, recipient, device_id, role_id) do
    now = DateTime.utc_now() |> DateTime.truncate(:microsecond)
    token_hash = Hash.blake3_base64url("workspace-invite-token:" <> Ecto.UUID.generate())
    digest = Hash.blake3_base64url("workspace-invite-fixture")

    %WorkspaceInvitation{}
    |> WorkspaceInvitation.changeset(%{
      id: Ecto.UUID.generate(),
      workspace_id: workspace_id,
      token_hash: token_hash,
      token_prefix: String.slice(token_hash, 0, 4),
      role_id: role_id,
      invited_by: owner_id,
      invited_email: recipient.email,
      delivery_mode: "known_recipient",
      recipient_user_id: recipient.id,
      recipient_device_ids: [device_id],
      kek_version: 1,
      bootstrap_key_commitment: digest,
      encrypted_bootstrap_package: %{"fixture" => "known-recipient"},
      bootstrap_package_hash: digest,
      bootstrap_package_key_recipient_wrap: %{"fixture" => "known-recipient"},
      bootstrap_suite_id: "refmd-v2-invitation-bootstrap-xchacha20poly1305",
      capability_context_hash: digest,
      expires_at: DateTime.add(now, 3600, :second),
      created_at: now
    })
    |> Repo.insert!()
  end
end
