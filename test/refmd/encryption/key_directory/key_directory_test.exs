defmodule RefMD.Encryption.KeyDirectory.KeyDirectoryTest do
  use RefMD.DataCase, async: true

  alias RefMD.Crypto.{Encoding, Hash, JCS, Signature, Suite}
  alias RefMD.Encryption.KeyDirectory
  alias RefMD.Encryption.KeyDirectory.Authority, as: Authority
  alias RefMD.Encryption.KeyDirectory.{Checkpoint, Payload, Signatures}
  alias RefMD.Repo

  import Ecto.Query
  import RefMD.TestCrypto

  test "user checkpoint signatures use identity_rotation while two identity keys are active" do
    payload = %{
      "scope_kind" => "user",
      "sequence" => 2,
      "identity_keys" => [
        %{
          "key_material" => %{
            "owner_kind" => "identity",
            "protocol" => "refmd.hybrid-signing-key-material"
          }
        },
        %{
          "key_material" => %{
            "owner_kind" => "identity",
            "protocol" => "refmd.hybrid-signing-key-material"
          }
        }
      ]
    }

    assert Signatures.checkpoint_signature_variant!(payload, %{"signer_kind" => "identity"}) ==
             "identity_rotation"

    retired_payload =
      put_in(payload, ["identity_keys"], [
        %{
          "key_material" => %{
            "owner_kind" => "identity",
            "protocol" => "refmd.hybrid-signing-key-material"
          }
        },
        %{
          "key_material" => %{
            "owner_kind" => "identity",
            "protocol" => "refmd.hybrid-signing-key-material"
          },
          "revoked_at" => %{}
        }
      ])

    assert Signatures.checkpoint_signature_variant!(retired_payload, %{
             "signer_kind" => "identity"
           }) == "identity_active"
  end

  test "stores signed initial user and workspace directories and exposes current checkpoints" do
    %{user_id: user_id, workspace_id: workspace_id, bootstrap: bootstrap} = directory_fixture()

    assert :ok =
             KeyDirectory.verify_complete_replay!(
               "user",
               user_id,
               bootstrap.user_events,
               bootstrap.user_checkpoint,
               checkpoint_signer_kind: "identity"
             )

    assert %{checkpoint: user_checkpoint} =
             KeyDirectory.insert_signed_initial_scope!(
               "user",
               user_id,
               bootstrap.user_events,
               bootstrap.user_checkpoint,
               checkpoint_signer_kind: "identity"
             )

    assert %{checkpoint: workspace_checkpoint} =
             KeyDirectory.insert_signed_initial_scope!(
               "workspace",
               workspace_id,
               bootstrap.workspace_events,
               bootstrap.workspace_checkpoint,
               checkpoint_signer_kind: "device"
             )

    assert KeyDirectory.current_checkpoint("user", user_id).checkpoint_hash ==
             user_checkpoint.checkpoint_hash

    assert KeyDirectory.current_checkpoint("workspace", workspace_id).checkpoint_hash ==
             workspace_checkpoint.checkpoint_hash
  end

  test "rejects checkpoint signature substitution before storing" do
    %{user_id: user_id, bootstrap: bootstrap} = directory_fixture()

    tampered =
      put_in(
        bootstrap.user_checkpoint,
        ["signatures", Access.at(0), "signature", "ed25519"],
        Encoding.encode_base64url(:binary.copy(<<0>>, 64))
      )

    assert_raise ArgumentError, "key_directory_checkpoint_signature_invalid", fn ->
      KeyDirectory.insert_signed_initial_scope!(
        "user",
        user_id,
        bootstrap.user_events,
        tampered,
        checkpoint_signer_kind: "identity"
      )
    end
  end

  test "rejects invalid extra checkpoint signatures before storing" do
    %{user_id: user_id, bootstrap: bootstrap} = directory_fixture()

    invalid_extra =
      bootstrap.user_checkpoint
      |> get_in(["signatures", Access.at(0)])
      |> put_in(["signature", "ed25519"], Encoding.encode_base64url(:binary.copy(<<0>>, 64)))

    poisoned =
      update_in(bootstrap.user_checkpoint, ["signatures"], &(&1 ++ [invalid_extra]))

    assert_raise ArgumentError, "key_directory_checkpoint_signature_invalid", fn ->
      KeyDirectory.insert_signed_initial_scope!(
        "user",
        user_id,
        bootstrap.user_events,
        poisoned,
        checkpoint_signer_kind: "identity"
      )
    end
  end

  test "rejects unsigned event envelopes" do
    %{user_id: user_id, bootstrap: bootstrap} = directory_fixture()

    unsigned_events = [
      put_in(hd(bootstrap.user_events), ["signatures"], []) | tl(bootstrap.user_events)
    ]

    assert_raise ArgumentError, "key_directory_signatures_required", fn ->
      KeyDirectory.insert_signed_initial_scope!(
        "user",
        user_id,
        unsigned_events,
        bootstrap.user_checkpoint,
        checkpoint_signer_kind: "identity"
      )
    end
  end

  test "rejects broken event chain continuity" do
    %{user_id: user_id, bootstrap: bootstrap} = directory_fixture()

    broken_events =
      put_in(
        bootstrap.user_events,
        [Access.at(1), "payload", "previous_event_hash"],
        Hash.blake3_base64url("wrong previous event")
      )

    assert_raise ArgumentError, "event_previous_hash_mismatch", fn ->
      KeyDirectory.insert_signed_initial_scope!(
        "user",
        user_id,
        broken_events,
        bootstrap.user_checkpoint,
        checkpoint_signer_kind: "identity"
      )
    end
  end

  test "rejects signed checkpoint payload with downgraded suite policy" do
    %{user_id: user_id, bootstrap: bootstrap} = directory_fixture()

    downgraded =
      put_in(bootstrap.user_checkpoint, ["payload", "min_suite_rank"], 1)

    assert_raise ArgumentError, "min_suite_rank_invalid", fn ->
      KeyDirectory.insert_signed_initial_scope!(
        "user",
        user_id,
        bootstrap.user_events,
        downgraded,
        checkpoint_signer_kind: "identity"
      )
    end
  end

  test "rejects share participant keys without a matching admission event" do
    %{user_id: user_id, bootstrap: bootstrap} = directory_fixture()

    tampered =
      put_in(
        bootstrap.user_checkpoint,
        ["payload", "share_participant_keys"],
        [hd(bootstrap.user_checkpoint["payload"]["device_keys"])]
      )

    assert_raise ArgumentError, "checkpoint_state_replay_mismatch", fn ->
      KeyDirectory.verify_complete_replay!(
        "user",
        user_id,
        bootstrap.user_events,
        tampered,
        checkpoint_signer_kind: "identity"
      )
    end
  end

  test "rejects invitation redeem authority keys in persistent checkpoint entries" do
    %{user_id: user_id, bootstrap: bootstrap} = directory_fixture()

    key_material =
      hybrid_signing_public_key_material(
        hybrid_signing_private_key_material("invitation_redeem_authority", Ecto.UUID.generate())
      )

    valid_from = hd(bootstrap.user_checkpoint["payload"]["identity_keys"])["valid_from"]

    key_entry = %{
      "key_id" => Signature.compute_signing_key_id!(key_material),
      "key_material" => key_material,
      "valid_from" => valid_from
    }

    assert_raise ArgumentError,
                 "key_directory_invitation_redeem_authority_signer_persistent",
                 fn ->
                   key_directory_checkpoint_payload!(%{
                     "scope_kind" => "user",
                     "scope_id" => user_id,
                     "sequence" => 1,
                     "issued_at" =>
                       DateTime.utc_now()
                       |> DateTime.truncate(:microsecond)
                       |> DateTime.to_iso8601(),
                     "covered_event_head" =>
                       bootstrap.user_checkpoint["payload"]["covered_event_head"],
                     "identity_keys" => [key_entry],
                     "device_keys" => bootstrap.user_checkpoint["payload"]["device_keys"]
                   })
                 end
  end

  test "requires document write authority for workspace device document admissions" do
    state = %{members: %{"viewer-user" => "viewer"}, invitations: %{}, shares: %{}}

    payload = %{
      "scope_kind" => "workspace",
      "event_type" => "document_update_accepted",
      "actor" => %{"signer_kind" => "device", "user_id" => "viewer-user"},
      "body" => %{}
    }

    assert_raise ArgumentError, "key_directory_document_write_required", fn ->
      Authority.assert_event_authority!(state, payload)
    end
  end

  test "guest invitation redemption does not create workspace member authority" do
    guest_user_id = Ecto.UUID.generate()
    guest_device_id = Ecto.UUID.generate()
    grant_id = Ecto.UUID.generate()
    document_id = Ecto.UUID.generate()

    state =
      Authority.assert_and_apply_event!(Authority.empty_state(), %{
        "scope_kind" => "workspace",
        "event_type" => "guest_invitation_redeemed",
        "actor" => %{"signer_kind" => "invitation_redeem_authority"},
        "body" => %{
          "guest_grant_id" => grant_id,
          "guest_user_id" => guest_user_id,
          "guest_device_id" => guest_device_id,
          "scope_kind" => "document",
          "scope_id" => document_id,
          "permission" => "view"
        }
      })

    refute Map.has_key?(state.members, guest_user_id)

    wrap_payload = %{
      "scope_kind" => "workspace",
      "event_type" => "wrap_issued",
      "actor" => %{
        "signer_kind" => "device",
        "user_id" => guest_user_id,
        "device_id" => guest_device_id
      },
      "body" => %{}
    }

    assert_raise ArgumentError, "key_directory_active_member_required", fn ->
      Authority.assert_event_authority!(state, wrap_payload)
    end

    write_payload = %{
      "scope_kind" => "workspace",
      "event_type" => "document_update_accepted",
      "actor" => %{
        "signer_kind" => "device",
        "user_id" => guest_user_id,
        "device_id" => guest_device_id
      },
      "body" => %{"document_id" => document_id}
    }

    assert_raise ArgumentError, "key_directory_document_write_required", fn ->
      Authority.assert_event_authority!(state, write_payload)
    end
  end

  test "active edit guest grants only authorize their granted document scope" do
    guest_user_id = Ecto.UUID.generate()
    guest_device_id = Ecto.UUID.generate()
    granted_document_id = Ecto.UUID.generate()
    other_document_id = Ecto.UUID.generate()

    state =
      Authority.assert_and_apply_event!(Authority.empty_state(), %{
        "scope_kind" => "workspace",
        "event_type" => "guest_invitation_redeemed",
        "actor" => %{"signer_kind" => "invitation_redeem_authority"},
        "body" => %{
          "guest_grant_id" => Ecto.UUID.generate(),
          "guest_user_id" => guest_user_id,
          "guest_device_id" => guest_device_id,
          "scope_kind" => "document",
          "scope_id" => granted_document_id,
          "permission" => "edit"
        }
      })

    actor = %{
      "signer_kind" => "device",
      "user_id" => guest_user_id,
      "device_id" => guest_device_id
    }

    assert :ok =
             Authority.assert_event_authority!(state, %{
               "scope_kind" => "workspace",
               "event_type" => "document_update_accepted",
               "actor" => actor,
               "body" => %{"document_id" => granted_document_id}
             })

    assert_raise ArgumentError, "key_directory_document_write_required", fn ->
      Authority.assert_event_authority!(state, %{
        "scope_kind" => "workspace",
        "event_type" => "document_update_accepted",
        "actor" => actor,
        "body" => %{"document_id" => other_document_id}
      })
    end
  end

  test "rotation completion and deletion require prior rotation replay state" do
    workspace_id = Ecto.UUID.generate()

    state = %{
      members: %{"admin-user" => "admin"},
      invitations: %{},
      guest_grants: %{},
      shares: %{},
      rotations: %{}
    }

    actor = %{"signer_kind" => "device", "user_id" => "admin-user"}

    started =
      rotation_authority_payload(
        workspace_id,
        "rotation_started",
        actor,
        10,
        %{
          "event_type" => "rotation_started",
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "old_key_version" => 1,
          "new_key_version" => 2,
          "not_before_event_sequence" => 10,
          "reason" => "manual"
        }
      )

    completed =
      rotation_authority_payload(
        workspace_id,
        "rotation_completed",
        actor,
        11,
        %{
          "event_type" => "rotation_completed",
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "old_key_version" => 1,
          "new_key_version" => 2,
          "completed_at_event_sequence" => 11,
          "completion_manifest_hash" => Hash.blake3_base64url("manifest")
        }
      )

    deleted =
      rotation_authority_payload(
        workspace_id,
        "old_key_deleted",
        actor,
        12,
        %{
          "event_type" => "old_key_deleted",
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "old_key_version" => 1,
          "deleted_at_event_sequence" => 12,
          "deletion_manifest_hash" => Hash.blake3_base64url("deletion-manifest")
        }
      )

    assert_raise ArgumentError, "rotation_started_event_missing", fn ->
      Authority.assert_event_authority!(state, completed)
    end

    assert_raise ArgumentError, "rotation_completed_event_missing", fn ->
      Authority.assert_event_authority!(state, deleted)
    end

    state = Authority.assert_and_apply_event!(state, started)
    state = Authority.assert_and_apply_event!(state, completed)

    assert :ok = Authority.assert_event_authority!(state, deleted)
  end

  test "requires active edit share scope for share participant document admissions" do
    document_id = Ecto.UUID.generate()
    share_id = Ecto.UUID.generate()

    active_state = %{
      members: %{},
      invitations: %{},
      shares: %{
        share_id => %{
          share_id: share_id,
          parent_share_id: nil,
          scope_kind: "document",
          scope_id: document_id,
          permission: "edit",
          status: "active"
        }
      }
    }

    payload = %{
      "scope_kind" => "workspace",
      "event_type" => "document_update_accepted",
      "actor" => %{"signer_kind" => "share_participant_device"},
      "body" => %{
        "document_id" => document_id,
        "share_id" => share_id,
        "share_authority_kind" => "share_participant_device",
        "share_permission" => "edit"
      }
    }

    assert :ok = Authority.assert_event_authority!(active_state, payload)

    revoked_state = put_in(active_state, [:shares, share_id, :status], "revoked")

    assert_raise ArgumentError, "key_directory_share_participant_share_inactive", fn ->
      Authority.assert_event_authority!(revoked_state, payload)
    end
  end

  test "allows active edit folder share participant admissions for child documents" do
    folder_id = Ecto.UUID.generate()
    document_id = Ecto.UUID.generate()
    root_share_id = Ecto.UUID.generate()
    child_share_id = Ecto.UUID.generate()

    state = %{
      members: %{},
      invitations: %{},
      shares: %{
        root_share_id => %{
          share_id: root_share_id,
          parent_share_id: nil,
          scope_kind: "folder",
          scope_id: folder_id,
          permission: "edit",
          status: "active"
        },
        child_share_id => %{
          share_id: child_share_id,
          parent_share_id: root_share_id,
          scope_kind: "document",
          scope_id: document_id,
          permission: "edit",
          status: "active"
        }
      }
    }

    payload = %{
      "scope_kind" => "workspace",
      "event_type" => "document_update_accepted",
      "actor" => %{"signer_kind" => "share_participant_device"},
      "body" => %{
        "document_id" => document_id,
        "share_id" => root_share_id,
        "share_authority_kind" => "share_participant_device",
        "share_permission" => "edit"
      }
    }

    assert :ok = Authority.assert_event_authority!(state, payload)
  end

  test "removed child share scopes do not revoke the whole parent share authority" do
    folder_id = Ecto.UUID.generate()
    removed_document_id = Ecto.UUID.generate()
    allowed_document_id = Ecto.UUID.generate()
    root_share_id = Ecto.UUID.generate()
    removed_child_share_id = Ecto.UUID.generate()
    allowed_child_share_id = Ecto.UUID.generate()

    state = %{
      members: %{"admin-user" => "admin"},
      invitations: %{},
      guest_grants: %{},
      shares: %{
        root_share_id => %{
          share_id: root_share_id,
          parent_share_id: nil,
          scope_kind: "folder",
          scope_id: folder_id,
          permission: "edit",
          status: "active"
        },
        removed_child_share_id => %{
          share_id: removed_child_share_id,
          parent_share_id: root_share_id,
          scope_kind: "document",
          scope_id: removed_document_id,
          permission: "edit",
          status: "active"
        },
        allowed_child_share_id => %{
          share_id: allowed_child_share_id,
          parent_share_id: root_share_id,
          scope_kind: "document",
          scope_id: allowed_document_id,
          permission: "edit",
          status: "active"
        }
      }
    }

    state =
      Authority.assert_and_apply_event!(state, %{
        "scope_kind" => "workspace",
        "event_type" => "share_key_scope_removed",
        "actor" => %{"signer_kind" => "device", "user_id" => "admin-user"},
        "body" => %{
          "share_id" => root_share_id,
          "scope_id" => removed_document_id
        }
      })

    admission_payload = fn document_id ->
      %{
        "scope_kind" => "workspace",
        "event_type" => "document_update_accepted",
        "actor" => %{"signer_kind" => "share_participant_device"},
        "body" => %{
          "document_id" => document_id,
          "share_id" => root_share_id,
          "share_authority_kind" => "share_participant_device",
          "share_permission" => "edit"
        }
      }
    end

    assert_raise ArgumentError, "key_directory_share_scope_not_active", fn ->
      Authority.assert_event_authority!(state, admission_payload.(removed_document_id))
    end

    assert :ok = Authority.assert_event_authority!(state, admission_payload.(allowed_document_id))
  end

  test "resolves active key material only from the current checkpoint" do
    %{user_id: user_id, bootstrap: bootstrap} = directory_fixture()

    %{checkpoint: checkpoint} =
      KeyDirectory.insert_signed_initial_scope!(
        "user",
        user_id,
        bootstrap.user_events,
        bootstrap.user_checkpoint,
        checkpoint_signer_kind: "identity"
      )

    key_id = hd(checkpoint.payload["identity_keys"])["key_id"]
    material = hd(checkpoint.payload["identity_keys"])["key_material"]

    assert {:ok, ^material} =
             KeyDirectory.active_key_material_in_current_checkpoint("user", user_id, key_id)

    assert {:ok, ^material} =
             KeyDirectory.active_key_material_at_checkpoint(
               "user",
               user_id,
               key_id,
               checkpoint.sequence,
               checkpoint.checkpoint_hash
             )

    assert {:error, :not_found} =
             KeyDirectory.active_key_material_at_checkpoint(
               "user",
               user_id,
               key_id,
               checkpoint.sequence,
               Hash.blake3_base64url("untrusted checkpoint")
             )
  end

  test "appends a signed descendant checkpoint and advances the pin" do
    %{user_id: user_id, bootstrap: bootstrap, identity_private: identity_private} =
      directory_fixture()

    %{checkpoint: checkpoint} =
      KeyDirectory.insert_signed_initial_scope!(
        "user",
        user_id,
        bootstrap.user_events,
        bootstrap.user_checkpoint,
        checkpoint_signer_kind: "identity"
      )

    policy = Suite.current_suite_policy()

    event =
      key_directory_event_payload!(%{
        "scope_kind" => "user",
        "scope_id" => user_id,
        "sequence" => checkpoint.covered_event_head_sequence + 1,
        "event_type" => "suite_policy_changed",
        "actor" => identity_actor(user_id, hd(checkpoint.payload["identity_keys"])["key_id"]),
        "previous_event_hash" => checkpoint.covered_event_head_hash,
        "body" => %{
          "suite_policy_version" => policy["suite_policy_version"],
          "min_suite_rank" => policy["min_suite_rank"],
          "allowed_suite_ids" => policy["allowed_suite_ids"]
        }
      })

    checkpoint_payload =
      key_directory_checkpoint_payload!(%{
        "scope_kind" => "user",
        "scope_id" => user_id,
        "sequence" => checkpoint.sequence + 1,
        "issued_at" =>
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601(),
        "previous_checkpoint_hash" => checkpoint.checkpoint_hash,
        "covered_event_head" => key_directory_event_head(event),
        "identity_keys" => checkpoint.payload["identity_keys"],
        "device_keys" => checkpoint.payload["device_keys"]
      })

    %{checkpoint: appended, pin: pin} =
      KeyDirectory.append_signed_scope!(
        "user",
        user_id,
        [signed_key_directory_event_envelope(event, identity_private)],
        signed_key_directory_checkpoint_envelope(
          checkpoint_payload,
          "identity_active",
          identity_private
        ),
        checkpoint_signer_kind: "identity"
      )

    assert appended.previous_checkpoint_hash == checkpoint.checkpoint_hash
    assert pin.checkpoint_hash == appended.checkpoint_hash

    assert KeyDirectory.current_checkpoint("user", user_id).checkpoint_hash ==
             appended.checkpoint_hash
  end

  test "rejects append when pinned checkpoint contains non-adopted share participant keys" do
    %{user_id: user_id, bootstrap: bootstrap, identity_private: identity_private} =
      directory_fixture()

    %{checkpoint: checkpoint} =
      KeyDirectory.insert_signed_initial_scope!(
        "user",
        user_id,
        bootstrap.user_events,
        bootstrap.user_checkpoint,
        checkpoint_signer_kind: "identity"
      )

    poisoned_payload =
      Map.put(checkpoint.payload, "share_participant_keys", [
        hd(checkpoint.payload["device_keys"])
      ])

    from(c in Checkpoint, where: c.id == ^checkpoint.id)
    |> Repo.update_all(set: [payload: poisoned_payload])

    policy = Suite.current_suite_policy()

    event =
      key_directory_event_payload!(%{
        "scope_kind" => "user",
        "scope_id" => user_id,
        "sequence" => checkpoint.covered_event_head_sequence + 1,
        "event_type" => "suite_policy_changed",
        "actor" => identity_actor(user_id, hd(checkpoint.payload["identity_keys"])["key_id"]),
        "previous_event_hash" => checkpoint.covered_event_head_hash,
        "body" => %{
          "suite_policy_version" => policy["suite_policy_version"],
          "min_suite_rank" => policy["min_suite_rank"],
          "allowed_suite_ids" => policy["allowed_suite_ids"]
        }
      })

    checkpoint_payload =
      key_directory_checkpoint_payload!(%{
        "scope_kind" => "user",
        "scope_id" => user_id,
        "sequence" => checkpoint.sequence + 1,
        "issued_at" =>
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601(),
        "previous_checkpoint_hash" => checkpoint.checkpoint_hash,
        "covered_event_head" => key_directory_event_head(event),
        "identity_keys" => checkpoint.payload["identity_keys"],
        "device_keys" => checkpoint.payload["device_keys"]
      })

    assert_raise ArgumentError, "key_directory_checkpoint_storage_mismatch", fn ->
      KeyDirectory.append_signed_scope!(
        "user",
        user_id,
        [signed_key_directory_event_envelope(event, identity_private)],
        signed_key_directory_checkpoint_envelope(
          checkpoint_payload,
          "identity_active",
          identity_private
        ),
        checkpoint_signer_kind: "identity"
      )
    end
  end

  test "rejects descendant checkpoint approved only by a newly introduced identity key" do
    %{user_id: user_id, bootstrap: bootstrap} = directory_fixture()

    %{checkpoint: checkpoint} =
      KeyDirectory.insert_signed_initial_scope!(
        "user",
        user_id,
        bootstrap.user_events,
        bootstrap.user_checkpoint,
        checkpoint_signer_kind: "identity"
      )

    new_identity_private = hybrid_signing_private_key_material("identity", user_id, "new")
    new_identity_public = hybrid_signing_public_key_material(new_identity_private)
    new_identity_key_id = Signature.compute_signing_key_id!(new_identity_public)

    event =
      key_directory_event_payload!(%{
        "scope_kind" => "user",
        "scope_id" => user_id,
        "sequence" => checkpoint.covered_event_head_sequence + 1,
        "event_type" => "identity_key_added",
        "actor" => identity_actor(user_id, new_identity_key_id),
        "previous_event_hash" => checkpoint.covered_event_head_hash,
        "body" => %{
          "key_id" => new_identity_key_id,
          "key_material_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(new_identity_public))
        }
      })

    checkpoint_payload =
      key_directory_checkpoint_payload!(%{
        "scope_kind" => "user",
        "scope_id" => user_id,
        "sequence" => checkpoint.sequence + 1,
        "issued_at" =>
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601(),
        "previous_checkpoint_hash" => checkpoint.checkpoint_hash,
        "covered_event_head" => key_directory_event_head(event),
        "identity_keys" =>
          checkpoint.payload["identity_keys"] ++
            [
              Payload.key_entry!(
                new_identity_public,
                key_directory_event_ref("user", user_id, event)
              )
            ],
        "device_keys" => checkpoint.payload["device_keys"]
      })

    assert_raise ArgumentError, "key_directory_event_signer_unknown", fn ->
      KeyDirectory.append_signed_scope!(
        "user",
        user_id,
        [signed_key_directory_event_envelope(event, new_identity_private)],
        signed_key_directory_checkpoint_envelope(
          checkpoint_payload,
          "identity_active",
          new_identity_private
        ),
        checkpoint_signer_kind: "identity"
      )
    end

    assert KeyDirectory.current_checkpoint("user", user_id).checkpoint_hash ==
             checkpoint.checkpoint_hash

    assert {:ok, _material} =
             KeyDirectory.active_key_material_in_current_checkpoint(
               "user",
               user_id,
               Signature.compute_signing_key_id!(
                 hd(checkpoint.payload["identity_keys"])["key_material"]
               )
             )
  end

  test "rejects checkpoint signed by a key revoked in the pinned authority state" do
    %{user_id: user_id, bootstrap: bootstrap, identity_private: identity_private} =
      directory_fixture()

    %{checkpoint: checkpoint} =
      KeyDirectory.insert_signed_initial_scope!(
        "user",
        user_id,
        bootstrap.user_events,
        bootstrap.user_checkpoint,
        checkpoint_signer_kind: "identity"
      )

    identity_entry = hd(checkpoint.payload["identity_keys"])
    identity_key_id = identity_entry["key_id"]

    revoke_event =
      key_directory_event_payload!(%{
        "scope_kind" => "user",
        "scope_id" => user_id,
        "sequence" => checkpoint.covered_event_head_sequence + 1,
        "event_type" => "signing_key_revoked",
        "actor" => identity_actor(user_id, identity_key_id),
        "previous_event_hash" => checkpoint.covered_event_head_hash,
        "body" => %{
          "key_id" => identity_key_id,
          "reason" => "device_revoked",
          "revoked_at_event_sequence" => checkpoint.covered_event_head_sequence + 1
        }
      })

    revoked_identity_entry =
      Map.put(
        identity_entry,
        "revoked_at",
        key_directory_event_ref("user", user_id, revoke_event)
      )

    revoked_checkpoint_payload =
      key_directory_checkpoint_payload!(%{
        "scope_kind" => "user",
        "scope_id" => user_id,
        "sequence" => checkpoint.sequence + 1,
        "issued_at" =>
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601(),
        "previous_checkpoint_hash" => checkpoint.checkpoint_hash,
        "covered_event_head" => key_directory_event_head(revoke_event),
        "identity_keys" => [revoked_identity_entry | tl(checkpoint.payload["identity_keys"])],
        "device_keys" => checkpoint.payload["device_keys"],
        "revoked_key_ids" => [identity_key_id]
      })

    assert_raise ArgumentError, "key_directory_signer_revoked", fn ->
      KeyDirectory.append_signed_scope!(
        "user",
        user_id,
        [signed_key_directory_event_envelope(revoke_event, identity_private)],
        signed_key_directory_checkpoint_envelope(
          revoked_checkpoint_payload,
          "identity_active",
          identity_private
        ),
        checkpoint_signer_kind: "identity"
      )
    end
  end

  test "rejects workspace event signed before signer key is active" do
    %{workspace_id: workspace_id, bootstrap: bootstrap} = directory_fixture()

    not_yet_valid =
      update_in(
        bootstrap.workspace_checkpoint,
        ["payload", "device_keys", Access.all(), "valid_from", "event_sequence"],
        fn _ -> 2 end
      )

    assert_raise ArgumentError, "key_directory_signer_not_yet_valid", fn ->
      KeyDirectory.insert_signed_initial_scope!(
        "workspace",
        workspace_id,
        bootstrap.workspace_events,
        not_yet_valid,
        checkpoint_signer_kind: "device"
      )
    end
  end

  test "rejects wrap issued to an encryption key revoked at the wrap event sequence" do
    %{
      user_id: user_id,
      workspace_id: workspace_id,
      bootstrap: bootstrap,
      device_private: device_private
    } =
      directory_fixture()

    %{checkpoint: checkpoint} =
      KeyDirectory.insert_signed_initial_scope!(
        "workspace",
        workspace_id,
        bootstrap.workspace_events,
        bootstrap.workspace_checkpoint,
        checkpoint_signer_kind: "device"
      )

    device_id = device_private["owner_id"]
    signing_entry = device_key_entry!(checkpoint.payload, "refmd.hybrid-signing-key-material")

    encryption_entry =
      device_key_entry!(checkpoint.payload, "refmd.hybrid-encryption-key-material")

    actor = workspace_device_actor(user_id, device_id, signing_entry["key_id"])
    revoke_sequence = checkpoint.covered_event_head_sequence + 1

    revoke_event =
      key_directory_event_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => revoke_sequence,
        "event_type" => "encryption_key_revoked",
        "actor" => actor,
        "previous_event_hash" => checkpoint.covered_event_head_hash,
        "body" => %{
          "key_id" => encryption_entry["key_id"],
          "reason" => "device_revoked",
          "revoked_at_event_sequence" => revoke_sequence
        }
      })

    wrap_sequence = revoke_sequence + 1
    resource = %{"kind" => "workspace_kek", "workspace_id" => workspace_id}

    sender = %{
      "user_id" => user_id,
      "device_id" => device_id,
      "signing_key_id" => signing_entry["key_id"],
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id
    }

    recipient = %{
      "user_id" => user_id,
      "device_id" => device_id,
      "encryption_key_id" => encryption_entry["key_id"],
      "key_scope_kind" => "workspace",
      "key_scope_id" => workspace_id
    }

    wrap_event =
      key_directory_event_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => wrap_sequence,
        "event_type" => "wrap_issued",
        "actor" => actor,
        "previous_event_hash" => KeyDirectory.event_hash(revoke_event),
        "body" => %{
          "purpose" => "workspace_kek",
          "recipient" => recipient,
          "resource" => resource,
          "resource_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(resource)),
          "sender" => sender,
          "wrap_body_hash" => Hash.blake3_base64url("wrap body"),
          "wrap_protocol" => "refmd.signed-pq-hybrid-wrap",
          "wrap_suite_id" =>
            "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
          "wrap_suite_rank" => 1000,
          "wrap_version" => 1
        }
      })

    revoked_encryption_entry =
      Map.put(
        encryption_entry,
        "revoked_at",
        key_directory_event_ref("workspace", workspace_id, revoke_event)
      )

    checkpoint_payload =
      key_directory_checkpoint_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => checkpoint.sequence + 1,
        "issued_at" =>
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601(),
        "previous_checkpoint_hash" => checkpoint.checkpoint_hash,
        "covered_event_head" => key_directory_event_head(wrap_event),
        "identity_keys" => checkpoint.payload["identity_keys"],
        "device_keys" =>
          replace_key_entry(checkpoint.payload["device_keys"], revoked_encryption_entry),
        "revoked_key_ids" => [encryption_entry["key_id"]]
      })

    assert_raise ArgumentError, "key_directory_signer_revoked", fn ->
      KeyDirectory.append_signed_scope!(
        "workspace",
        workspace_id,
        [
          signed_key_directory_event_envelope(revoke_event, device_private),
          signed_key_directory_event_envelope(wrap_event, device_private)
        ],
        signed_key_directory_checkpoint_envelope(
          checkpoint_payload,
          "workspace_authorized",
          device_private,
          user_id
        ),
        checkpoint_signer_kind: "device"
      )
    end
  end

  test "accepts signed KEK rotation completion and old-key deletion events only as chained workspace descendants" do
    %{
      user_id: user_id,
      workspace_id: workspace_id,
      bootstrap: bootstrap,
      device_private: device_private
    } =
      directory_fixture()

    %{checkpoint: checkpoint} =
      KeyDirectory.insert_signed_initial_scope!(
        "workspace",
        workspace_id,
        bootstrap.workspace_events,
        bootstrap.workspace_checkpoint,
        checkpoint_signer_kind: "device"
      )

    device_id = device_private["owner_id"]
    device_public = hybrid_signing_public_key_material(device_private)
    signing_key_id = Signature.compute_signing_key_id!(device_public)
    actor = workspace_device_actor(user_id, device_id, signing_key_id)
    old_key_version = 1
    new_key_version = 2
    started_sequence = checkpoint.covered_event_head_sequence + 1

    started_event =
      key_directory_event_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => started_sequence,
        "event_type" => "rotation_started",
        "actor" => actor,
        "previous_event_hash" => checkpoint.covered_event_head_hash,
        "body" => %{
          "event_type" => "rotation_started",
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "old_key_version" => old_key_version,
          "new_key_version" => new_key_version,
          "not_before_event_sequence" => started_sequence,
          "reason" => "manual"
        }
      })

    completed_sequence = started_sequence + 1

    completion_manifest_hash =
      Hash.blake3_base64url(
        JCS.canonical_bytes!(%{
          "protocol" => "refmd.rotation-completion-manifest",
          "version" => 1,
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "old_key_version" => old_key_version,
          "new_key_version" => new_key_version,
          "started_event_hash" => KeyDirectory.event_hash(started_event)
        })
      )

    completed_event =
      key_directory_event_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => completed_sequence,
        "event_type" => "rotation_completed",
        "actor" => actor,
        "previous_event_hash" => KeyDirectory.event_hash(started_event),
        "body" => %{
          "event_type" => "rotation_completed",
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "old_key_version" => old_key_version,
          "new_key_version" => new_key_version,
          "completed_at_event_sequence" => completed_sequence,
          "completion_manifest_hash" => completion_manifest_hash
        }
      })

    deleted_sequence = completed_sequence + 1

    deletion_manifest_hash =
      Hash.blake3_base64url(
        JCS.canonical_bytes!(%{
          "protocol" => "refmd.old-key-deletion-manifest",
          "version" => 1,
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "old_key_version" => old_key_version,
          "rotation_completed_event_hash" => KeyDirectory.event_hash(completed_event)
        })
      )

    deleted_event =
      key_directory_event_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => deleted_sequence,
        "event_type" => "old_key_deleted",
        "actor" => actor,
        "previous_event_hash" => KeyDirectory.event_hash(completed_event),
        "body" => %{
          "event_type" => "old_key_deleted",
          "rotation_kind" => "kek",
          "scope_kind" => "workspace",
          "scope_id" => workspace_id,
          "old_key_version" => old_key_version,
          "deleted_at_event_sequence" => deleted_sequence,
          "deletion_manifest_hash" => deletion_manifest_hash
        }
      })

    checkpoint_payload =
      key_directory_checkpoint_payload!(%{
        "scope_kind" => "workspace",
        "scope_id" => workspace_id,
        "sequence" => checkpoint.sequence + 1,
        "issued_at" =>
          DateTime.utc_now() |> DateTime.truncate(:microsecond) |> DateTime.to_iso8601(),
        "previous_checkpoint_hash" => checkpoint.checkpoint_hash,
        "covered_event_head" => key_directory_event_head(deleted_event),
        "identity_keys" => checkpoint.payload["identity_keys"],
        "device_keys" => checkpoint.payload["device_keys"],
        "share_participant_keys" => checkpoint.payload["share_participant_keys"],
        "revoked_key_ids" => checkpoint.payload["revoked_key_ids"]
      })

    %{checkpoint: appended} =
      KeyDirectory.append_signed_scope!(
        "workspace",
        workspace_id,
        [
          signed_key_directory_event_envelope(started_event, device_private),
          signed_key_directory_event_envelope(completed_event, device_private),
          signed_key_directory_event_envelope(deleted_event, device_private)
        ],
        signed_key_directory_checkpoint_envelope(
          checkpoint_payload,
          "workspace_authorized",
          device_private,
          user_id
        ),
        checkpoint_signer_kind: "device"
      )

    assert appended.covered_event_head_hash == KeyDirectory.event_hash(deleted_event)
  end

  defp rotation_authority_payload(workspace_id, event_type, actor, sequence, body) do
    %{
      "protocol" => "refmd.key-directory-event",
      "version" => 1,
      "scope_kind" => "workspace",
      "scope_id" => workspace_id,
      "sequence" => sequence,
      "event_type" => event_type,
      "actor" => actor,
      "previous_event_hash" => Hash.blake3_base64url("previous-event"),
      "body" => body
    }
  end

  defp directory_fixture do
    user_id = Ecto.UUID.generate()
    workspace_id = Ecto.UUID.generate()
    owner_role_id = Ecto.UUID.generate()
    device_id = Ecto.UUID.generate()

    identity_private = hybrid_signing_private_key_material("identity", user_id)
    device_private = hybrid_signing_private_key_material("device", device_id)

    {identity_ecdh_public, _} = :crypto.generate_key(:ecdh, :x25519)
    {device_ecdh_public, _} = :crypto.generate_key(:ecdh, :x25519)

    identity_encryption =
      hybrid_encryption_public_key_material("identity", user_id, identity_ecdh_public)

    device_encryption =
      hybrid_encryption_public_key_material("device", device_id, device_ecdh_public)

    bootstrap =
      initial_key_directory_bootstrap(
        user_id,
        workspace_id,
        owner_role_id,
        identity_private,
        identity_encryption.public,
        device_private,
        device_encryption.public
      )

    %{
      user_id: user_id,
      workspace_id: workspace_id,
      bootstrap: bootstrap,
      identity_private: identity_private,
      device_private: device_private
    }
  end

  defp identity_actor(user_id, signing_key_id) do
    %{"signer_kind" => "identity", "user_id" => user_id, "signing_key_id" => signing_key_id}
  end

  defp workspace_device_actor(user_id, device_id, signing_key_id) do
    %{
      "signer_kind" => "device",
      "user_id" => user_id,
      "device_id" => device_id,
      "signing_key_id" => signing_key_id
    }
  end

  defp key_directory_event_payload!(attrs) do
    attrs
    |> put_initial_event_actor_authority()
    |> Map.put_new("authority_boundary", key_directory_event_authority_boundary(attrs))
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

  defp key_directory_event_authority_boundary(attrs) do
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

  defp key_directory_checkpoint_payload!(attrs) do
    attrs
    |> Map.put("authority_boundary", key_directory_checkpoint_authority_boundary(attrs))
    |> KeyDirectory.build_checkpoint_payload!()
  end

  defp key_directory_checkpoint_authority_boundary(%{"sequence" => 1}) do
    %{"required_authority" => "tofu_root"}
  end

  defp key_directory_checkpoint_authority_boundary(_attrs) do
    %{"required_authority" => "checkpoint_authorized"}
  end

  defp device_key_entry!(checkpoint_payload, protocol) do
    Enum.find(checkpoint_payload["device_keys"], fn entry ->
      get_in(entry, ["key_material", "protocol"]) == protocol
    end) || flunk("missing #{protocol} device key entry")
  end

  defp replace_key_entry(entries, replacement) do
    replacement_key_id = replacement["key_id"]

    Enum.map(entries, fn
      %{"key_id" => ^replacement_key_id} -> replacement
      entry -> entry
    end)
  end
end
