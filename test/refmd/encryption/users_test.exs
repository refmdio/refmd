defmodule RefMD.Encryption.UsersTest do
  use RefMD.DataCase, async: true

  alias RefMD.Crypto.{Hash, JCS, Signature}
  alias RefMD.Devices.Registrations.Materials
  alias RefMD.Encryption
  alias RefMD.Encryption.{UserEncryptedIdentityKey, UserIdentityPublicKey}
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMDWeb.Payloads.DeviceIdentity

  describe "create_user_identity_public_key/1" do
    test "assigns an explicit rotation deadline when omitted" do
      identity = create_identity_public_key!(create_user!()).public_key

      assert %DateTime{} = identity.rotation_due_at
    end

    test "rejects an explicitly missing rotation deadline" do
      user_id = create_user!()
      attrs = build_identity_material(user_id)

      assert {:error, changeset} =
               attrs
               |> Map.merge(%{
                 rotation_due_at: nil,
                 pending_registration_challenge_hash: Hash.blake3_base64url("challenge")
               })
               |> Encryption.create_user_identity_public_key()

      assert "can't be blank" in errors_on(changeset).rotation_due_at
    end
  end

  describe "create_user_encrypted_identity_key/1" do
    test "accepts encrypted identity key material matching the identity public keys" do
      user_id = create_user!()
      identity = create_identity_public_key!(user_id)

      assert {:ok, key} =
               Encryption.create_user_encrypted_identity_key(valid_identity_key_attrs(identity))

      assert key.user_id == user_id
      assert key.encryption_key_id == identity.encryption_key_id
      assert key.signing_key_id == identity.signing_key_id
    end

    test "rejects encrypted identity private key material that cannot contain an auth tag" do
      identity = create_identity_public_key!(create_user!())

      assert {:error, changeset} =
               identity
               |> valid_identity_key_attrs()
               |> Map.put(:encrypted_identity_hybrid_signing_private_key_material, <<1, 2, 3>>)
               |> Encryption.create_user_encrypted_identity_key()

      assert "must be a valid encrypted material blob" in errors_on(changeset).encrypted_identity_hybrid_signing_private_key_material
    end

    test "rejects encrypted identity key ids that do not match the identity public keys" do
      identity = create_identity_public_key!(create_user!())

      assert {:error, changeset} =
               identity
               |> valid_identity_key_attrs()
               |> Map.merge(%{
                 encryption_key_id: Hash.blake3_base64url("wrong-encryption-key"),
                 signing_key_id: Hash.blake3_base64url("wrong-signing-key")
               })
               |> Encryption.create_user_encrypted_identity_key()

      assert "must match identity public key" in errors_on(changeset).encryption_key_id
      assert "must match identity public key" in errors_on(changeset).signing_key_id
    end

    test "rejects encrypted identity keys without corresponding identity public material" do
      attrs =
        create_user!()
        |> build_identity_material()
        |> valid_identity_key_attrs()

      assert {:error, changeset} = Encryption.create_user_encrypted_identity_key(attrs)
      assert "must match identity public key" in errors_on(changeset).encryption_key_id
      assert "must match identity public key" in errors_on(changeset).signing_key_id
    end
  end

  describe "identity rotation lifecycle" do
    test "rejects obsolete identity deletion proof signature aliases at the domain boundary" do
      proof = %{
        "device_key_deletion_proofs" => [
          %{
            "payload" => %{},
            "transcript" => %{},
            "signature" => %{},
            "hybrid_signature" => %{}
          }
        ]
      }

      assert {:error, :invalid_identity_rotation} =
               Encryption.finalize_user_identity_rotation(
                 Ecto.UUID.generate(),
                 2,
                 proof,
                 %{events: [], checkpoint: %{}}
               )
    end

    test "device registration rejects overdue and historical identity signing keys" do
      user_id = create_user!()
      identity = create_identity_public_key!(user_id)

      assert :ok = Materials.validate_identity_signing_key_id(user_id, identity.signing_key_id)

      identity.public_key
      |> Ecto.Changeset.change(needs_rotation: true, rotation_due_at: DateTime.utc_now())
      |> Repo.update!()

      assert {:error, :invalid_identity_signing_key_id} =
               Materials.validate_identity_signing_key_id(user_id, identity.signing_key_id)

      identity.public_key
      |> Ecto.Changeset.change(
        lifecycle_state: "historical",
        needs_rotation: false,
        rotation_due_at: DateTime.add(DateTime.utc_now(), 86_400, :second)
      )
      |> Repo.update!()

      assert {:error, :invalid_identity_signing_key_id} =
               Materials.validate_identity_signing_key_id(user_id, identity.signing_key_id)

      assert {:error, :invalid_identity_hybrid_signing_public_key_material} =
               Materials.validate_bootstrap_identity_material(user_id, %{
                 identity_signing_key_id: identity.signing_key_id,
                 identity_hybrid_signing_public_key_material:
                   identity.hybrid_signing_public_key_material
               })
    end

    test "workspace creation rejects an overdue identity before bootstrap validation" do
      user_id = create_user!()
      identity = create_identity_public_key!(user_id)

      identity.public_key
      |> Ecto.Changeset.change(needs_rotation: true, rotation_due_at: DateTime.utc_now())
      |> Repo.update!()

      assert {:error, :identity_rotation_required} =
               Workspaces.create_workspace(user_id, "Blocked during identity rotation", %{})
    end

    test "versioned records retain historical public material after old private deletion" do
      user_id = create_user!()
      current = create_identity_public_key!(user_id)
      {:ok, _} = Encryption.create_user_encrypted_identity_key(valid_identity_key_attrs(current))
      pending = insert_pending_identity!(user_id, 2)

      proof = deletion_proof(current, pending)

      proof_hash = Hash.blake3_base64url(JCS.canonical_bytes!(proof))

      current.public_key
      |> Ecto.Changeset.change(
        lifecycle_state: "historical",
        superseded_at: DateTime.utc_now(),
        private_key_deletion_proof_hash: proof_hash
      )
      |> Repo.update!()

      pending |> Ecto.Changeset.change(lifecycle_state: "current") |> Repo.update!()
      Repo.get_by!(UserEncryptedIdentityKey, user_id: user_id, key_version: 1) |> Repo.delete!()

      Repo.get_by!(UserEncryptedIdentityKey, user_id: user_id, key_version: 2)
      |> Ecto.Changeset.change(lifecycle_state: "current")
      |> Repo.update!()

      assert %{key_version: 2, lifecycle_state: "current"} =
               Encryption.get_user_identity_public_key(user_id)

      assert [new_key, old_key] = Encryption.list_user_identity_public_keys(user_id)
      assert new_key.key_version == 2
      assert old_key.lifecycle_state == "historical"

      assert old_key.private_key_deletion_proof_hash == proof_hash

      refute Repo.get_by(UserEncryptedIdentityKey, user_id: user_id, key_version: 1)

      assert %{key_version: 2, lifecycle_state: "current"} =
               Encryption.get_user_encrypted_identity_key(user_id)

      device_identity = %{
        user_id: user_id,
        hybrid_encryption_public_key_material: %{},
        hybrid_signing_public_key_material: %{},
        approval_signature: %{},
        approval_signature_surface: "genesis_device_bootstrap",
        approval_proof: %{"approving_signing_key_id" => old_key.signing_key_id},
        approval_delivery_commitments: nil,
        approval_delivery_artifacts: nil,
        client_nonce: nil
      }

      sender_fields = DeviceIdentity.sender_fields(device_identity)

      assert sender_fields.sender_identity_hybrid_signing_public_key_material ==
               old_key.hybrid_signing_public_key_material

      recovery_sender_fields =
        device_identity
        |> Map.put(:approval_signature_surface, "recovery_device_approval")
        |> DeviceIdentity.sender_fields()

      assert recovery_sender_fields.sender_identity_hybrid_signing_public_key_material ==
               old_key.hybrid_signing_public_key_material
    end

    test "refuses finalization while any required workspace successor envelope is missing" do
      user_id = create_user!()
      current = create_identity_public_key!(user_id)
      {:ok, _} = Encryption.create_user_encrypted_identity_key(valid_identity_key_attrs(current))
      pending = insert_pending_identity!(user_id, 2)

      assert {:ok, _workspace} =
               Workspaces.create_default_workspace(user_id, "Rotation workspace")

      assert {:error, :identity_rotation_incomplete} =
               Encryption.finalize_user_identity_rotation(
                 user_id,
                 2,
                 deletion_proof(current, pending),
                 %{events: [], checkpoint: %{}}
               )

      assert %{key_version: 1, lifecycle_state: "current"} =
               Encryption.get_user_identity_public_key(user_id)

      assert %{key_version: 1} = Encryption.get_user_encrypted_identity_key(user_id)
      assert %{key_version: 2} = Encryption.get_pending_user_encrypted_identity_key(user_id)
    end

    test "durable activation makes fresh restore select only the successor" do
      user_id = create_user!()
      current = create_identity_public_key!(user_id)
      {:ok, _} = Encryption.create_user_encrypted_identity_key(valid_identity_key_attrs(current))
      pending = insert_pending_identity!(user_id, 2)

      assert {:ok, %{key_version: 2, deleted_key_version: 1}} =
               Encryption.activate_user_identity_rotation(user_id, 2)

      refute Repo.get_by(UserEncryptedIdentityKey, user_id: user_id, key_version: 1)

      assert %{key_version: 2, encryption_key_id: successor_key_id} =
               Encryption.get_user_encrypted_identity_key(user_id)

      assert successor_key_id == pending.encryption_key_id
      assert Encryption.get_pending_user_encrypted_identity_key(user_id) == nil

      assert %{
               encrypted_identity_key: %{key_version: 2, encryption_key_id: ^successor_key_id},
               identity_public_key: %{key_version: 1}
             } = Encryption.get_login_keys(user_id, nil)

      assert %{pending_key_version: 2, finalization_started: true} =
               Encryption.user_identity_rotation_status(user_id)

      assert {:ok, %{key_version: 2}} =
               Encryption.activate_user_identity_rotation(user_id, 2)
    end

    test "overdue persisted guest identity can enter durable rotation finalization" do
      user_id = create_user!("guest")
      current = create_identity_public_key!(user_id)
      {:ok, _} = Encryption.create_user_encrypted_identity_key(valid_identity_key_attrs(current))

      current.public_key
      |> Ecto.Changeset.change(needs_rotation: true, rotation_due_at: DateTime.utc_now())
      |> Repo.update!()

      pending = insert_pending_identity!(user_id, 2)

      assert {:error, :identity_rotation_required} =
               Encryption.user_identity_key_for_new_encryption(user_id)

      assert {:ok, %{key_version: 2}} =
               Encryption.activate_user_identity_rotation(user_id, 2)

      assert %{key_version: 2, encryption_key_id: successor_key_id} =
               Encryption.get_user_encrypted_identity_key(user_id)

      assert successor_key_id == pending.encryption_key_id

      assert %{finalization_started: true, pending_key_version: 2} =
               Encryption.user_identity_rotation_status(user_id)
    end

    test "guest activation rejects a missing current encrypted identity" do
      user_id = create_user!("guest")
      current = create_identity_public_key!(user_id)

      current.public_key
      |> Ecto.Changeset.change(needs_rotation: true, rotation_due_at: DateTime.utc_now())
      |> Repo.update!()

      pending = insert_pending_identity!(user_id, 2)

      assert {:error, :identity_rotation_incomplete} =
               Encryption.activate_user_identity_rotation(user_id, pending.key_version)

      assert %{key_version: 1, lifecycle_state: "current"} =
               Encryption.get_user_identity_public_key(user_id)

      assert %{key_version: 2, lifecycle_state: "pending"} =
               Encryption.get_pending_user_encrypted_identity_key(user_id)
    end
  end

  defp create_user!(account_type \\ "registered") do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: "identity-#{user_id}@example.com",
      name: "Identity #{user_id}",
      account_type: account_type
    })

    user_id
  end

  defp create_identity_public_key!(user_id) do
    material = build_identity_material(user_id)

    {:ok, identity} =
      Encryption.create_user_identity_public_key(%{
        user_id: user_id,
        hybrid_encryption_public_key_material: material.hybrid_encryption_public_key_material,
        hybrid_signing_public_key_material: material.hybrid_signing_public_key_material,
        pending_registration_challenge_hash: Hash.blake3_base64url("challenge")
      })

    Map.merge(material, %{
      public_key: identity,
      encryption_key_id: identity.encryption_key_id,
      signing_key_id: identity.signing_key_id
    })
  end

  defp build_identity_material(user_id) do
    build_identity_material(user_id, nil)
  end

  defp build_identity_material(user_id, label) do
    signing_private = hybrid_signing_private_key_material("identity", user_id, label)
    signing_public = hybrid_signing_public_key_material(signing_private)
    {x25519_public, _} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("identity", user_id, x25519_public)

    %{
      user_id: user_id,
      hybrid_encryption_public_key_material: encryption.public,
      hybrid_signing_public_key_material: signing_public,
      encryption_key_id: encryption.encryption_key_id,
      signing_key_id: Signature.compute_signing_key_id!(signing_public)
    }
  end

  defp insert_pending_identity!(user_id, key_version) do
    material = build_identity_material(user_id, "rotation-#{key_version}")
    current = Encryption.get_user_identity_public_key(user_id)

    public =
      %UserIdentityPublicKey{}
      |> UserIdentityPublicKey.changeset(%{
        user_id: user_id,
        key_version: key_version,
        lifecycle_state: "pending",
        rotation_due_at: DateTime.add(DateTime.utc_now(), 86_400, :second),
        hybrid_encryption_public_key_material: material.hybrid_encryption_public_key_material,
        hybrid_signing_public_key_material: material.hybrid_signing_public_key_material,
        pending_registration_challenge_hash: current.pending_registration_challenge_hash
      })
      |> Repo.insert!()

    %UserEncryptedIdentityKey{}
    |> UserEncryptedIdentityKey.changeset(
      valid_identity_key_attrs(%{
        material
        | encryption_key_id: public.encryption_key_id,
          signing_key_id: public.signing_key_id
      })
      |> Map.merge(%{key_version: key_version, lifecycle_state: "pending"})
    )
    |> Repo.insert!()

    public
  end

  defp deletion_proof(current, pending) do
    %{
      "old_encryption_key_id" => current.encryption_key_id,
      "old_private_key_use_blocked" => true,
      "old_signing_key_id" => current.signing_key_id,
      "old_version" => 1,
      "persistent_identity_deletion_authorized" => true,
      "successor_encryption_key_id" => pending.encryption_key_id,
      "successor_signing_key_id" => pending.signing_key_id,
      "successor_version" => 2
    }
  end

  defp valid_identity_key_attrs(identity) do
    %{
      user_id: identity.user_id,
      encrypted_identity_hybrid_encryption_private_key_material: <<1::128>>,
      identity_hybrid_encryption_private_key_material_nonce: <<2::192>>,
      encryption_key_id: identity.encryption_key_id,
      encrypted_identity_hybrid_signing_private_key_material: <<3::128>>,
      identity_hybrid_signing_private_key_material_nonce: <<4::192>>,
      signing_key_id: identity.signing_key_id
    }
  end
end
