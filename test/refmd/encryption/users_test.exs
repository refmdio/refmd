defmodule RefMD.Encryption.UsersTest do
  use RefMD.DataCase, async: true

  alias RefMD.Crypto.{Hash, Signature}
  alias RefMD.Encryption
  alias RefMD.Users.User

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

  defp create_user! do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: "identity-#{user_id}@example.com",
      name: "Identity #{user_id}",
      account_type: "registered"
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
      encryption_key_id: identity.encryption_key_id,
      signing_key_id: identity.signing_key_id
    })
  end

  defp build_identity_material(user_id) do
    signing_private = hybrid_signing_private_key_material("identity", user_id)
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
