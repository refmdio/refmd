defmodule RefMD.UsersTest do
  use RefMD.DataCase, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias RefMD.Crypto.Hash
  alias RefMD.Devices.Device
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Users
  alias RefMD.Users.User

  test "resolve_invitation_recipient returns only active verified device delivery keys" do
    user_id = create_user("known-recipient@example.com")
    Users.update_encryption_setup(user_id)
    active = insert_device_fixture(user_id)
    revoked = insert_device_fixture(user_id, DateTime.utc_now())

    assert {:ok,
            %{
              delivery_mode: "known_recipient",
              recipient_user_id: ^user_id,
              devices: [device]
            }} = Users.resolve_invitation_recipient("  KNOWN-recipient@example.com ")

    assert device.device_id == active.id
    assert device.encryption_key_id == active.encryption_key_id
    assert device.signing_key_id == active.signing_key_id
    refute device.device_id == revoked.id
  end

  test "resolve_invitation_recipient permits fragments only for absent registered accounts" do
    incomplete_user_id = create_user("incomplete-recipient@example.com")
    insert_device_fixture(incomplete_user_id)

    revoked_user_id = create_user("revoked-recipient@example.com")
    Users.update_encryption_setup(revoked_user_id)
    insert_device_fixture(revoked_user_id, DateTime.utc_now())

    assert {:ok, %{delivery_mode: "unknown_fragment"}} =
             Users.resolve_invitation_recipient("missing@example.com")

    assert {:error, :recipient_delivery_unavailable} =
             Users.resolve_invitation_recipient("incomplete-recipient@example.com")

    assert {:error, :recipient_delivery_unavailable} =
             Users.resolve_invitation_recipient("revoked-recipient@example.com")

    assert :ok =
             Users.validate_invitation_delivery_binding(
               "missing@example.com",
               "unknown_fragment",
               nil,
               []
             )

    assert {:error, :recipient_delivery_unavailable} =
             Users.validate_invitation_delivery_binding(
               "revoked-recipient@example.com",
               "unknown_fragment",
               nil,
               []
             )
  end

  test "unlink_external_account_preserving_login keeps one OAuth method under concurrent deletes" do
    user_id = create_user("oauth-unlink-race@example.com")
    create_oauth_master_key(user_id)

    {:ok, _google} =
      Users.create_user_external_account(%{
        user_id: user_id,
        provider: "google",
        provider_user_id: "oauth-unlink-race-google",
        email: "oauth-unlink-race@example.com"
      })

    {:ok, _github} =
      Users.create_user_external_account(%{
        user_id: user_id,
        provider: "github",
        provider_user_id: "oauth-unlink-race-github",
        email: "oauth-unlink-race@example.com"
      })

    parent = self()

    tasks =
      for provider <- ["google", "github"] do
        Task.async(fn ->
          Sandbox.allow(Repo, parent, self())
          Users.unlink_external_account_preserving_login(user_id, provider)
        end)
      end

    results = Enum.map(tasks, &Task.await(&1, 5_000))

    assert Enum.count(results, &match?({:ok, :ok}, &1)) == 1
    assert Enum.count(results, &match?({:error, :last_auth_method_required}, &1)) == 1
    assert length(Users.get_user_external_accounts(user_id)) == 1
  end

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email,
      account_type: "registered"
    })

    user_id
  end

  defp create_oauth_master_key(user_id) do
    recovery = recovery_authorization_material(user_id)

    {:ok, _master_key} =
      Encryption.create_user_encrypted_master_key(%{
        user_id: user_id,
        auth_type: "oauth",
        recovery_encrypted_umk: <<4::256>>,
        recovery_nonce: <<5::192>>,
        recovery_authorization_public_material: recovery.public,
        recovery_authorization_key_id: recovery.key_id
      })
  end

  defp insert_device_fixture(user_id, revoked_at \\ nil) do
    device_id = Ecto.UUID.generate()
    signing = hybrid_device_material(device_id)
    {x25519_public, _private} = :crypto.generate_key(:ecdh, :x25519)
    encryption = hybrid_encryption_public_key_material("device", device_id, x25519_public)
    checkpoint_hash = Hash.blake3_base64url("recipient-device:" <> device_id)
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
      approval_signature: %{"fixture" => "recipient-device"},
      approval_signature_surface: "device_approval",
      approval_proof: %{
        "target_key_checkpoint_sequence" => 1,
        "target_key_checkpoint_hash" => checkpoint_hash
      },
      key_checkpoint_sequence: 1,
      key_checkpoint_hash: checkpoint_hash,
      client_nonce: :crypto.strong_rand_bytes(16),
      last_seen_at: now,
      created_at: now,
      revoked_at: revoked_at
    })
  end
end
