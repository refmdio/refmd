defmodule RefMD.Devices.DeviceRegistrationTest do
  use RefMD.DataCase, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias RefMD.Auth.Session
  alias RefMD.Crypto.{Encoding, Hash, JCS, Signature}
  alias RefMD.Devices
  alias RefMD.Devices.DeviceRegistration
  alias RefMD.Repo
  alias RefMD.Users.User

  test "changeset accepts responder prekeys bound to the registration challenge" do
    attrs = registration_attrs()

    assert %Ecto.Changeset{valid?: true} =
             DeviceRegistration.changeset(%DeviceRegistration{}, attrs)
  end

  test "changeset rejects missing or substituted responder prekey challenges" do
    attrs = registration_attrs()

    substituted =
      update_in(attrs, [:ake_responder_prekeys, "umk_distribution", "payload"], fn payload ->
        Map.put(
          payload,
          "server_challenge",
          Encoding.encode_base64url(:crypto.strong_rand_bytes(32))
        )
      end)

    missing =
      update_in(attrs, [:ake_responder_prekeys, "trust_transfer", "payload"], fn payload ->
        Map.delete(payload, "server_challenge")
      end)

    refute DeviceRegistration.changeset(%DeviceRegistration{}, substituted).valid?
    refute DeviceRegistration.changeset(%DeviceRegistration{}, missing).valid?
  end

  test "changeset rejects operation ids reused across registration purposes" do
    attrs = registration_attrs()
    registration_id = attrs.id

    reused =
      put_in(
        attrs,
        [:ake_responder_prekeys, "umk_distribution", "payload", "operation_id"],
        registration_id
      )

    refute DeviceRegistration.changeset(%DeviceRegistration{}, reused).valid?
  end

  test "registration challenge is consumed exactly once" do
    user = user_fixture()
    session = session_fixture(user.id)

    assert {:ok, %{challenge: challenge}} = Devices.issue_registration_challenge(user.id, session)

    assert {:ok, %{pending: pending}} =
             Devices.replace_user_device_registration(
               user.id,
               session.id,
               registration_attrs(user_id: user.id, challenge: challenge)
             )

    assert pending.user_id == user.id

    stored_prekeys =
      from(p in "initial_ake_prekeys",
        where: p.device_registration_id == ^Ecto.UUID.dump!(pending.id),
        select: %{purpose: p.purpose, operation_id: p.operation_id, payload: p.payload}
      )
      |> Repo.all()

    assert Enum.sort(Enum.map(stored_prekeys, & &1.purpose)) == [
             "device_approval_kek_initial",
             "trust_transfer",
             "umk_distribution"
           ]

    encoded_challenge = Encoding.encode_base64url(challenge)
    assert Enum.all?(stored_prekeys, &(&1.payload["server_challenge"] == encoded_challenge))
    assert Enum.all?(stored_prekeys, &(&1.payload["operation_id"] == &1.operation_id))

    assert {:error, :registration_challenge, :invalid_registration_challenge, %{}} =
             Devices.replace_user_device_registration(
               user.id,
               session.id,
               registration_attrs(user_id: user.id, challenge: challenge)
             )
  end

  test "registration rejects challenge substitution and expiry" do
    user = user_fixture()
    session = session_fixture(user.id)

    assert {:ok, %{challenge: _issued_challenge}} =
             Devices.issue_registration_challenge(user.id, session)

    assert {:error, :registration_challenge, :invalid_registration_challenge, %{}} =
             Devices.replace_user_device_registration(
               user.id,
               session.id,
               registration_attrs(user_id: user.id)
             )

    assert {:ok, %{challenge: challenge}} = Devices.issue_registration_challenge(user.id, session)

    from(s in Session, where: s.id == ^session.id)
    |> Repo.update_all(
      set: [pending_registration_challenge_expires_at: DateTime.add(DateTime.utc_now(), -1)]
    )

    assert {:error, :registration_challenge, :invalid_registration_challenge, %{}} =
             Devices.replace_user_device_registration(
               user.id,
               session.id,
               registration_attrs(user_id: user.id, challenge: challenge)
             )
  end

  test "concurrent registration attempts consume one challenge atomically" do
    user = user_fixture()
    session = session_fixture(user.id)

    assert {:ok, %{challenge: challenge}} = Devices.issue_registration_challenge(user.id, session)

    parent = self()

    results =
      1..2
      |> Task.async_stream(
        fn _attempt ->
          Sandbox.allow(Repo, parent, self())

          Devices.replace_user_device_registration(
            user.id,
            session.id,
            registration_attrs(user_id: user.id, challenge: challenge)
          )
        end,
        max_concurrency: 2,
        ordered: false
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &match?({:ok, _}, &1)) == 1

    assert Enum.count(
             results,
             &match?(
               {:error, :registration_challenge, :invalid_registration_challenge, %{}},
               &1
             )
           ) == 1
  end

  defp registration_attrs(opts \\ []) do
    user_id = Keyword.get_lazy(opts, :user_id, &Ecto.UUID.generate/0)
    device_id = Keyword.get_lazy(opts, :device_id, &Ecto.UUID.generate/0)
    challenge = Keyword.get_lazy(opts, :challenge, fn -> :crypto.strong_rand_bytes(32) end)
    challenge_hash = Hash.blake3_base64url(challenge)
    private_material = hybrid_signing_private_key_material("device", device_id)
    public_material = hybrid_signing_public_key_material(private_material)
    {x25519_public, _private} = :crypto.generate_key(:ecdh, :x25519)

    encryption_material =
      hybrid_encryption_public_key_material("device", device_id, x25519_public).public

    prekeys = %{
      "umk_distribution" =>
        responder_prekey(
          "umk_distribution",
          Ecto.UUID.generate(),
          user_id,
          device_id,
          challenge,
          private_material,
          public_material
        ),
      "trust_transfer" =>
        responder_prekey(
          "trust_transfer",
          Ecto.UUID.generate(),
          user_id,
          device_id,
          challenge,
          private_material,
          public_material
        ),
      "device_approval_kek_initial:#{Ecto.UUID.generate()}" =>
        responder_prekey(
          "device_approval_kek_initial",
          device_id,
          user_id,
          device_id,
          challenge,
          private_material,
          public_material
        )
    }

    %{
      id: device_id,
      user_id: user_id,
      name: "Challenge-bound device",
      device_type: "browser",
      hybrid_encryption_public_key_material: encryption_material,
      hybrid_signing_public_key_material: public_material,
      client_nonce: :crypto.strong_rand_bytes(16),
      pending_registration_challenge_hash: challenge_hash,
      ake_responder_prekeys: prekeys,
      expires_at: DateTime.add(DateTime.utc_now(), 300, :second)
    }
  end

  defp user_fixture do
    id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: id,
      email: "challenge-#{id}@example.com",
      name: "Challenge user",
      account_type: "registered"
    })
  end

  defp session_fixture(user_id) do
    now = DateTime.utc_now()

    %Session{}
    |> Map.put(:created_at, now)
    |> Session.changeset(%{
      user_id: user_id,
      token_hash: Hash.blake3_base64url(:crypto.strong_rand_bytes(32)),
      remember_me: false,
      expires_at: DateTime.add(now, 3_600),
      last_seen_at: now
    })
    |> Repo.insert!()
  end

  defp responder_prekey(
         purpose,
         operation_id,
         user_id,
         device_id,
         challenge,
         private_material,
         public_material
       ) do
    mlkem_public = :crypto.strong_rand_bytes(1184)

    payload = %{
      "protocol" => "refmd.responder-prekey",
      "version" => 1,
      "purpose" => purpose,
      "prekey_id" => Ecto.UUID.generate(),
      "responder_signer_kind" => "device",
      "responder_user_id" => user_id,
      "responder_device_id" => device_id,
      "responder_signing_key_id" => Signature.compute_signing_key_id!(public_material),
      "x25519_ephemeral_public" => Encoding.encode_base64url(:crypto.strong_rand_bytes(32)),
      "mlkem768_ephemeral_public" => Encoding.encode_base64url(mlkem_public),
      "mlkem768_ephemeral_public_hash" => Hash.blake3_base64url(mlkem_public),
      "operation_id" => operation_id,
      "issued_at_event_sequence" => 1,
      "expires_event_sequence" => 2,
      "server_challenge" => Encoding.encode_base64url(challenge)
    }

    transcript =
      Signature.build_responder_prekey_transcript!(
        device_id,
        payload,
        %{
          "user_id" => user_id,
          "device_id" => device_id,
          "signing_key_id" => Signature.compute_signing_key_id!(public_material),
          "key_scope_kind" => "user",
          "key_scope_id" => user_id,
          "key_checkpoint_sequence" => 1,
          "key_checkpoint_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(payload))
        },
        %{
          "purpose" => purpose,
          "prekey_id" => payload["prekey_id"],
          "operation_id" => operation_id,
          "issued_at_event_sequence" => 1,
          "expires_event_sequence" => 2,
          "server_challenge" => payload["server_challenge"]
        }
      )

    %{
      "payload" => payload,
      "signature" =>
        Signature.__test_sign_hybrid_signature__(
          "responder_prekey",
          transcript,
          private_material,
          public_material
        )
    }
  end
end
