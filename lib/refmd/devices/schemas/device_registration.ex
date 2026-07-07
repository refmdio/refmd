defmodule RefMD.Devices.DeviceRegistration do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.{Encoding, Hash, HybridEncryptionMaterial, JCS, Signature}

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "device_registrations" do
    belongs_to :user, RefMD.Users.User
    field :name, :string
    field :device_type, :string
    field :hybrid_encryption_public_key_material, :map
    field :encryption_key_id, :string
    field :hybrid_signing_public_key_material, :map
    field :signing_key_id, :string
    field :client_nonce, :binary
    field :pending_registration_challenge_hash, :string
    field :ake_responder_prekeys, :map
    field :approval_signature, :map
    field :approval_signature_surface, :string
    field :approval_proof, :map
    field :approval_delivery_commitments, :map
    field :approval_delivery_artifacts, :map
    field :approval_key_directory, :map
    field :ip_address, :string
    field :created_at, :utc_datetime_usec
    field :expires_at, :utc_datetime_usec
  end

  def changeset(device_registration, attrs) do
    device_registration
    |> cast(attrs, [
      :id,
      :user_id,
      :name,
      :device_type,
      :hybrid_encryption_public_key_material,
      :hybrid_signing_public_key_material,
      :signing_key_id,
      :client_nonce,
      :pending_registration_challenge_hash,
      :ake_responder_prekeys,
      :approval_signature,
      :approval_signature_surface,
      :approval_proof,
      :approval_delivery_commitments,
      :approval_delivery_artifacts,
      :approval_key_directory,
      :ip_address,
      :expires_at
    ])
    |> validate_required([
      :id,
      :user_id,
      :name,
      :device_type,
      :hybrid_encryption_public_key_material,
      :hybrid_signing_public_key_material,
      :client_nonce,
      :pending_registration_challenge_hash,
      :expires_at
    ])
    |> validate_inclusion(:device_type, ~w(browser desktop mobile))
    |> validate_hybrid_encryption_material()
    |> validate_hybrid_signing_material()
    |> validate_change(
      :pending_registration_challenge_hash,
      &validate_pending_registration_challenge_hash/2
    )
    |> validate_required([:encryption_key_id, :signing_key_id])
    |> validate_byte_size(:client_nonce, 16)
    |> validate_ake_responder_prekeys()
    |> unique_constraint(:signing_key_id)
  end

  defp validate_pending_registration_challenge_hash(:pending_registration_challenge_hash, value) do
    Hash.assert_blake3_base64url!(value)
    []
  rescue
    ArgumentError -> [pending_registration_challenge_hash: "is invalid"]
  end

  defp validate_ake_responder_prekeys(changeset) do
    prekeys = get_field(changeset, :ake_responder_prekeys)

    if is_nil(prekeys) do
      changeset
    else
      validate_change(
        changeset,
        :ake_responder_prekeys,
        &validate_ake_responder_prekey_set(&1, &2, changeset)
      )
    end
  end

  defp validate_ake_responder_prekey_set(field, value, changeset) do
    if valid_responder_prekey_set?(value, changeset) do
      []
    else
      [{field, "must be a valid purpose-scoped initial AKE responder prekey set"}]
    end
  end

  defp valid_responder_prekey_set?(prekeys, changeset) when is_map(prekeys) do
    device_id = get_field(changeset, :id)
    user_id = get_field(changeset, :user_id)
    signing_key_id = get_field(changeset, :signing_key_id)
    public_material = get_field(changeset, :hybrid_signing_public_key_material)

    required_keys = ["umk_distribution", "trust_transfer"]

    valid_responder_prekey_set_keys?(prekeys) and
      Enum.all?(required_keys, &Map.has_key?(prekeys, &1)) and
      Enum.all?(prekeys, fn
        {"umk_distribution", %{"payload" => payload, "signature" => signature} = record} ->
          exact_keys?(record, ["payload", "signature"]) and
            valid_responder_prekey_record?(
              payload,
              signature,
              "umk_distribution",
              device_id,
              user_id,
              signing_key_id,
              public_material
            )

        {"trust_transfer", %{"payload" => payload, "signature" => signature} = record} ->
          exact_keys?(record, ["payload", "signature"]) and valid_uuid?(payload["operation_id"]) and
            valid_responder_prekey_record?(
              payload,
              signature,
              "trust_transfer",
              payload["operation_id"],
              user_id,
              signing_key_id,
              public_material
            )

        {<<"device_approval_kek_initial:", _workspace_id::binary>>,
         %{"payload" => payload, "signature" => signature} = record} ->
          exact_keys?(record, ["payload", "signature"]) and
            valid_responder_prekey_record?(
              payload,
              signature,
              "device_approval_kek_initial",
              device_id,
              user_id,
              signing_key_id,
              public_material
            )

        _ ->
          false
      end)
  end

  defp valid_responder_prekey_set?(_, _), do: false

  defp valid_responder_prekey_set_keys?(prekeys) when is_map(prekeys) do
    Enum.all?(Map.keys(prekeys), fn
      "umk_distribution" -> true
      "trust_transfer" -> true
      <<"device_approval_kek_initial:", workspace_id::binary>> -> valid_uuid?(workspace_id)
      _ -> false
    end)
  end

  defp valid_uuid?(value) when is_binary(value), do: match?({:ok, _}, Ecto.UUID.cast(value))
  defp valid_uuid?(_), do: false

  defp valid_responder_prekey_record?(
         payload,
         signature,
         purpose,
         operation_id,
         user_id,
         signing_key_id,
         public_material
       )
       when is_map(payload) and is_map(signature) and is_binary(purpose) and
              is_binary(operation_id) and is_binary(user_id) and is_binary(signing_key_id) and
              is_map(public_material) do
    with true <-
           exact_keys?(payload, [
             "expires_event_sequence",
             "issued_at_event_sequence",
             "mlkem768_ephemeral_public",
             "mlkem768_ephemeral_public_hash",
             "operation_id",
             "prekey_id",
             "protocol",
             "purpose",
             "responder_device_id",
             "responder_signer_kind",
             "responder_signing_key_id",
             "responder_user_id",
             "server_challenge",
             "version",
             "x25519_ephemeral_public"
           ]),
         true <- payload["protocol"] == "refmd.responder-prekey",
         true <- payload["version"] == 1,
         true <- payload["purpose"] == purpose,
         true <- payload["operation_id"] == operation_id,
         true <- payload["responder_user_id"] == user_id,
         true <- payload["responder_device_id"] == public_material["owner_id"],
         true <- payload["responder_signer_kind"] == "device",
         true <- payload["responder_signing_key_id"] == signing_key_id,
         {:ok, x25519_public} <- decode_base64url(payload["x25519_ephemeral_public"], 32),
         {:ok, mlkem768_public} <- decode_base64url(payload["mlkem768_ephemeral_public"], 1184),
         true <-
           payload["mlkem768_ephemeral_public_hash"] == Hash.blake3_base64url(mlkem768_public),
         {:ok, _server_challenge} <- decode_base64url(payload["server_challenge"], 32),
         true <- byte_size(x25519_public) == 32,
         true <- is_integer(payload["issued_at_event_sequence"]),
         true <- is_integer(payload["expires_event_sequence"]),
         true <- payload["issued_at_event_sequence"] < payload["expires_event_sequence"],
         transcript <-
           Signature.build_responder_prekey_transcript!(
             public_material["owner_id"],
             payload,
             %{
               "user_id" => user_id,
               "device_id" => public_material["owner_id"],
               "signing_key_id" => signing_key_id,
               "key_scope_kind" => "user",
               "key_scope_id" => user_id,
               "key_checkpoint_sequence" => 1,
               "key_checkpoint_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(payload))
             },
             %{
               "purpose" => purpose,
               "prekey_id" => payload["prekey_id"],
               "operation_id" => operation_id,
               "issued_at_event_sequence" => payload["issued_at_event_sequence"],
               "expires_event_sequence" => payload["expires_event_sequence"],
               "server_challenge" => payload["server_challenge"]
             }
           ) do
      Signature.verify_hybrid_signature(
        "responder_prekey",
        transcript,
        signature,
        public_material
      )
    else
      _ -> false
    end
  rescue
    _ -> false
  end

  defp valid_responder_prekey_record?(_, _, _, _, _, _, _), do: false

  defp decode_base64url(value, bytes) when is_binary(value) do
    {:ok, Encoding.decode_base64url!(value, bytes)}
  rescue
    ArgumentError -> :error
  end

  defp decode_base64url(_, _), do: :error

  defp exact_keys?(value, keys) do
    Enum.sort(Map.keys(value)) == Enum.sort(keys)
  end

  defp validate_hybrid_encryption_material(changeset) do
    changeset
    |> put_encryption_key_id()
    |> validate_change(:hybrid_encryption_public_key_material, fn field, material ->
      device_id = get_field(changeset, :id)

      try do
        with :ok <- HybridEncryptionMaterial.assert_public_key_material!(material),
             true <- material["owner_kind"] == "device",
             true <- is_binary(device_id),
             true <- material["owner_id"] == device_id do
          []
        else
          _ -> [{field, "must be valid device hybrid encryption public key material"}]
        end
      rescue
        ArgumentError -> [{field, "must be valid device hybrid encryption public key material"}]
      end
    end)
  end

  defp put_encryption_key_id(changeset) do
    case get_change(changeset, :hybrid_encryption_public_key_material) do
      material when is_map(material) ->
        put_change(
          changeset,
          :encryption_key_id,
          HybridEncryptionMaterial.compute_key_id!(material)
        )

      _ ->
        changeset
    end
  rescue
    ArgumentError -> changeset
  end

  defp validate_hybrid_signing_material(changeset) do
    validate_change(changeset, :hybrid_signing_public_key_material, fn field, material ->
      device_id = get_field(changeset, :id)

      try do
        with :ok <- Signature.assert_public_key_material!(material),
             true <- material["owner_kind"] == "device",
             true <- is_binary(device_id),
             true <- material["owner_id"] == device_id do
          []
        else
          _ -> [{field, "must be valid device hybrid signing public key material"}]
        end
      rescue
        ArgumentError -> [{field, "must be valid device hybrid signing public key material"}]
      end
    end)
    |> put_signing_key_id()
  end

  defp put_signing_key_id(changeset) do
    case get_change(changeset, :hybrid_signing_public_key_material) do
      material when is_map(material) ->
        put_change(changeset, :signing_key_id, Signature.compute_signing_key_id!(material))

      _ ->
        changeset
    end
  rescue
    ArgumentError -> changeset
  end

  defp validate_byte_size(changeset, field, expected) do
    validate_change(changeset, field, fn _, value ->
      if byte_size(value) == expected,
        do: [],
        else: [{field, "must be exactly #{expected} bytes"}]
    end)
  end
end
