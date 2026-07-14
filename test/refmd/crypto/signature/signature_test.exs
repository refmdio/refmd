defmodule RefMD.Crypto.Signature.SignatureTest do
  use ExUnit.Case, async: true

  alias RefMD.Crypto.{Blake3, Encoding, Hash, Signature}
  alias RefMD.Crypto.SigningSurface
  alias RefMD.TestCrypto

  @suite_id "refmd-v2-hybrid-signature-ed25519-mldsa65"
  @device_id "00000000-0000-4000-8000-000000000001"
  @other_device_id "00000000-0000-4000-8000-000000000002"
  @approver_device_id "00000000-0000-4000-8000-000000000003"
  @approved_device_id "00000000-0000-4000-8000-000000000004"
  @user_id "00000000-0000-4000-8000-000000000005"

  @mldsa65_public """
  R0Z20_Y9AHMXBb5U4X81MOiwLOK_e7Kj5ubccU_UexvDUxM-ZXOvZIhKbdj67gGbrggYMG9FaJd1izotMps9PnGm1yYMXps7yq-OJiG8ebWB8v8am9Dkl2xc5fFWE3uqnFOcBaajauZdxVN0OdURVG6t9ejYEafZrNN9cjGDRmZsisVyiHiVspY2DxJ0B6UDBJ8H2PC4sQdwjQl7gJwasX8nk7ghnUJOZw_XIhotj5a_B6SQGqgactnS9hH278gJmy2dGOxv8AvI6v3BrFmVcHLQJygXGNyM5-VKB-6MaUDeya9uLV3CzR3sPU5piC8JVnPuCvhmD0pLVIMVDXLNTlYWxaA1dONf7EjNTmFJQoOI_ldpEhVQzlzV_54bqOjOce4Y7q7MFpwCySopZjNCK203ep9SxHsma7Q4Zo1HiLL6Cl3oKz6I4_EVWEs5xS-xob8ZE-C6mNLjCqi70ITUKLfu_PbJ214nYvdwHBfG8WnLqDSQFtk1lV-fDltStgLNQBiBZ_mmbxg__x7sLuEZp-c3aexfMBd-A_JI9_ncXKqw0FzNO1dBX8cTusOl_-sVTxRHKPkuSLnE--B19qMi2mzAxkOzfuS1FBk5DB7o7YyTm68IXtb83WWHOxkdb85qNLHkpeU-Yw5N4FBh8SlIK-WSEJUrCOzH99HxIZZcBbDvkIZYRI_BPBYZEyhEVMJKblwr69LrM48nFGCFszDHVylQuNGG0Sv7wQpl8y7bDwK9uINkaUjLlMyoM1FjWcwBg6Xt3bY3T1PJKcc6jPZb6ncXTUhUQjT9PWX6Apm5F83ogETTzqcVVBE9iKxcS7c4s1rKSSw0amSArLWu95fo5kyZq4W22c3CPDnnDIrdoYV6okk0eYO4_goHtY-0HwPFtTPwumdlbxYUbukddAwG85nKBKx-SeoFcWJvyaeknWyaNt5Oa6jQeVZad9pJFRoI_uTbuJWJHYxkkoFGEDSPSx-3M-xvrDRCO6J9IuGlUn2rMsrBVbKFoxE_KXAZeCIfsL6sOiGEjdnTbwGPBaMYi-swbNt1-ZIsnjwVOuq94S2EgXZbgSR0PiTyiw419TX3xD3dj0CRv-KY5YvPvdsk6tIltosUCK9jaYoALqmsHaZulNGNC0OdSJAy25m1WwfNl5vZ-VY4XZ8vuawcaz8mtgOwirpYBHrLQXBZkScMunerQaVwQz-6YtzH3tJXfVTNRKDrD7xAcXRwAj7wQuQ_CMLfIE4VZPwpBDEZnZqPx4RI9u7grk6-GZM-N2QJfTVhE8EzMcNCMnXZLxgTZFn8tfeNdXu8C5LIvTrxFpyfjxBnIt9a5Tz6TW90lmzx-YUa9c7wYpn-8fnu4OlcYlbl533Jz6kVO3rAe3U2XzmvPkSgInDzm0_WWAEE44JXeHyoX0p9qvx90qHPoF61vBiBbU89hN-KElvk_xNqorWO9IEBjscXKlq4acZvSxrJzR0MdjHELePbd2OfAEzG98N91o8UPFwRHnyE8x_kLYoEWnEAVHKyLDX5S9XLijsJQiIwTvDAkNAMWJzlcVHLI57Seug0eg5v6jTHwz-rnF_uyVk5hpVbOQIL26HG21ueu9jshPGzaYB8KGMHW0tjinxcTo3IT1Zl5rl2qJoaT3aX8fkkyJPxStXnlS17KUftKBwkEp5rjs2OjhSeLLBTctFUwKyb4k3AiED5RpDQTKQ4Z6RwRVPNyJyIxTUy1WtoSKohu2nCzN8g8Scu7W-HdnXwh6c3xvbWpIwMnZGxD-_yIeeGA4hySCLS5ut3EonP-7RjZRUm19Tb_qiZFRxAc5G5nVZ_vVGB1WVanHZCnNOAQkLbq-3IfVLYrFUogTTC3iGeHzQNzFa0snFu1GdO5xUei3Nr1DDO0EIf4kUcqHGo_wa5Y6tGf44wMZyNwzkObkRXXmbfk9c3ZVdVq4blOkT5Q4-MDB6u-ffZxAEnCDOy762xqodMwx6iH4QaMGk5RbtlCsI_-YPMTsuEUdbqDgHyH27mEH7DQCjSQ5L_a-HLCcsHrRQtSnerGryq4JEoRG9xIsuwj9WOnz95TweS2JSXr4e241T96_QkBVLfxnNZKaCYUUx4E8Cy8c-Aol9f0gx3MQ4tRmke6guY5EJfcKguiCJrvWz5cEMAularyCYeDqbo1o-wVNiGgoiM-JB9uDjmCJ18WjCSooVnT6qXuG6Ea2hgVHD6ZIiT66TbavPPAhq-IsQx8CqTFpnOV2JKjx-nILV7D6-8sPZS-m0VF4gkgMTOIApWgpPc-nW_I3rIADU1AdTAvdKDhUvUv4E_DtHdMApr3_wV05kWlrAk6TQwufxLxT6hFkoMC5nVHsEWwCBeOowLO1y0bXQXOTtzlwUWsR89cTUCSSgimEPERckbA6SoC8HWFkVJ1CZ0A5ewC1ZUutdQRFuhYx_GJ8gwGHtRIM8iflda9eFFmXreX6jMNcdbOrgkXR6AeGaBbkFphL9KqCM5W8209JRknhToMhrxFKtvCDezc80gpZ6o4nKC6q-5B6olg4vkwaCVLXHMKzj_4BBuWWV9i2TFdbDdQjh5taDlIK5EAzITW7dw-zBXvwU9IfovhTPn9W5g7rIECKE
  """

  test "verifies a TS-generated Ed25519 and ML-DSA-65 hybrid signature vector" do
    assert :ok ==
             Signature.assert_hybrid_signature!(
               "rrp_request",
               transcript(),
               signature(),
               public_key_material()
             )

    assert Signature.compute_signing_key_id!(public_key_material()) ==
             "LD5DqdhyIp9JAKzUYsfV0hZT2W-HtqRNfale_DrqA4Q"
  end

  test "requires both signature components and exact suite binding" do
    refute Signature.verify_hybrid_signature(
             "rrp_request",
             transcript(),
             Map.delete(signature(), "mldsa65"),
             public_key_material()
           )

    refute Signature.verify_hybrid_signature(
             "rrp_request",
             transcript(),
             Map.delete(signature(), "ed25519"),
             public_key_material()
           )

    refute Signature.verify_hybrid_signature(
             "rrp_request",
             transcript(),
             Map.put(signature(), "suite_rank", 1),
             public_key_material()
           )

    refute Signature.verify_hybrid_signature(
             "rrp_request",
             Map.put(transcript(), "challenge", "different"),
             signature(),
             public_key_material()
           )

    refute Signature.verify_hybrid_signature(
             "rrp_request",
             Map.put(transcript(), "generic_authority_boundary", %{"role" => "admin"}),
             signature(),
             public_key_material()
           )

    refute Signature.verify_hybrid_signature(
             "rrp_request",
             Map.put(transcript(), "owner_id", @other_device_id),
             signature(),
             public_key_material()
           )
  end

  test "classifies cryptographic failures before external semantic failures" do
    assert {:error, :invalid_signature} =
             Signature.verify_hybrid_signature_result(
               "rrp_request",
               Map.put(transcript(), "owner_id", @other_device_id),
               signature(),
               public_key_material()
             )

    assert {:error, :rrp_challenge_mismatch} =
             Signature.verify_hybrid_signature_result(
               "rrp_request",
               transcript(),
               signature(),
               public_key_material(),
               Map.put(rrp_semantic_context(), :challenge, "different")
             )

    assert {:error, :invalid_signature} =
             Signature.verify_hybrid_signature_result(
               "rrp_request",
               transcript(),
               Map.put(signature(), "ed25519", flip_base64url_byte(signature()["ed25519"])),
               public_key_material(),
               Map.put(rrp_semantic_context(), :challenge, "different")
             )
  end

  test "classifies signature validator ArgumentError reasons as dedicated errors" do
    reasons =
      "lib/refmd/crypto/signature/**/*.ex"
      |> Path.wildcard()
      |> Enum.flat_map(fn path ->
        ~r/raise(?:\(| )ArgumentError, "([a-z0-9_]+)"/
        |> Regex.scan(File.read!(path), capture: :all_but_first)
        |> List.flatten()
      end)
      |> Enum.uniq()

    assert reasons != []

    generic_reasons =
      Enum.filter(reasons, fn reason ->
        Signature.__test_semantic_error_reason__(reason) == :invalid_signature_semantics
      end)

    assert generic_reasons == []
  end

  test "rejects component-specific corruption" do
    refute Signature.verify_hybrid_signature(
             "rrp_request",
             transcript(),
             Map.put(signature(), "ed25519", flip_base64url_byte(signature()["ed25519"])),
             public_key_material()
           )

    refute Signature.verify_hybrid_signature(
             "rrp_request",
             transcript(),
             Map.put(signature(), "mldsa65", flip_base64url_byte(signature()["mldsa65"])),
             public_key_material()
           )

    refute Signature.verify_hybrid_signature(
             "rrp_request",
             transcript(),
             Map.put(
               signature(),
               "signing_key_id",
               flip_base64url_byte(signature()["signing_key_id"])
             ),
             public_key_material()
           )

    refute Signature.verify_hybrid_signature(
             "rrp_request",
             transcript(),
             signature(),
             Map.put(
               public_key_material(),
               "mldsa65_public",
               flip_base64url_byte(public_key_material()["mldsa65_public"])
             )
           )

    refute Signature.verify_hybrid_signature(
             "rrp_response",
             transcript(),
             signature(),
             public_key_material()
           )
  end

  test "rejects forbidden owner kinds and surface-owner combinations" do
    refute Signature.verify_hybrid_signature(
             "rrp_request",
             transcript(),
             signature(),
             Map.put(public_key_material(), "owner_kind", "plugin_publisher")
           )

    assert SigningSurface.get_active!("pq_wrap", "none").owner_kind == "device"

    assert SigningSurface.get_active!("workspace_pin_bootstrap", "none").owner_kind == "device"

    assert SigningSurface.get_active!("recipient_bound_authorization", "none").owner_kind ==
             "device"

    assert_raise ArgumentError, "signing_surface_not_active", fn ->
      SigningSurface.get_active!("key_directory_event", "document_update_accepted")
    end

    document_write_session_surface =
      SigningSurface.get_active!("key_directory_event", "document_write_session_admitted")

    assert document_write_session_surface.owner_kind == "device"

    assert :ok =
             SigningSurface.assert_owner_kind!(
               document_write_session_surface,
               "share_participant_device"
             )

    assert_raise ArgumentError, fn ->
      SigningSurface.get_active!("retired_transfer", "none")
    end
  end

  test "rejects null key directory previous hashes in transcript validation" do
    assert {:error, :invalid_signature} =
             Signature.verify_hybrid_signature_result(
               "key_directory_event",
               key_directory_event_transcript_with_null_previous_hash(),
               signature(),
               public_key_material()
             )

    assert {:error, :invalid_signature} =
             Signature.verify_hybrid_signature_result(
               "key_directory_checkpoint",
               key_directory_checkpoint_transcript_with_null_previous_hash(),
               signature(),
               public_key_material()
             )
  end

  test "device approval is device-owned and transcript-buildable" do
    assert SigningSurface.get_active!("device_approval", "none").owner_kind == "device"
    ecdh_public_key = "RUVfUzPqGgJWB8aDH5o80sn9A662y4hmI7nPI7TXpGg"

    hybrid_encryption_material =
      RefMD.TestCrypto.hybrid_encryption_public_key_material(
        "device",
        @approved_device_id,
        Base.url_decode64!(ecdh_public_key, padding: false)
      ).public

    transcript =
      Signature.build_device_approval_transcript!(
        @user_id,
        @approver_device_id,
        @approved_device_id,
        Map.put(public_key_material(), "owner_id", @approved_device_id),
        hybrid_encryption_material,
        "TjFQ5y_BaUt2XlscmYxEEw",
        %{
          "approved_device_registration_sas_hash" => Hash.blake3_base64url("sas"),
          "pending_registration_id" => @approved_device_id,
          "pending_registration_challenge_hash" => Hash.blake3_base64url("challenge"),
          "approving_owner_kind" => "device",
          "approving_owner_id" => @approver_device_id,
          "approving_signing_key_id" => Hash.blake3_base64url("approver-key"),
          "approving_key_checkpoint_sequence" => 1,
          "approving_key_checkpoint_hash" => Hash.blake3_base64url("approver-checkpoint"),
          "approving_device_key_directory_proof_hash" => Hash.blake3_base64url("proof"),
          "target_device_id" => @approved_device_id,
          "target_device_signing_key_id" => Hash.blake3_base64url("target-key"),
          "target_device_hybrid_signing_public_key_material_hash" =>
            Hash.blake3_base64url("target-signing-material"),
          "target_device_hybrid_encryption_public_key_material_hash" =>
            Hash.blake3_base64url("target-encryption-material"),
          "target_device_encryption_key_id" => Hash.blake3_base64url("target-encryption-key"),
          "target_device_client_nonce_hash" => Hash.blake3_base64url("target-nonce"),
          "target_key_checkpoint_sequence" => 2,
          "target_key_checkpoint_hash" => Hash.blake3_base64url("target-checkpoint"),
          "umk_distribution_delivery_commitment" => %{},
          "trust_transfer_delivery_commitment" => %{},
          "device_approval_kek_initial_delivery_commitments" => []
        }
      )

    assert transcript["owner_kind"] == "device"
    assert transcript["owner_id"] == @approver_device_id
  end

  defp key_directory_event_transcript_with_null_previous_hash do
    payload = %{
      "protocol" => "refmd.key-directory.event",
      "version" => 1,
      "scope_kind" => "workspace",
      "scope_id" => "workspace-1",
      "sequence" => 2,
      "previous_event_hash" => Hash.blake3_base64url("previous-event"),
      "event_type" => "device_key_added",
      "actor" => %{
        "signer_kind" => "device",
        "user_id" => @user_id,
        "device_id" => @device_id,
        "signing_key_id" => Signature.compute_signing_key_id!(public_key_material()),
        "key_scope_kind" => "workspace",
        "key_scope_id" => "workspace-1",
        "key_checkpoint_sequence" => 1,
        "key_checkpoint_hash" => Hash.blake3_base64url("checkpoint")
      },
      "body" => %{
        "user_id" => @user_id,
        "device_id" => @device_id,
        "signing_key_id" => Signature.compute_signing_key_id!(public_key_material()),
        "encryption_key_id" => Hash.blake3_base64url("encryption-key")
      }
    }

    "device_key_added"
    |> Signature.build_key_directory_event_transcript!("device", @device_id, payload)
    |> put_in(["event", "previous_event_hash"], nil)
  end

  defp key_directory_checkpoint_transcript_with_null_previous_hash do
    signer = %{
      "signer_kind" => "device",
      "user_id" => @user_id,
      "device_id" => @device_id,
      "signing_key_id" => Signature.compute_signing_key_id!(public_key_material()),
      "authorizing_checkpoint_sequence" => 1,
      "authorizing_checkpoint_hash" => Hash.blake3_base64url("previous-checkpoint")
    }

    payload = %{
      "protocol" => "refmd.key-directory.checkpoint",
      "version" => 1,
      "scope_kind" => "workspace",
      "scope_id" => "workspace-1",
      "sequence" => 2,
      "previous_checkpoint_hash" => Hash.blake3_base64url("previous-checkpoint"),
      "covered_event_head" => %{
        "head_sequence" => 2,
        "head_hash" => Hash.blake3_base64url("event-head")
      },
      "allowed_suite_ids" => [@suite_id],
      "min_suite_rank" => 1000,
      "suite_policy_version" => 1,
      "signer" => signer
    }

    "workspace_authorized"
    |> Signature.build_key_directory_checkpoint_transcript!("device", @device_id, payload, signer)
    |> put_in(["scope", "previous_checkpoint_hash"], nil)
  end

  test "snapshot transcript normalizes genesis nil parent id for strict JCS" do
    transcript =
      Signature.build_document_snapshot_transcript!(%{
        owner_kind: "device",
        owner_id: @device_id,
        workspace_id: "refmd.workspace.test",
        actor_user_id: @user_id,
        actor_device_id: @device_id,
        signing_key_id: Signature.compute_signing_key_id!(public_key_material()),
        public_data: %{
          "docId" => "refmd.doc.test-doc",
          "snapshotId" => "refmd.snapshot.genesis",
          "signingKeyId" => Signature.compute_signing_key_id!(public_key_material()),
          "ownerKind" => "device",
          "ownerId" => @device_id,
          "authorityKind" => "workspace_device",
          "authorityId" => "refmd.workspace.test",
          "authorityContextKey" => Signature.compute_signing_key_id!(public_key_material()),
          "authorityScopeId" => "refmd.doc.test-doc",
          "authorityPermissionVersion" => 1,
          "keyVersion" => 1,
          "keyCheckpointSequence" => 1,
          "keyCheckpointHash" => Hash.blake3_base64url("checkpoint"),
          "parentSnapshotId" => "GENESIS",
          "parentProofHash" => "GENESIS",
          "parentSnapshotUpdateClocks" => %{}
        },
        authority_boundary: %{
          "previous_workspace_event_sequence" => 1,
          "previous_workspace_event_hash" => Hash.blake3_base64url("checkpoint"),
          "admission_event_type" => "document_snapshot_accepted",
          "admission_nonce" => Hash.blake3_base64url("nonce"),
          "min_dek_version" => 1,
          "document_permission_proof_hash" => Hash.blake3_base64url("permission")
        },
        ciphertext: Encoding.encode_base64url("ciphertext"),
        nonce: Encoding.encode_base64url("nonce")
      })

    assert transcript["public_data"]["parentSnapshotId"] == "GENESIS"
  end

  defp public_key_material do
    %{
      "protocol" => "refmd.hybrid-signing-key-material",
      "version" => 1,
      "owner_kind" => "device",
      "owner_id" => @device_id,
      "ed25519_public" => "yoiIwo4OYEKbOu8Z9OoL-Elfq8SVi3JW-V41aOMSkcw",
      "mldsa65_public" => clean(@mldsa65_public),
      "suite_id" => @suite_id,
      "suite_rank" => 1000
    }
  end

  defp transcript do
    %{
      "protocol" => "refmd.hybrid-signature-transcript",
      "label" => "RefMD hybrid signature transcript v1",
      "version" => 1,
      "transcript_owner" => "refmd.rrp.request.http_user_device",
      "surface_id" => "rrp_request",
      "surface_variant" => "http_user_device",
      "signing_purpose" => "rrp_request",
      "owner_kind" => "device",
      "owner_id" => @device_id,
      "signature_suite_id" => @suite_id,
      "signature_suite_rank" => 1000,
      "challenge" => "TjFQ5y_BaUt2XlscmYxEEw",
      "rrp_variant" => "http_user_device",
      "transport" => "http",
      "actor" => %{
        "signer_kind" => "device",
        "device_id" => @device_id,
        "user_id" => @user_id,
        "signing_key_id" => Signature.compute_signing_key_id!(public_key_material()),
        "key_scope_kind" => "user",
        "key_scope_id" => @user_id,
        "key_checkpoint_sequence" => 1,
        "key_checkpoint_hash" => Hash.blake3_base64url("test-checkpoint")
      },
      "request" => %{
        "body_hash" => Hash.blake3_base64url(""),
        "canonical_query" => "a=1",
        "method" => "GET",
        "path" => "/api/test",
        "query_hash" => Hash.blake3_base64url("a=1")
      },
      "session" => %{
        "is_recovery" => false,
        "session_id_hash" => Hash.blake3_base64url("test-session"),
        "session_kind" => "user"
      }
    }
  end

  defp signature do
    Signature.__test_sign_hybrid_signature__(
      "rrp_request",
      transcript(),
      private_key_material(),
      public_key_material()
    )
  end

  defp rrp_semantic_context do
    %{
      device: %{
        id: @device_id,
        signing_key_id: Signature.compute_signing_key_id!(public_key_material()),
        revoked_at: nil
      },
      session: %{
        session_id_hash: transcript()["session"]["session_id_hash"]
      },
      challenge: transcript()["challenge"],
      user_id: @user_id
    }
  end

  defp private_key_material do
    {ed25519_public, ed25519_private} =
      :crypto.generate_key(:eddsa, :ed25519, fixture_seed("ed25519-private"))

    {mldsa65_private, mldsa65_public} =
      TestCrypto.mldsa65_keypair(fixture_seed("mldsa65-private"))

    %{
      "protocol" => "refmd.hybrid-signing-private-key-material",
      "version" => 1,
      "owner_kind" => "device",
      "owner_id" => @device_id,
      "ed25519_private" => Encoding.encode_base64url(ed25519_private),
      "ed25519_public" => Encoding.encode_base64url(ed25519_public),
      "mldsa65_private" => Encoding.encode_base64url(mldsa65_private),
      "mldsa65_public" => Encoding.encode_base64url(mldsa65_public),
      "suite_id" => @suite_id,
      "suite_rank" => 1000
    }
  end

  defp fixture_seed(label), do: Blake3.hash("refmd-test:" <> label)

  defp clean(value), do: String.replace(value, ~r/\s+/, "")

  defp flip_base64url_byte(value) do
    <<first, rest::binary>> = Base.url_decode64!(value, padding: false)
    Base.url_encode64(<<Bitwise.bxor(first, 1), rest::binary>>, padding: false)
  end
end
