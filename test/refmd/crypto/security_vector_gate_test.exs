defmodule RefMD.Crypto.SecurityVectorGateTest do
  use ExUnit.Case, async: true

  alias RefMD.Crypto.{Encoding, Hash, HybridEncryptionMaterial, JCS, Signature, SigningSurface}
  alias RefMD.Crypto.Signature.Plugin, as: PluginSignature
  alias RefMD.Crypto.Signature.SemanticValidator
  alias RefMD.Encryption.KeyDirectory.Signatures
  alias RefMD.Encryption.Wraps.SignedPQ

  @root Path.expand("../../..", __DIR__)

  test "server native crypto boundary is verify and hash only" do
    elixir_native = File.read!(Path.join(@root, "lib/refmd/crypto/native.ex"))
    rust_native = File.read!(Path.join(@root, "native/refmd_crypto/src/lib.rs"))
    rust_manifest = File.read!(Path.join(@root, "native/refmd_crypto/Cargo.toml"))

    assert elixir_native =~ "def hash("
    assert elixir_native =~ "def mldsa65_verify("
    refute elixir_native =~ "features:"
    refute elixir_native =~ "mldsa65_keypair"
    refute elixir_native =~ "mldsa65_sign"

    assert rust_native =~ "fn hash"
    assert rust_native =~ "fn mldsa65_verify"
    refute rust_native =~ "fn mldsa65_keypair"
    refute rust_native =~ "fn mldsa65_sign"
    refute rust_manifest =~ "test_signing"
  end

  test "test-only ML-DSA fixture generator stays outside the production native boundary" do
    test_crypto = File.read!(Path.join(@root, "test/support/test_crypto.ex"))
    test_native = File.read!(Path.join(@root, "test/support/test_crypto/native.ex"))
    test_rust_native = File.read!(Path.join(@root, "native/refmd_test_crypto/src/lib.rs"))
    signature_source = File.read!(Path.join(@root, "lib/refmd/crypto/signature/signature.ex"))

    assert test_native =~ ~s(crate: "refmd_test_crypto")
    assert test_crypto =~ "mldsa65_keypair"
    assert test_crypto =~ "mldsa65_sign"
    assert test_rust_native =~ "fn keypair_from_seed"
    assert test_rust_native =~ "fn sign"
    assert signature_source =~ "if Mix.env() == :test do"
    refute signature_source =~ "RefMD.TestCrypto.Native"

    production_refs =
      @root
      |> Path.join("lib/**/*.ex")
      |> Path.wildcard()
      |> Enum.filter(fn path ->
        source = File.read!(path)
        source =~ "RefMD.TestCrypto"
      end)
      |> Enum.map(&relative/1)
      |> Enum.sort()

    assert production_refs == ["lib/refmd/crypto/signature/signature.ex"]
  end

  test "fixture helpers stay in scanned approved fixture paths" do
    refute File.exists?(Path.join(@root, "assets/test-support"))
  end

  test "domain context roots contain only public API modules" do
    expected_root_files = %{
      "auth" => ["auth.ex"],
      "devices" => ["devices.ex"],
      "documents" => ["documents.ex"],
      "encryption" => ["encryption.ex"],
      "public" => ["public.ex"],
      "sharing" => ["sharing.ex"],
      "users" => ["users.ex"],
      "workspaces" => ["workspaces.ex"]
    }

    actual_root_files =
      for {context, _expected} <- expected_root_files, into: %{} do
        files =
          @root
          |> Path.join("lib/refmd/#{context}/*.ex")
          |> Path.wildcard()
          |> Enum.map(&Path.basename/1)
          |> Enum.sort()

        {context, files}
      end

    assert actual_root_files == expected_root_files
  end

  test "plugin archive temporary staging uses random exclusive file creation" do
    files = [
      Path.join(@root, "lib/refmd/plugins/source_archives/source_archives.ex"),
      Path.join(@root, "lib/refmd_web/controllers/plugin_management_controller.ex")
    ]

    for path <- files do
      source = File.read!(path)

      assert source =~ ":crypto.strong_rand_bytes"
      assert source =~ "Base.url_encode64(padding: false)"
      assert source =~ "[:write, :binary, :exclusive]"
      refute source =~ "System.unique_integer"
      refute source =~ "File.write(path,"
    end
  end

  test "static DH key-distribution worker surface is absent" do
    forbidden_literals = [
      token(["ecdh", "-encrypt"]),
      token(["ecdh", "-decrypt"]),
      token(["ecdh", "-encrypt", "-umk"]),
      token(["ecdh", "-decrypt", "-umk"]),
      token(["DEVICE", "_UMK", "_WRAP"]),
      token(["DEVICE", "_KEK", "_WRAP"]),
      token(["MEMBER", "_ENVELOPE", "_KEK", "_WRAP"]),
      token(["INVITATION", "_KEK", "_WRAP"]),
      token(["UMK", "_KEK", "_BACKUP"])
    ]

    assert not File.exists?(Path.join(@root, "assets/src/shared/lib/crypto/ecdh-cipher.ts"))

    assert not File.exists?(
             Path.join(@root, "assets/src/shared/lib/crypto/worker/handler/ecdh.ts")
           )

    assert not File.exists?(Path.join(@root, "assets/src/shared/lib/crypto/kek.ts"))

    offenders =
      scannable_files()
      |> Enum.flat_map(fn path ->
        source = File.read!(path)

        forbidden_literals
        |> Enum.filter(&String.contains?(source, &1))
        |> Enum.map(&{relative(path), &1})
      end)

    assert offenders == []
  end

  test "legacy generic signing worker routes are absent" do
    forbidden_literals = [
      quoted_token(["sign", "-pop"]),
      quoted_token(["sign", "-pop", "-request"]),
      quoted_token(["sign", "-device", "-approval"]),
      quoted_token(["sign", "-device", "-registration"]),
      quoted_token(["sign", "-device", "-revocation"]),
      quoted_token(["sign", "-recovery", "-challenge"]),
      quoted_token(["sign", "-session", "-proof"]),
      quoted_token(["sign", "-editor", "-ephemeral", "-session", "-proof"]),
      quoted_token(["verify", "-session", "-proof"]),
      quoted_token(["verify", "-device", "-identity", "-signature"]),
      token(["sign", "Pop"]),
      token(["sign", "Device", "Approval"]),
      token(["sign", "Device", "Registration"]),
      token(["sign", "Device", "Revocation"]),
      token(["sign", "Recovery", "Challenge"]),
      token(["sign", "Session", "Proof"]),
      token(["verify", "Session", "Proof"]),
      token(["verify", "Device", "Identity", "Signature"]),
      token(["handle", "Sign", "Pop"]),
      token(["handle", "Sign", "Device", "Approval"]),
      token(["handle", "Sign", "Device", "Registration"]),
      token(["handle", "Sign", "Device", "Revocation"]),
      token(["handle", "Sign", "Recovery", "Challenge"]),
      token(["handle", "Sign", "Session", "Proof"]),
      token(["handle", "Verify", "Session", "Proof"]),
      token(["handle", "Verify", "Device", "Identity", "Signature"])
    ]

    offenders =
      scannable_files()
      |> Enum.flat_map(fn path ->
        source = File.read!(path)

        forbidden_literals
        |> Enum.filter(&String.contains?(source, &1))
        |> Enum.map(&{relative(path), &1})
      end)

    assert offenders == []
  end

  test "generated API surfaces do not expose raw sender Ed25519 public keys" do
    forbidden_literals = [
      "sender_signing_public_key:",
      "\"sender_signing_public_key\""
    ]

    files =
      [
        "assets/openapi.json",
        "assets/src/shared/api/schema.d.ts"
      ]
      |> Enum.map(&Path.join(@root, &1))
      |> Enum.filter(&File.regular?/1)

    offenders =
      files
      |> Enum.flat_map(fn path ->
        source = File.read!(path)

        forbidden_literals
        |> Enum.filter(&String.contains?(source, &1))
        |> Enum.map(&{relative(path), &1})
      end)

    assert offenders == []
  end

  test "generated API exposes recovery authorization material only on member recovery surfaces" do
    openapi =
      @root
      |> Path.join("assets/openapi.json")
      |> File.read!()
      |> Jason.decode!()

    register_props = openapi["components"]["schemas"]["RegisterRequest"]["properties"]
    guest_props = openapi["components"]["schemas"]["RedeemGuestInvitationRequest"]["properties"]

    password_props =
      openapi["components"]["schemas"]["RegenerateRecoveryKeyRequest"]["properties"]

    assert register_props["recovery_authorization_public_material"] == %{
             "$ref" => "#/components/schemas/IdentityHybridSigningPublicKeyMaterial"
           }

    refute Map.has_key?(guest_props, "recovery_authorization_public_material")

    assert password_props["new_recovery_authorization_public_material"] == %{
             "$ref" => "#/components/schemas/IdentityHybridSigningPublicKeyMaterial"
           }

    generated_schema =
      @root
      |> Path.join("assets/src/shared/api/schema.d.ts")
      |> File.read!()

    assert generated_schema =~
             "recovery_authorization_public_material: components[\"schemas\"][\"IdentityHybridSigningPublicKeyMaterial\"]"

    refute generated_schema =~ "recovery_authorization_public_material: string"
  end

  test "generated OpenAPI object schemas explicitly close additional properties" do
    openapi =
      @root
      |> Path.join("assets/openapi.json")
      |> File.read!()
      |> Jason.decode!()

    component_offenders =
      openapi
      |> get_in(["components", "schemas"])
      |> Enum.flat_map(fn {name, schema} ->
        open_object_schema_paths(schema, "#/components/schemas/#{name}")
      end)

    request_offenders =
      openapi
      |> get_in(["paths"])
      |> Enum.flat_map(fn {path, path_item} ->
        path_item
        |> Enum.filter(fn {method, _operation} -> method in http_methods() end)
        |> Enum.flat_map(fn {method, operation} ->
          operation
          |> get_in(["requestBody", "content", "application/json", "schema"])
          |> open_object_schema_paths("#{String.upcase(method)} #{path} requestBody")
        end)
      end)

    assert component_offenders ++ request_offenders == []
  end

  test "generated OpenAPI binds initial AKE purpose to exact branches" do
    openapi =
      @root
      |> Path.join("assets/openapi.json")
      |> File.read!()
      |> Jason.decode!()

    assert one_of_refs(openapi, "InitialAkeArtifact") == [
             "#/components/schemas/InitialAkeUmkArtifact",
             "#/components/schemas/InitialAkeApprovalArtifact",
             "#/components/schemas/InitialAkeTrustTransferArtifact"
           ]

    assert one_of_refs(openapi, "InitialKeyDeliveryRecord") == [
             "#/components/schemas/InitialKeyDeliveryUmkRecord",
             "#/components/schemas/InitialKeyDeliveryApprovalRecord",
             "#/components/schemas/InitialKeyDeliveryTrustTransferRecord"
           ]

    branch_expectations = [
      {"InitialAkeUmkArtifact", "umk_distribution",
       "#/components/schemas/InitialAkeUmkTranscript"},
      {"InitialAkeApprovalArtifact", "device_approval_kek_initial",
       "#/components/schemas/InitialAkeApprovalTranscript"},
      {"InitialAkeTrustTransferArtifact", "trust_transfer",
       "#/components/schemas/InitialAkeTrustTransferTranscript"}
    ]

    Enum.each(branch_expectations, fn {name, purpose, transcript_ref} ->
      assert property_enum(openapi, name, "purpose") == [purpose]
      assert all_of_ref(openapi, name, "transcript") == transcript_ref
    end)

    transcript_expectations = [
      {"InitialAkeUmkTranscript", "umk_distribution", "#/components/schemas/InitialAkeUmkContext",
       "#/components/schemas/InitialAkeUmkDirectory"},
      {"InitialAkeApprovalTranscript", "device_approval_kek_initial",
       "#/components/schemas/InitialAkeApprovalContext",
       "#/components/schemas/InitialAkeApprovalDirectory"},
      {"InitialAkeTrustTransferTranscript", "trust_transfer",
       "#/components/schemas/InitialAkeTrustTransferContext",
       "#/components/schemas/InitialAkeTrustTransferDirectory"}
    ]

    Enum.each(transcript_expectations, fn {name, purpose, context_ref, directory_ref} ->
      assert property_enum(openapi, name, "purpose") == [purpose]
      assert all_of_ref(openapi, name, "context") == context_ref
      assert all_of_ref(openapi, name, "directory") == directory_ref
    end)

    delivery_expectations = [
      {"InitialKeyDeliveryUmkRecord", "umk_distribution",
       "#/components/schemas/InitialKeyDeliveryMetadata"},
      {"InitialKeyDeliveryApprovalRecord", "device_approval_kek_initial",
       "#/components/schemas/InitialKeyDeliveryApprovalMetadata"},
      {"InitialKeyDeliveryTrustTransferRecord", "trust_transfer",
       "#/components/schemas/InitialKeyDeliveryTrustTransferMetadata"}
    ]

    Enum.each(delivery_expectations, fn {name, purpose, metadata_ref} ->
      assert property_enum(openapi, name, "purpose") == [purpose]
      assert property_enum(openapi, name, "variant") == [purpose]
      assert all_of_ref(openapi, name, "metadata") == metadata_ref
    end)

    assert "pending_registration_binding_hash" in get_in(openapi, [
             "components",
             "schemas",
             "InitiatorAkeCommitmentInitiator",
             "required"
           ])

    initial_ake_components =
      get_in(openapi, ["components", "schemas", "InitialAkeRequiredComponents"])

    expected_required_components = [
      "x25519-ephemeral",
      "mlkem768-ephemeral",
      "hkdf-sha256",
      "initiator-ake-commitment",
      "responder-prekey-signature"
    ]

    assert initial_ake_components["minItems"] == length(expected_required_components)
    assert initial_ake_components["maxItems"] == length(expected_required_components)
    assert initial_ake_components["items"]["enum"] == expected_required_components

    assert "recipient_encryption_key_id" in get_in(openapi, [
             "components",
             "schemas",
             "InitialKeyDeliveryMetadata",
             "required"
           ])
  end

  test "device_authorized checkpoint surface is bound to device owners only" do
    previous_payload = %{
      "scope_kind" => "workspace",
      "device_keys" => []
    }

    checkpoint_payload = %{
      "scope_kind" => "workspace",
      "device_keys" => [%{"key_id" => "new-device-signing-key"}]
    }

    assert Signatures.checkpoint_signature_variant!(
             checkpoint_payload,
             %{"signer_kind" => "device", "signing_key_id" => "new-device-signing-key"},
             previous_payload
           ) == "device_authorized"

    assert_raise ArgumentError, "checkpoint_signer_kind_invalid", fn ->
      Signatures.checkpoint_signature_variant!(
        checkpoint_payload,
        %{"signer_kind" => "identity", "signing_key_id" => "identity-signing-key"},
        previous_payload
      )
    end
  end

  test "frontend session and worker surfaces do not expose legacy raw signing key fields" do
    forbidden_literals = [
      token(["identity", "Signing", "Public"]),
      token(["device", "Signing", "Public"]),
      token(["signing", "Public", "Key", ": ", "Uint8Array"]),
      token(["p", ".", "signing", "Public", "Key"]),
      quoted_token(["create", "-device", "-registration", "-signature"]),
      token(["create", "Device", "Registration", "Signature"])
    ]

    files =
      scannable_files()
      |> Enum.filter(fn path ->
        relative_path = relative(path)

        String.starts_with?(relative_path, "assets/src/") ||
          String.starts_with?(relative_path, "assets/test/")
      end)

    offenders =
      files
      |> Enum.flat_map(fn path ->
        source = File.read!(path)

        forbidden_literals
        |> Enum.filter(&String.contains?(source, &1))
        |> Enum.map(&{relative(path), &1})
      end)

    assert offenders == []
  end

  test "worker recovery authorization signing state is atomic" do
    state_source =
      @root
      |> Path.join("assets/src/shared/lib/crypto/worker/state/shared.ts")
      |> File.read!()

    assert String.contains?(state_source, "recoveryAuthorizationHybridSigningState")

    refute String.contains?(state_source, "recoveryAuthorizationPrivateKeyMaterial")
    refute String.contains?(state_source, "recoveryAuthorizationPublicKey")
    refute String.contains?(state_source, "recoveryAuthorizationKeyId: string | null")

    forbidden_state_access = [
      "state.recoveryAuthorizationPrivateKeyMaterial",
      "state.recoveryAuthorizationPublicKey",
      "state.recoveryAuthorizationKeyId"
    ]

    files =
      [
        "assets/src/shared/lib/crypto/worker/state/lifecycle.ts",
        "assets/src/shared/lib/crypto/worker/handler/keys/recovery.ts",
        "assets/src/shared/lib/crypto/worker/handler/sign.ts"
      ]
      |> Enum.map(&Path.join(@root, &1))

    offenders =
      files
      |> Enum.flat_map(fn path ->
        source = File.read!(path)

        forbidden_state_access
        |> Enum.filter(&String.contains?(source, &1))
        |> Enum.map(&{relative(path), &1})
      end)

    assert offenders == []
  end

  test "endpoint config supports hybrid PoP header sizes" do
    endpoint_config = Application.fetch_env!(:refmd, RefMDWeb.Endpoint)
    http_config = Keyword.fetch!(endpoint_config, :http)

    http_1_options = Keyword.fetch!(http_config, :http_1_options)
    http_2_options = Keyword.fetch!(http_config, :http_2_options)

    assert Keyword.fetch!(http_1_options, :max_header_length) >= 16_384
    assert Keyword.fetch!(http_2_options, :max_header_block_size) >= 16_384
  end

  test "share trust anchor refresh does not treat latest bootstrap hash as immutable identity" do
    source =
      @root
      |> Path.join("assets/src/features/share/lib/session/session.ts")
      |> File.read!()

    refute source =~ "anchor.latestBootstrapEventHash === response.latest_bootstrap_event_hash"
    assert source =~ "latestBootstrapEventHash: response.latest_bootstrap_event_hash"
    refute source =~ "shareAuthorizationStateFromAnchor"
  end

  test "share participant admission requires capability authorization proof" do
    session_source =
      @root
      |> Path.join("assets/src/features/share/lib/session/session.ts")
      |> File.read!()

    authorization_source =
      @root
      |> Path.join("lib/refmd/sharing/participants/authorization.ex")
      |> File.read!()

    openapi =
      @root
      |> Path.join("assets/openapi.json")
      |> File.read!()
      |> Jason.decode!()

    assert session_source =~ "signShareCapabilityAuthorization"
    assert session_source =~ "share_capability_authorization"
    assert authorization_source =~ "build_share_capability_authorization_transcript!"
    assert authorization_source =~ "share.authorization_public_key_material"

    for component <- ["ShareBootstrapRequest", "SharePasswordChallengeRequest"] do
      schema = component_schema(openapi, component)
      assert schema["properties"]["share_capability_authorization"]
      assert "share_capability_authorization" in schema["required"]
    end
  end

  test "password share capability authorization is not derived from server-visible auth key" do
    dek_source =
      @root
      |> Path.join("assets/src/shared/lib/crypto/worker/handler/dek.ts")
      |> File.read!()

    sign_source =
      @root
      |> Path.join("assets/src/shared/lib/crypto/worker/handler/sign.ts")
      |> File.read!()

    share_dek_source =
      @root
      |> Path.join("assets/src/shared/lib/crypto/share-dek.ts")
      |> File.read!()

    assert share_dek_source =~ "derivePasswordShareAdmissionKey"
    assert dek_source =~ "derivePasswordShareAdmissionKey("
    assert dek_source =~ "passwordChallengeAuthKey"

    assert dek_source =~
             ~r/deriveShareCapabilitySigningPrivateKeyMaterial\(\s*capabilitySecret,\s*shareTokenHash,\s*\)/

    assert sign_source =~
             ~r/deriveShareCapabilitySigningPrivateKeyMaterial\(\s*capabilitySecret,\s*shareTokenHash\s*\)/

    refute dek_source =~ "deriveShareCapabilitySigningPrivateKeyMaterial(\n      authKey,"

    refute dek_source =~
             ~r/deriveShareCapabilitySigningPrivateKeyMaterial\(\s*authorizationSecret,/

    refute sign_source =~
             ~r/deriveShareCapabilitySigningPrivateKeyMaterial\(\s*authorizationSecret,/

    refute dek_source =~ "authorizationSecret: authKey"
  end

  test "password share metadata hash covers full public metadata" do
    share_source =
      @root
      |> Path.join("assets/src/features/share/lib/manage/build-share.ts")
      |> File.read!()

    assert share_source =~ "refmd.password-auth-metadata-public"
    assert share_source =~ "auth_scheme: \"argon2id-hmac-authkey\""
    assert share_source =~ "server_auth_key_wrap_aad_hash"
    refute share_source =~ "canonicalizeStrictBytes(input.passwordFields"
  end

  defp open_object_schema_paths(nil, _path), do: []

  defp open_object_schema_paths(schema, path) when is_map(schema) do
    own =
      cond do
        schema["type"] == "object" and not Map.has_key?(schema, "additionalProperties") ->
          ["#{path} missing additionalProperties"]

        schema["type"] == "object" and schema["additionalProperties"] == true ->
          ["#{path} additionalProperties true"]

        true ->
          []
      end

    nested =
      schema
      |> Enum.flat_map(fn {key, value} ->
        open_object_schema_paths(value, "#{path}/#{key}")
      end)

    own ++ nested
  end

  defp open_object_schema_paths(values, path) when is_list(values) do
    values
    |> Enum.with_index()
    |> Enum.flat_map(fn {value, index} ->
      open_object_schema_paths(value, "#{path}[#{index}]")
    end)
  end

  defp open_object_schema_paths(_value, _path), do: []

  defp one_of_refs(openapi, component_name) do
    openapi
    |> component_schema(component_name)
    |> Map.fetch!("oneOf")
    |> Enum.map(&Map.fetch!(&1, "$ref"))
  end

  defp property_enum(openapi, component_name, property_name) do
    openapi
    |> component_schema(component_name)
    |> get_in(["properties", property_name, "enum"])
  end

  defp all_of_ref(openapi, component_name, property_name) do
    openapi
    |> component_schema(component_name)
    |> get_in(["properties", property_name, "allOf"])
    |> List.first()
    |> Map.fetch!("$ref")
  end

  defp component_schema(openapi, component_name),
    do: get_in(openapi, ["components", "schemas", component_name])

  defp http_methods,
    do: ["get", "put", "post", "delete", "options", "head", "patch", "trace"]

  test "security vector gates do not opt out of failures" do
    forbidden_literals = [
      token(["allow", "Failure"]),
      token(["allow", "_failure"]),
      token(["allowed", " failure"]),
      token(["allow", "-failure"])
    ]

    offenders =
      scannable_files()
      |> Enum.flat_map(fn path ->
        source = File.read!(path)

        forbidden_literals
        |> Enum.filter(&String.contains?(source, &1))
        |> Enum.map(&{relative(path), &1})
      end)

    assert offenders == []
  end

  test "mount bootstrap public surfaces stay hash-only and mount-local material stays local" do
    forbidden_public_literals = [
      token(["capability", "_reopen", "_secret", "_ref"]),
      token(["password", "_capability", "_secret", "_ref"])
    ]

    public_surface_files =
      [
        "assets/openapi.json",
        "assets/src/shared/api/schema.d.ts",
        "assets/src/shared/api/shares.ts",
        "lib/refmd/sharing/mounts/mounts.ex",
        "lib/refmd_web/controllers/share_mount_controller.ex",
        "lib/refmd_web/schemas/share/mount.ex"
      ]
      |> Enum.map(&Path.join(@root, &1))

    public_offenders =
      public_surface_files
      |> Enum.flat_map(fn path ->
        source = File.read!(path)

        forbidden_public_literals
        |> Enum.filter(&String.contains?(source, &1))
        |> Enum.map(&{relative(path), &1})
      end)

    assert public_offenders == []

    anchor_source =
      @root
      |> Path.join("assets/src/entities/mount/model/trust-anchor/trust-anchor.ts")
      |> File.read!()

    assert anchor_source =~ "share_session_key"
    assert anchor_source =~ "mountTrustAnchorRequest(anchor: MountTrustAnchor)"
    assert anchor_source =~ "mount_trust_anchor_invalid"
    assert anchor_source =~ "mountedShareSessionKey(anchor.mountId)"
    refute anchor_source =~ token(["capability", "_reopen", "_secret", "_ref"])
    refute anchor_source =~ token(["password", "_capability", "_secret", "_ref"])

    mounted_session_source =
      @root
      |> Path.join("assets/src/features/share/lib/session/session.ts")
      |> File.read!()

    assert mounted_session_source =~ "persistMountedShareSecretsWithDsk"
    assert mounted_session_source =~ "mountSessionKey"
  end

  test "every active signing surface has executable hybrid positive and negative vectors" do
    surfaces = active_surfaces_by_owner_kind()

    Enum.each(surfaces, fn surface ->
      private =
        RefMD.TestCrypto.hybrid_signing_private_key_material(
          owner_kind(surface),
          owner_id(surface)
        )

      public = RefMD.TestCrypto.hybrid_signing_public_key_material(private)
      transcript = production_transcript(surface, public)

      signature =
        Signature.__test_sign_hybrid_signature__(
          surface.signing_purpose,
          transcript,
          private,
          public
        )

      assert :ok =
               Signature.assert_hybrid_signature!(
                 surface.signing_purpose,
                 transcript,
                 signature,
                 public
               )

      refute Signature.verify_hybrid_signature(
               surface.signing_purpose,
               transcript,
               Map.delete(signature, "mldsa65"),
               public
             )

      refute Signature.verify_hybrid_signature(
               surface.signing_purpose,
               transcript,
               Map.delete(signature, "ed25519"),
               public
             )

      refute Signature.verify_hybrid_signature(
               surface.signing_purpose,
               Map.put(transcript, "transcript_owner", "refmd.invalid.transcript_owner"),
               signature,
               public
             )

      tampered_public = Map.put(public, "owner_id", tampered_owner_id(surface))

      assert {:error, :invalid_signature} =
               Signature.verify_hybrid_signature_result(
                 surface.signing_purpose,
                 transcript,
                 signature,
                 tampered_public
               )
    end)
  end

  test "device key deletion proof semantic negatives keep the signature valid" do
    surface =
      active_surfaces_by_owner_kind()
      |> Enum.find(
        &(&1.signing_purpose == "device_key_deletion_proof" and
            &1.variant == "device_key_deletion_proof")
      )

    private =
      RefMD.TestCrypto.hybrid_signing_private_key_material(
        owner_kind(surface),
        owner_id(surface)
      )

    public = RefMD.TestCrypto.hybrid_signing_public_key_material(private)
    transcript = production_transcript(surface, public)

    signature =
      Signature.__test_sign_hybrid_signature__(
        surface.signing_purpose,
        transcript,
        private,
        public
      )

    context = key_deletion_semantic_context(transcript, public)

    assert :ok =
             Signature.verify_hybrid_signature_result(
               surface.signing_purpose,
               transcript,
               signature,
               public,
               context
             )

    bad_context = put_in(context, [:deletion, :old_key_version], 2)

    assert {:error, :key_deletion_old_key_version_mismatch} =
             Signature.verify_hybrid_signature_result(
               surface.signing_purpose,
               transcript,
               signature,
               public,
               bad_context
             )

    assert {:error, :invalid_signature} =
             Signature.verify_hybrid_signature_result(
               surface.signing_purpose,
               transcript,
               Map.delete(signature, "ed25519"),
               public,
               bad_context
             )
  end

  test "plugin semantic validators reject non-canonical subject protocols" do
    [
      {"plugin_bundle_approval", "refmd.plugin.bundle_approval",
       :plugin_bundle_approval_subject_protocol_invalid},
      {"plugin_consent_event", "refmd.plugin.consent_event",
       :plugin_consent_event_subject_protocol_invalid},
      {"plugin_network_proxy_request", "refmd.plugin.network_proxy_request",
       :plugin_network_proxy_request_subject_protocol_invalid}
    ]
    |> Enum.each(fn {signing_purpose, stale_protocol, expected_reason} ->
      surface =
        active_surfaces_by_owner_kind()
        |> Enum.find(&(&1.signing_purpose == signing_purpose and &1.variant == "none"))

      public =
        RefMD.TestCrypto.hybrid_signing_private_key_material(
          owner_kind(surface),
          owner_id(surface)
        )
        |> RefMD.TestCrypto.hybrid_signing_public_key_material()

      transcript = production_transcript(surface, public)
      stale_transcript = Map.put(transcript, "subject_protocol", stale_protocol)

      assert_raise ArgumentError, Atom.to_string(expected_reason), fn ->
        case signing_purpose do
          "plugin_bundle_approval" ->
            SemanticValidator.validate_plugin_bundle_approval!(
              stale_transcript,
              surface.signing_purpose,
              owner_kind(surface),
              owner_id(surface),
              plugin_semantic_context(stale_transcript)
            )

          "plugin_consent_event" ->
            SemanticValidator.validate_plugin_consent_event!(
              stale_transcript,
              surface.signing_purpose,
              owner_kind(surface),
              owner_id(surface),
              plugin_semantic_context(stale_transcript)
            )

          "plugin_network_proxy_request" ->
            SemanticValidator.validate_plugin_network_proxy_request!(
              stale_transcript,
              surface.signing_purpose,
              owner_kind(surface),
              owner_id(surface),
              plugin_semantic_context(stale_transcript)
            )
        end
      end
    end)
  end

  test "plugin proxy request semantic validator rejects subject drift with valid signature shape" do
    surface =
      active_surfaces_by_owner_kind()
      |> Enum.find(
        &(&1.signing_purpose == "plugin_network_proxy_request" and &1.variant == "none")
      )

    public =
      RefMD.TestCrypto.hybrid_signing_private_key_material(
        owner_kind(surface),
        owner_id(surface)
      )
      |> RefMD.TestCrypto.hybrid_signing_public_key_material()

    transcript = production_transcript(surface, public)
    context = plugin_semantic_context(transcript)
    drifted_context = put_in(context, [:proxy_request_subject, "request_id"], "request-drift")

    assert :ok =
             SemanticValidator.validate_plugin_network_proxy_request!(
               transcript,
               surface.signing_purpose,
               owner_kind(surface),
               owner_id(surface),
               context
             )

    assert_raise ArgumentError, "plugin_network_proxy_request_subject_hash_mismatch", fn ->
      SemanticValidator.validate_plugin_network_proxy_request!(
        transcript,
        surface.signing_purpose,
        owner_kind(surface),
        owner_id(surface),
        drifted_context
      )
    end
  end

  test "plugin proxy request builders and semantic validators allow omitted credential audience" do
    surface =
      active_surfaces_by_owner_kind()
      |> Enum.find(
        &(&1.signing_purpose == "plugin_network_proxy_request" and &1.variant == "none")
      )

    public =
      RefMD.TestCrypto.hybrid_signing_private_key_material(
        owner_kind(surface),
        owner_id(surface)
      )
      |> RefMD.TestCrypto.hybrid_signing_public_key_material()

    subject =
      public
      |> plugin_network_proxy_request_subject()
      |> delete_nested_key(["endpoint", "credential_audience"])

    transcript =
      PluginSignature.build_plugin_network_proxy_request_transcript!(%{
        subject: subject
      })

    assert :ok =
             SemanticValidator.validate_plugin_network_proxy_request!(
               transcript,
               surface.signing_purpose,
               owner_kind(surface),
               owner_id(surface),
               %{proxy_request_subject: subject}
             )
  end

  test "plugin proxy request builders and semantic validators reject missing nested subject fields" do
    surface =
      active_surfaces_by_owner_kind()
      |> Enum.find(
        &(&1.signing_purpose == "plugin_network_proxy_request" and &1.variant == "none")
      )

    public =
      RefMD.TestCrypto.hybrid_signing_private_key_material(
        owner_kind(surface),
        owner_id(surface)
      )
      |> RefMD.TestCrypto.hybrid_signing_public_key_material()

    subject = plugin_network_proxy_request_subject(public)

    [
      {["proxy", "id"], "plugin_network_proxy_request_subject_invalid",
       "plugin_network_proxy_request_proxy_invalid"},
      {["target", "method"], "plugin_network_proxy_request_subject_invalid",
       "plugin_network_proxy_request_target_invalid"},
      {["target", "body_text"], "plugin_network_proxy_request_subject_invalid",
       "plugin_network_proxy_request_target_invalid"},
      {["endpoint", "max_request_bytes"], "plugin_network_proxy_request_subject_invalid",
       "plugin_network_proxy_request_endpoint_invalid"},
      {["runtime", "frame_generation"], "plugin_network_proxy_request_subject_invalid",
       "plugin_network_proxy_request_runtime_invalid"},
      {["runtime", "capability_grant_id"], "plugin_network_proxy_request_subject_invalid",
       "plugin_network_proxy_request_runtime_invalid"},
      {["runtime", "credential_handle_used"], "plugin_network_proxy_request_subject_invalid",
       "plugin_network_proxy_request_runtime_invalid"}
    ]
    |> Enum.each(fn {path, builder_error, validator_error} ->
      malformed_subject = delete_nested_key(subject, path)

      assert_raise ArgumentError, builder_error, fn ->
        PluginSignature.build_plugin_network_proxy_request_transcript!(%{
          subject: malformed_subject
        })
      end

      transcript =
        production_transcript(surface, public)
        |> Map.put("subject", malformed_subject)
        |> Map.put("subject_hash", Hash.blake3_base64url(JCS.canonical_bytes!(malformed_subject)))

      assert_raise ArgumentError, validator_error, fn ->
        SemanticValidator.validate_plugin_network_proxy_request!(
          transcript,
          surface.signing_purpose,
          owner_kind(surface),
          owner_id(surface),
          %{proxy_request_subject: malformed_subject}
        )
      end
    end)
  end

  test "plugin proxy request builders and semantic validators reject extra nested subject fields" do
    surface =
      active_surfaces_by_owner_kind()
      |> Enum.find(
        &(&1.signing_purpose == "plugin_network_proxy_request" and &1.variant == "none")
      )

    public =
      RefMD.TestCrypto.hybrid_signing_private_key_material(
        owner_kind(surface),
        owner_id(surface)
      )
      |> RefMD.TestCrypto.hybrid_signing_public_key_material()

    subject = plugin_network_proxy_request_subject(public)

    [
      {["proxy", "operator_label"], "plugin_network_proxy_request_subject_invalid",
       "plugin_network_proxy_request_proxy_invalid"},
      {["target", "redirect_policy"], "plugin_network_proxy_request_subject_invalid",
       "plugin_network_proxy_request_target_invalid"},
      {["endpoint", "policy"], "plugin_network_proxy_request_subject_invalid",
       "plugin_network_proxy_request_endpoint_invalid"},
      {["runtime", "deployment_id"], "plugin_network_proxy_request_subject_invalid",
       "plugin_network_proxy_request_runtime_invalid"}
    ]
    |> Enum.each(fn {path, builder_error, validator_error} ->
      malformed_subject = put_nested_key(subject, path, "unexpected")

      assert_raise ArgumentError, builder_error, fn ->
        PluginSignature.build_plugin_network_proxy_request_transcript!(%{
          subject: malformed_subject
        })
      end

      transcript =
        production_transcript(surface, public)
        |> Map.put("subject", malformed_subject)
        |> Map.put("subject_hash", Hash.blake3_base64url(JCS.canonical_bytes!(malformed_subject)))

      assert_raise ArgumentError, validator_error, fn ->
        SemanticValidator.validate_plugin_network_proxy_request!(
          transcript,
          surface.signing_purpose,
          owner_kind(surface),
          owner_id(surface),
          %{proxy_request_subject: malformed_subject}
        )
      end
    end)
  end

  test "plugin semantic validators reject actors outside the subject workspace scope" do
    [
      {"plugin_bundle_approval", :plugin_bundle_approval_actor_mismatch},
      {"plugin_consent_event", :plugin_consent_event_actor_mismatch}
    ]
    |> Enum.each(fn {signing_purpose, expected_reason} ->
      surface =
        active_surfaces_by_owner_kind()
        |> Enum.find(&(&1.signing_purpose == signing_purpose and &1.variant == "none"))

      public =
        RefMD.TestCrypto.hybrid_signing_private_key_material(
          owner_kind(surface),
          owner_id(surface)
        )
        |> RefMD.TestCrypto.hybrid_signing_public_key_material()

      transcript = production_transcript(surface, public)
      actor = transcript["actor"]

      for invalid_actor <- [
            %{actor | "key_scope_kind" => "user", "key_scope_id" => actor["user_id"]},
            %{actor | "key_scope_id" => "00000000-0000-4000-8000-000000000499"}
          ] do
        stale_transcript = Map.put(transcript, "actor", invalid_actor)

        assert_raise ArgumentError, Atom.to_string(expected_reason), fn ->
          case signing_purpose do
            "plugin_bundle_approval" ->
              SemanticValidator.validate_plugin_bundle_approval!(
                stale_transcript,
                surface.signing_purpose,
                owner_kind(surface),
                owner_id(surface),
                plugin_semantic_context(stale_transcript)
              )

            "plugin_consent_event" ->
              SemanticValidator.validate_plugin_consent_event!(
                stale_transcript,
                surface.signing_purpose,
                owner_kind(surface),
                owner_id(surface),
                plugin_semantic_context(stale_transcript)
              )
          end
        end
      end
    end)
  end

  test "plugin consent semantic validator rejects actor and consent subject user-device drift" do
    surface =
      active_surfaces_by_owner_kind()
      |> Enum.find(&(&1.signing_purpose == "plugin_consent_event" and &1.variant == "none"))

    public =
      RefMD.TestCrypto.hybrid_signing_private_key_material(owner_kind(surface), owner_id(surface))
      |> RefMD.TestCrypto.hybrid_signing_public_key_material()

    transcript = production_transcript(surface, public)

    stale_device =
      put_in(
        transcript,
        ["consent", "device_id"],
        "00000000-0000-4000-8000-000000000499"
      )
      |> refresh_plugin_consent_subject_hash()

    stale_user =
      transcript
      |> put_in(["consent", "user_id"], "00000000-0000-4000-8000-000000000499")
      |> refresh_plugin_consent_subject_hash()

    for stale_transcript <- [
          put_in(transcript, ["actor", "user_id"], "00000000-0000-4000-8000-000000000499"),
          stale_device,
          stale_user
        ] do
      assert_raise ArgumentError, "plugin_consent_event_actor_mismatch", fn ->
        SemanticValidator.validate_plugin_consent_event!(
          stale_transcript,
          surface.signing_purpose,
          owner_kind(surface),
          owner_id(surface),
          plugin_semantic_context(stale_transcript)
        )
      end
    end
  end

  test "active and disabled signing surface inventories are exact and disjoint" do
    active_pairs =
      SigningSurface.__test_active_surfaces__()
      |> Enum.map(&{&1.signing_purpose, &1.variant})
      |> Enum.sort()

    disabled_pairs = Enum.sort(expected_disabled_surface_pairs())

    assert active_pairs == Enum.sort(expected_active_surface_pairs())

    disabled = MapSet.new(disabled_pairs)
    active = MapSet.new(active_pairs)

    assert MapSet.disjoint?(disabled, active)

    Enum.each(expected_disabled_surface_pairs(), fn {signing_purpose, variant} ->
      assert_raise ArgumentError, "signing_surface_not_active", fn ->
        SigningSurface.get_active!(signing_purpose, variant)
      end
    end)
  end

  test "proxy request signing surface is active in both backend and frontend registries" do
    backend_pairs =
      SigningSurface.__test_active_surfaces__()
      |> MapSet.new(&{&1.signing_purpose, &1.variant})

    frontend_source =
      @root
      |> Path.join("assets/src/shared/lib/crypto/signing-surface.ts")
      |> File.read!()

    assert MapSet.member?(backend_pairs, {"plugin_network_proxy_request", "none"})
    assert frontend_source =~ ~s("plugin_network_proxy_request")
    assert frontend_source =~ ~s("refmd.plugin.network_proxy_request")
  end

  test "active signing surface registry resolves to production builder and validator functions" do
    Enum.each(SigningSurface.__test_active_surfaces__(), fn surface ->
      assert Map.keys(surface) |> Enum.sort() ==
               [
                 :owner_kind,
                 :protocol_version,
                 :signing_purpose,
                 :suite_id,
                 :surface_id,
                 :transcript_owner,
                 :variant
               ]

      builder = SigningSurface.transcript_builder!(surface)
      validator = SigningSurface.semantic_validator!(surface)

      assert Code.ensure_loaded?(builder.module)
      assert Code.ensure_loaded?(validator.module)
      assert function_exported?(builder.module, builder.function, builder.arity)
      assert function_exported?(validator.module, validator.function, validator.arity)
    end)
  end

  test "semantic validators are surface-specific for approval and admission surfaces" do
    validators =
      SigningSurface.__test_active_surfaces__()
      |> Map.new(fn surface ->
        validator = SigningSurface.semantic_validator!(surface)
        {{surface.signing_purpose, surface.variant}, validator.function}
      end)

    assert validators[{"device_approval", "none"}] == :validate_device_approval!
    assert validators[{"recovery_device_approval", "none"}] == :validate_recovery_approval!
    assert validators[{"plugin_bundle_approval", "none"}] == :validate_plugin_bundle_approval!
    assert validators[{"plugin_consent_event", "none"}] == :validate_plugin_consent_event!

    assert validators[{"plugin_network_proxy_request", "none"}] ==
             :validate_plugin_network_proxy_request!

    assert validators[{"document_update", "workspace_device"}] == :validate_document_admission!

    assert validators[{"document_snapshot", "share_participant_device"}] ==
             :validate_document_admission!

    assert validators[{"initial_key_delivery", "trust_transfer"}] ==
             :validate_initial_key_delivery!

    assert validators
           |> Map.values()
           |> MapSet.new()
           |> MapSet.size() > 1
  end

  test "stateful active signing surface validators receive server semantic context" do
    validators =
      SigningSurface.__test_active_surfaces__()
      |> Map.new(fn surface ->
        validator = SigningSurface.semantic_validator!(surface)
        {{surface.signing_purpose, surface.variant}, validator}
      end)

    Enum.each(stateful_semantic_surface_pairs(), fn pair ->
      assert %{arity: 5} = Map.fetch!(validators, pair)
    end)
  end

  test "critical signing surface transcripts match fixed known hashes" do
    expected_hashes = %{
      {"device_approval", "none"} => "ETSBSGm9tNk0qPU-jf4VOAec4DCH6INw4DYqM_lqJXE",
      {"initial_key_delivery", "device_approval_kek_initial"} =>
        "zcLux-hm8EKxKKKtPjvdgABqBjWcsKR1H9NUOxlxWmU",
      {"initiator_ake_commitment", "none"} => "yKREQZiYsh53w3Lhar0x231nXMbJewiFLTx3T29vsYU",
      {"key_directory_event", "old_key_deleted"} => "11BBwHRey50hdyHygrdZ8NkG2tlv4DL5yVhMKAz0F-o",
      {"pop_request", "http_user_device"} => "FBWSfnTExMamD6CsjYPzZxr5YBYKvtXWSJvbhOG1s9s",
      {"pq_wrap", "none"} => "xB-o8OD3A-OO3yd7nzVoX-FCThLgh5sHgCjbY_bPc-c"
    }

    actual_hashes =
      active_surfaces_by_owner_kind()
      |> Enum.filter(&Map.has_key?(expected_hashes, {&1.signing_purpose, &1.variant}))
      |> Map.new(fn surface ->
        public = fixed_public_material(owner_kind(surface), owner_id(surface))
        transcript = production_transcript(surface, public)

        {{surface.signing_purpose, surface.variant},
         Hash.blake3_base64url(JCS.canonical_bytes!(transcript))}
      end)

    assert actual_hashes == expected_hashes
  end

  test "non-workspace signed PQ wrap validators bind context, recipient, and wrap event" do
    Enum.each(non_workspace_signed_pq_wrap_purposes(), fn {purpose, validator} ->
      {attrs, context} = signed_pq_wrap_vector(purpose)

      assert :ok = apply(SignedPQ, validator, [attrs, context])

      assert :ok =
               SignedPQ.verify_signature(attrs, context.sender_signing_public_key_material)

      if purpose == "guest_invitation_workspace_kek_wrap" do
        {view_attrs, view_context} =
          signed_pq_wrap_vector(
            purpose,
            Map.put(signed_pq_wrap_resource(purpose), "permission", "view")
          )

        assert {:error, :invalid_guest_invitation_workspace_kek_wrap} =
                 SignedPQ.validate_guest_invitation_workspace_kek(view_attrs, view_context)
      end

      wrong_hpke_enc = %{attrs | hpke_enc: :crypto.strong_rand_bytes(32)}
      assert {:error, _reason} = apply(SignedPQ, validator, [wrong_hpke_enc, context])

      assert {:error, _reason} =
               SignedPQ.verify_signature(
                 %{attrs | hpke_enc: :crypto.strong_rand_bytes(1120)},
                 context.sender_signing_public_key_material
               )

      assert {:error, :invalid_signature} =
               SignedPQ.verify_signature(
                 %{attrs | ed25519_signature: :crypto.strong_rand_bytes(64)},
                 context.sender_signing_public_key_material
               )

      wrong_context = put_in(context, [:resource, "workspace_id"], "refmd.workspace.wrong")
      assert {:error, _reason} = apply(SignedPQ, validator, [attrs, wrong_context])

      wrong_recipient = %{context | recipient_key_id: Hash.blake3_base64url("wrong-recipient")}
      assert {:error, _reason} = apply(SignedPQ, validator, [attrs, wrong_recipient])

      wrong_event = %{context | key_directory_events: []}
      assert {:error, _reason} = apply(SignedPQ, validator, [attrs, wrong_event])
    end)
  end

  test "signed PQ wrap params reject unknown top-level fields before normalization" do
    {attrs, _context} = signed_pq_wrap_vector("share_link_secret_backup_wrap")

    wire_params =
      attrs
      |> SignedPQ.response_fields()
      |> Jason.encode!()
      |> Jason.decode!()

    assert %{} = SignedPQ.attrs_from_params!(wire_params)

    assert_raise ArgumentError, "signed_pq_wrap_schema_invalid", fn ->
      SignedPQ.attrs_from_params!(Map.put(wire_params, "unexpected", "field"))
    end

    assert_raise ArgumentError, "signed_pq_wrap_schema_invalid", fn ->
      SignedPQ.attrs_from_params!(put_in(wire_params, ["hpke", "unexpected"], "field"))
    end

    assert_raise ArgumentError, "signed_pq_wrap_schema_invalid", fn ->
      SignedPQ.attrs_from_params!(put_in(wire_params, ["signature", "unexpected"], "field"))
    end

    assert_raise ArgumentError, "signed_pq_wrap_schema_invalid", fn ->
      SignedPQ.attrs_from_params!(put_in(wire_params, ["resource", "unexpected"], "field"))
    end

    assert_raise ArgumentError, "signed_pq_wrap_schema_invalid", fn ->
      SignedPQ.attrs_from_params!(put_in(wire_params, ["sender", "unexpected"], "field"))
    end

    assert_raise ArgumentError, "signed_pq_wrap_schema_invalid", fn ->
      SignedPQ.attrs_from_params!(put_in(wire_params, ["recipient", "unexpected"], "field"))
    end

    assert_raise ArgumentError, "signed_pq_wrap_schema_invalid", fn ->
      SignedPQ.attrs_from_params!(put_in(wire_params, ["event_scope", "unexpected"], "field"))
    end

    assert %{} =
             SignedPQ.attrs_from_container_params!(
               Map.put(wire_params, "workspace_key_directory_checkpoint", %{})
             )

    assert_raise ArgumentError, "signed_pq_wrap_schema_invalid", fn ->
      SignedPQ.attrs_from_container_params!(Map.put(wire_params, "unexpected", "field"))
    end
  end

  test "signed PQ wrap validators reject schema-extra canonical nested objects" do
    Enum.each(non_workspace_signed_pq_wrap_purposes(), fn {purpose, validator} ->
      {attrs, context} = signed_pq_wrap_vector(purpose)

      assert {:error, _reason} =
               apply(SignedPQ, validator, [
                 %{attrs | sender: Map.put(attrs.sender, "unexpected", "field")},
                 %{context | sender: Map.put(context.sender, "unexpected", "field")}
               ])

      assert {:error, _reason} =
               apply(SignedPQ, validator, [
                 %{attrs | recipient: Map.put(attrs.recipient, "unexpected", "field")},
                 %{context | recipient: Map.put(context.recipient, "unexpected", "field")}
               ])

      assert {:error, _reason} =
               apply(SignedPQ, validator, [
                 %{attrs | event_scope: Map.put(attrs.event_scope, "unexpected", "field")},
                 %{context | event_scope: Map.put(context.event_scope, "unexpected", "field")}
               ])
    end)
  end

  test "signed PQ wrap event bodies reject schema-extra signed fields" do
    {attrs, _context} = signed_pq_wrap_vector("share_link_secret_backup_wrap")

    event =
      attrs
      |> signed_pq_wrap_event()
      |> put_in(["payload", "body", "unexpected"], "field")

    attrs = signed_pq_wrap_attrs_for_event(attrs, event)

    assert {:error, :wrap_event_mismatch} = SignedPQ.validate_wrap_event(attrs, [event])
  end

  test "signed PQ wrap resource semantics reject workspace scope for share-scoped purposes" do
    Enum.each(
      [
        {"share_participant_bootstrap_wrap", :validate_share_participant_bootstrap},
        {"share_link_secret_backup_wrap", :validate_share_link_secret_backup},
        {"guest_invitation_share_key_wrap", :validate_guest_invitation_share_key}
      ],
      fn {purpose, validator} ->
        {attrs, context} = signed_pq_wrap_vector(purpose)
        attrs = %{attrs | resource: Map.put(attrs.resource, "scope_kind", "workspace")}
        context = %{context | resource: attrs.resource}

        assert {:error, _reason} = apply(SignedPQ, validator, [attrs, context])
      end
    )
  end

  test "signed PQ wrap resource semantics reject none scope ids for share-scoped purposes" do
    Enum.each(
      [
        {"share_participant_bootstrap_wrap", :validate_share_participant_bootstrap},
        {"share_link_secret_backup_wrap", :validate_share_link_secret_backup},
        {"guest_invitation_share_key_wrap", :validate_guest_invitation_share_key}
      ],
      fn {purpose, validator} ->
        {attrs, context} = signed_pq_wrap_vector(purpose)
        attrs = %{attrs | resource: Map.put(attrs.resource, "scope_id", "none")}
        context = %{context | resource: attrs.resource}

        assert {:error, _reason} = apply(SignedPQ, validator, [attrs, context])
      end
    )
  end

  test "signed PQ wrap resource semantics reject malformed share-scoped hashes" do
    Enum.each(
      [
        {"share_participant_bootstrap_wrap", :validate_share_participant_bootstrap},
        {"share_link_secret_backup_wrap", :validate_share_link_secret_backup},
        {"guest_invitation_share_key_wrap", :validate_guest_invitation_share_key}
      ],
      fn {purpose, validator} ->
        {attrs, context} = signed_pq_wrap_vector(purpose)
        attrs = %{attrs | resource: Map.put(attrs.resource, "document_scope_hash", "not-a-hash")}
        context = %{context | resource: attrs.resource}

        assert {:error, _reason} = apply(SignedPQ, validator, [attrs, context])
      end
    )
  end

  test "share link secret backup allows absent password capability only for unprotected shares" do
    {attrs, context} = signed_pq_wrap_vector("share_link_secret_backup_wrap")
    resource = Map.put(attrs.resource, "password_capability_secret_commitment", "none")
    attrs = %{attrs | resource: resource} |> signed_pq_wrap_with_event_hashes()

    context = %{
      context
      | resource: attrs.resource,
        key_directory_events: [signed_pq_wrap_event(attrs)]
    }

    assert :ok = SignedPQ.validate_share_link_secret_backup(attrs, context)

    protected_resource = Map.put(resource, "password_protected", true)
    attrs = %{attrs | resource: protected_resource} |> signed_pq_wrap_with_event_hashes()

    context = %{
      context
      | resource: attrs.resource,
        key_directory_events: [signed_pq_wrap_event(attrs)]
    }

    assert {:error, _reason} = SignedPQ.validate_share_link_secret_backup(attrs, context)
  end

  defp scannable_files do
    include_roots = [
      "lib",
      "test",
      "assets/src",
      "assets/test",
      "assets/openapi.json",
      "priv/repo/migrations",
      ".github"
    ]

    files =
      include_roots
      |> Enum.flat_map(fn root ->
        path = Path.join(@root, root)

        if File.regular?(path) do
          [path]
        else
          Path.wildcard(Path.join([path, "**", "*"]))
        end
      end)
      |> Enum.filter(&File.regular?/1)

    metadata =
      [
        "justfile",
        "mix.exs",
        "mix.lock",
        "assets/package.json",
        "assets/pnpm-lock.yaml"
      ]
      |> Enum.map(&Path.join(@root, &1))
      |> Enum.filter(&File.regular?/1)

    Enum.sort(files ++ metadata)
  end

  defp token(parts), do: Enum.join(parts)

  defp quoted_token(parts), do: ~s("#{token(parts)}")

  defp relative(path), do: Path.relative_to(path, @root)

  defp non_workspace_signed_pq_wrap_purposes do
    [
      {"share_participant_bootstrap_wrap", :validate_share_participant_bootstrap},
      {"share_link_secret_backup_wrap", :validate_share_link_secret_backup},
      {"workspace_invitation_kek_wrap", :validate_workspace_invitation_kek},
      {"guest_invitation_workspace_kek_wrap", :validate_guest_invitation_workspace_kek},
      {"guest_invitation_share_key_wrap", :validate_guest_invitation_share_key}
    ]
  end

  defp signed_pq_wrap_vector(purpose, resource_override \\ nil) do
    sender_private =
      RefMD.TestCrypto.hybrid_signing_private_key_material(
        "device",
        "00000000-0000-4000-8000-000000000101"
      )

    sender_public = RefMD.TestCrypto.hybrid_signing_public_key_material(sender_private)
    sender_key_id = Signature.compute_signing_key_id!(sender_public)
    recipient_key_id = :crypto.strong_rand_bytes(32)

    event_scope = %{
      "scope_kind" => "workspace",
      "scope_id" => "refmd.workspace.security-vector"
    }

    sender = %{
      "signer_kind" => "device",
      "user_id" => "00000000-0000-4000-8000-000000000102",
      "device_id" => "00000000-0000-4000-8000-000000000101",
      "signing_key_id" => sender_key_id,
      "key_scope_kind" => "workspace",
      "key_scope_id" => event_scope["scope_id"],
      "key_checkpoint_sequence" => 1,
      "key_checkpoint_hash" => Hash.blake3_base64url("checkpoint")
    }

    recipient = %{
      "recipient_kind" => "device",
      "user_id" => "00000000-0000-4000-8000-000000000102",
      "device_id" => "00000000-0000-4000-8000-000000000103",
      "encryption_key_id" => Base.url_encode64(recipient_key_id, padding: false),
      "key_scope_kind" => "workspace",
      "key_scope_id" => event_scope["scope_id"],
      "key_checkpoint_sequence" => 1,
      "key_checkpoint_hash" => Hash.blake3_base64url("checkpoint")
    }

    attrs =
      %{
        wrap_protocol: "refmd.signed-pq-hybrid-wrap",
        wrap_version: 1,
        suite_id:
          "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
        suite_rank: 1000,
        kem_id: 0x647A,
        kdf_id: 0x0001,
        aead_id: 0x0003,
        purpose: purpose,
        resource: resource_override || signed_pq_wrap_resource(purpose),
        sender: sender,
        recipient: recipient,
        event_scope: event_scope,
        recipient_key_id: recipient_key_id,
        sender_signing_key_id: Base.url_decode64!(sender_key_id, padding: false),
        hpke_enc: :crypto.strong_rand_bytes(1120),
        hpke_ciphertext: :crypto.strong_rand_bytes(48),
        signature_protocol: "refmd.hybrid-signature",
        signature_version: 1,
        signature_suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
        signature_suite_rank: 1000,
        transcript_hash: :crypto.strong_rand_bytes(32),
        ed25519_signature: :crypto.strong_rand_bytes(64),
        mldsa65_signature: :crypto.strong_rand_bytes(3309),
        operation_checkpoint_sequence: 1,
        operation_checkpoint_hash: :crypto.strong_rand_bytes(32),
        operation_checkpoint_covered_head_sequence: 1,
        operation_checkpoint_covered_head_hash: :crypto.strong_rand_bytes(32),
        wrap_event_sequence: 2,
        previous_event_hash: Hash.blake3_base64url("previous-event")
      }
      |> signed_pq_wrap_with_event_hashes()
      |> sign_signed_pq_wrap_attrs(sender_private, sender_public)

    context = %{
      event_scope: attrs.event_scope,
      resource: attrs.resource,
      sender: attrs.sender,
      recipient: attrs.recipient,
      sender_signing_key_id: sender_key_id,
      sender_signing_public_key_material: sender_public,
      recipient_key_id: Base.url_encode64(recipient_key_id, padding: false),
      key_directory_events: [signed_pq_wrap_event(attrs)]
    }

    {attrs, context}
  end

  defp sign_signed_pq_wrap_attrs(attrs, private_material, public_material) do
    signature =
      Signature.__test_sign_hybrid_signature__(
        "pq_wrap",
        Signature.build_pq_wrap_transcript!(
          attrs.sender["device_id"],
          attrs.sender,
          signed_pq_wrap_authority_boundary(attrs),
          signed_pq_wrap_subject_hashes(attrs)
        ),
        private_material,
        public_material
      )

    attrs
    |> Map.put(:transcript_hash, Base.url_decode64!(signature["transcript_hash"], padding: false))
    |> Map.put(:ed25519_signature, Base.url_decode64!(signature["ed25519"], padding: false))
    |> Map.put(:mldsa65_signature, Base.url_decode64!(signature["mldsa65"], padding: false))
  end

  defp signed_pq_wrap_authority_boundary(attrs) do
    %{
      "scope_kind" => attrs.event_scope["scope_kind"],
      "scope_id" => attrs.event_scope["scope_id"],
      "event_hash" => Base.url_encode64(attrs.wrap_event_hash, padding: false),
      "operation_checkpoint_sequence" => attrs.operation_checkpoint_sequence,
      "operation_checkpoint_hash" =>
        Base.url_encode64(attrs.operation_checkpoint_hash, padding: false),
      "covered_event_head_sequence" => attrs.operation_checkpoint_covered_head_sequence,
      "covered_event_head_hash" =>
        Base.url_encode64(attrs.operation_checkpoint_covered_head_hash, padding: false)
    }
  end

  defp signed_pq_wrap_subject_hashes(attrs) do
    %{
      "resource_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(attrs.resource)),
      "wrap_body_hash" => Base.url_encode64(attrs.wrap_body_hash, padding: false),
      "wrap_event_body_hash" => Base.url_encode64(attrs.wrap_event_body_hash, padding: false),
      "wrap_event_hash" => Base.url_encode64(attrs.wrap_event_hash, padding: false),
      "hpke_info_hash" => Hash.blake3_base64url(signed_pq_wrap_hpke_info(attrs)),
      "aad_hash" => Hash.blake3_base64url(signed_pq_wrap_aad(attrs))
    }
  end

  defp signed_pq_wrap_hpke_info(attrs) do
    JCS.canonical_bytes!(%{
      "label" => "RefMD HPKE info v1",
      "protocol" => "refmd.signed-pq-hybrid-wrap",
      "protocol_version" => attrs.wrap_version,
      "suite_id" => attrs.suite_id,
      "suite_rank" => attrs.suite_rank,
      "purpose" => attrs.purpose,
      "resource_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(attrs.resource)),
      "sender_user_id" => attrs.sender["user_id"],
      "sender_device_id" => attrs.sender["device_id"],
      "sender_signing_key_id" => attrs.sender["signing_key_id"],
      "sender_key_scope_kind" => attrs.sender["key_scope_kind"],
      "sender_key_scope_id" => attrs.sender["key_scope_id"],
      "sender_key_checkpoint_hash" => attrs.sender["key_checkpoint_hash"],
      "recipient_kind" => attrs.recipient["recipient_kind"],
      "recipient_key_id" => attrs.recipient["encryption_key_id"],
      "recipient_key_scope_kind" => attrs.recipient["key_scope_kind"],
      "recipient_key_scope_id" => attrs.recipient["key_scope_id"],
      "recipient_key_checkpoint_hash" => attrs.recipient["key_checkpoint_hash"],
      "event_scope_kind" => attrs.event_scope["scope_kind"],
      "event_scope_id" => attrs.event_scope["scope_id"]
    })
  end

  defp signed_pq_wrap_aad(attrs) do
    JCS.canonical_bytes!(%{
      "label" => "RefMD PQ wrap AAD v1",
      "protocol" => "refmd.signed-pq-hybrid-wrap",
      "protocol_version" => attrs.wrap_version,
      "suite_id" => attrs.suite_id,
      "suite_rank" => attrs.suite_rank,
      "purpose" => attrs.purpose,
      "resource" => attrs.resource,
      "sender" => attrs.sender,
      "recipient" => attrs.recipient,
      "event_scope" => attrs.event_scope,
      "hpke" => %{
        "mode" => "base",
        "kem_id" => attrs.kem_id,
        "kdf_id" => attrs.kdf_id,
        "aead_id" => attrs.aead_id,
        "enc" => Base.url_encode64(attrs.hpke_enc, padding: false)
      }
    })
  end

  defp signed_pq_wrap_with_event_hashes(attrs) do
    wrap_body_hash =
      Hash.blake3_base64url(
        JCS.canonical_bytes!(%{
          "label" => "RefMD PQ wrap body v1",
          "protocol" => "refmd.signed-pq-hybrid-wrap",
          "version" => attrs.wrap_version,
          "suite_id" => attrs.suite_id,
          "suite_rank" => attrs.suite_rank,
          "purpose" => attrs.purpose,
          "resource" => attrs.resource,
          "sender" => attrs.sender,
          "recipient" => attrs.recipient,
          "event_scope" => attrs.event_scope,
          "hpke" => %{
            "mode" => "base",
            "kem_id" => attrs.kem_id,
            "kdf_id" => attrs.kdf_id,
            "aead_id" => attrs.aead_id,
            "enc" => Base.url_encode64(attrs.hpke_enc, padding: false),
            "ciphertext" => Base.url_encode64(attrs.hpke_ciphertext, padding: false)
          },
          "hpke_info_hash" => Hash.blake3_base64url(signed_pq_wrap_hpke_info(attrs)),
          "aad_hash" => Hash.blake3_base64url(signed_pq_wrap_aad(attrs))
        })
      )

    attrs = Map.put(attrs, :wrap_body_hash, Base.url_decode64!(wrap_body_hash, padding: false))
    event = signed_pq_wrap_event(attrs)
    event_body_hash = Hash.blake3_base64url(JCS.canonical_bytes!(event["payload"]["body"]))
    event_hash = Hash.blake3_base64url(JCS.canonical_bytes!(event["payload"]))

    attrs
    |> Map.put(:wrap_event_body_hash, Base.url_decode64!(event_body_hash, padding: false))
    |> Map.put(:wrap_event_hash, Base.url_decode64!(event_hash, padding: false))
    |> Map.put(:operation_checkpoint_covered_head_sequence, attrs.wrap_event_sequence)
    |> Map.put(
      :operation_checkpoint_covered_head_hash,
      Base.url_decode64!(event_hash, padding: false)
    )
  end

  defp signed_pq_wrap_event(attrs) do
    event_body = %{
      "purpose" => attrs.purpose,
      "recipient" => attrs.recipient,
      "resource" => attrs.resource,
      "resource_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(attrs.resource)),
      "sender" => attrs.sender,
      "wrap_body_hash" => Base.url_encode64(attrs.wrap_body_hash, padding: false),
      "wrap_protocol" => attrs.wrap_protocol,
      "wrap_suite_id" => attrs.suite_id,
      "wrap_suite_rank" => attrs.suite_rank,
      "wrap_version" => attrs.wrap_version
    }

    %{
      "payload" => %{
        "protocol" => "refmd.key-directory-event",
        "version" => attrs.wrap_version,
        "scope_kind" => attrs.event_scope["scope_kind"],
        "scope_id" => attrs.event_scope["scope_id"],
        "sequence" => attrs.wrap_event_sequence,
        "event_type" => "wrap_issued",
        "actor" => attrs.sender,
        "authority_boundary" => signed_pq_wrap_event_authority_boundary(attrs),
        "previous_event_hash" => attrs.previous_event_hash,
        "body" => event_body
      }
    }
  end

  defp signed_pq_wrap_attrs_for_event(attrs, %{"payload" => %{"body" => body} = payload}) do
    event_body_hash = Hash.blake3_base64url(JCS.canonical_bytes!(body))
    event_hash = Hash.blake3_base64url(JCS.canonical_bytes!(payload))

    %{
      attrs
      | wrap_event_body_hash: Base.url_decode64!(event_body_hash, padding: false),
        wrap_event_hash: Base.url_decode64!(event_hash, padding: false)
    }
  end

  defp signed_pq_wrap_event_authority_boundary(attrs) do
    %{
      "scope_kind" => attrs.event_scope["scope_kind"],
      "scope_id" => attrs.event_scope["scope_id"],
      "checkpoint_sequence" => attrs.operation_checkpoint_sequence,
      "checkpoint_hash" => Base.url_encode64(attrs.operation_checkpoint_hash, padding: false),
      "required_authority" => "event_type_authorized_actor"
    }
  end

  defp signed_pq_wrap_resource("share_participant_bootstrap_wrap") do
    %{
      "bootstrap_version" => 1,
      "dek_version" => 1,
      "document_scope_hash" => Hash.blake3_base64url("document-scope"),
      "permission" => "edit",
      "scope_id" => "refmd.document.scope",
      "scope_kind" => "document",
      "share_id" => "refmd.share",
      "share_key_version" => 1,
      "share_participant_device_id" => "refmd.share-device",
      "share_participant_principal_id" => "refmd.share-principal",
      "share_session_id" => "refmd.share-session",
      "workspace_id" => "refmd.workspace.security-vector"
    }
  end

  defp signed_pq_wrap_resource("share_link_secret_backup_wrap") do
    %{
      "created_event_hash" => Hash.blake3_base64url("share-created"),
      "key_checkpoint_hash" => Hash.blake3_base64url("checkpoint"),
      "password_capability_secret_commitment" => Hash.blake3_base64url("password-capability"),
      "password_protected" => false,
      "permission" => "edit",
      "recipient_device_id" => "refmd.device.recipient",
      "recipient_encryption_key_id" => Hash.blake3_base64url("recipient-key"),
      "recipient_user_id" => "refmd.user.recipient",
      "scope_id" => "refmd.document.scope",
      "scope_kind" => "document",
      "share_capability_secret_commitment" => Hash.blake3_base64url("share-capability"),
      "share_id" => "refmd.share",
      "token_hash" => Hash.blake3_base64url("token"),
      "workspace_id" => "refmd.workspace.security-vector",
      "workspace_pin_bootstrap_hash" => Hash.blake3_base64url("pin")
    }
  end

  defp signed_pq_wrap_resource("workspace_invitation_kek_wrap") do
    %{
      "invitation_id" => "refmd.invitation",
      "kek_version" => 1,
      "recipient_encryption_key_id" => Hash.blake3_base64url("recipient-key"),
      "redeemed_device_id" => "refmd.device.redeemed",
      "redeemed_user_id" => "refmd.user.redeemed",
      "role_id" => "refmd.role",
      "workspace_id" => "refmd.workspace.security-vector",
      "workspace_invitation_redeemed_event_hash" => Hash.blake3_base64url("redeemed")
    }
  end

  defp signed_pq_wrap_resource("guest_invitation_workspace_kek_wrap") do
    %{
      "guest_device_id" => "refmd.device.guest",
      "guest_grant_id" => "refmd.guest-grant",
      "guest_invitation_id" => "refmd.guest-invitation",
      "guest_invitation_redeemed_event_hash" => Hash.blake3_base64url("guest-redeemed"),
      "guest_user_id" => "refmd.user.guest",
      "kek_version" => 1,
      "permission" => "edit",
      "recipient_encryption_key_id" => Hash.blake3_base64url("recipient-key"),
      "scope_id" => "none",
      "scope_kind" => "workspace",
      "workspace_id" => "refmd.workspace.security-vector"
    }
  end

  defp signed_pq_wrap_resource("guest_invitation_share_key_wrap") do
    %{
      "dek_version" => 1,
      "document_scope_hash" => Hash.blake3_base64url("document-scope"),
      "guest_device_id" => "refmd.device.guest",
      "guest_invitation_id" => "refmd.guest-invitation",
      "guest_invitation_redeemed_event_hash" => Hash.blake3_base64url("guest-redeemed"),
      "guest_user_id" => "refmd.user.guest",
      "permission" => "view",
      "recipient_encryption_key_id" => Hash.blake3_base64url("recipient-key"),
      "scope_id" => "refmd.document.scope",
      "scope_kind" => "document",
      "share_id" => "refmd.share",
      "share_key_version" => 1,
      "workspace_id" => "refmd.workspace.security-vector"
    }
  end

  defp owner_kind(surface), do: surface.owner_kind

  defp active_surfaces_by_owner_kind do
    SigningSurface.__test_active_surfaces__()
    |> Enum.flat_map(fn surface ->
      surface.signing_purpose
      |> SigningSurface.__test_owner_kinds__(surface.variant)
      |> Enum.map(&Map.put(surface, :owner_kind, &1))
    end)
  end

  defp owner_id(%{signing_purpose: "share_capability_authorization"}),
    do: Hash.blake3_base64url("share-token")

  defp owner_id(surface) do
    case owner_kind(surface) do
      "identity" -> "00000000-0000-4000-8000-000000000201"
      "device" -> "00000000-0000-4000-8000-000000000202"
      "share_participant_device" -> "00000000-0000-4000-8000-000000000203"
      "invitation_redeem_authority" -> "00000000-0000-4000-8000-000000000204"
      owner_kind -> "refmd.#{owner_kind}.security-vector"
    end
  end

  defp tampered_owner_id(%{signing_purpose: "share_capability_authorization"}),
    do: Hash.blake3_base64url("wrong-share-token")

  defp tampered_owner_id(surface) do
    case owner_kind(surface) do
      "identity" -> "00000000-0000-4000-8000-000000000301"
      "device" -> "00000000-0000-4000-8000-000000000302"
      "share_participant_device" -> "00000000-0000-4000-8000-000000000303"
      "invitation_redeem_authority" -> "00000000-0000-4000-8000-000000000304"
      owner_kind -> "refmd.#{owner_kind}.semantic-negative"
    end
  end

  defp fixed_public_material(owner_kind, owner_id) do
    %{
      "protocol" => "refmd.hybrid-signing-key-material",
      "version" => 1,
      "owner_kind" => owner_kind,
      "owner_id" => owner_id,
      "suite_id" => "refmd-v2-hybrid-signature-ed25519-mldsa65",
      "suite_rank" => 1000,
      "ed25519_public" =>
        Base.url_encode64(deterministic_bytes("#{owner_kind}:#{owner_id}:ed25519", 32),
          padding: false
        ),
      "mldsa65_public" =>
        Base.url_encode64(deterministic_bytes("#{owner_kind}:#{owner_id}:mldsa65", 1952),
          padding: false
        )
    }
  end

  defp fixed_encryption_public_material(owner_kind, owner_id, label) do
    x25519_public = deterministic_bytes("#{label}:x25519", 32)
    mlkem768_public = deterministic_bytes("#{label}:mlkem768", 1184)

    %{
      "protocol" => "refmd.hybrid-encryption-key-material",
      "version" => 1,
      "owner_kind" => owner_kind,
      "owner_id" => owner_id,
      "suite_id" =>
        "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
      "suite_rank" => 1000,
      "x25519_public" => Base.url_encode64(x25519_public, padding: false),
      "mlkem768_public" => Base.url_encode64(mlkem768_public, padding: false),
      "hybrid_public" => Base.url_encode64(mlkem768_public <> x25519_public, padding: false)
    }
  end

  defp production_transcript(surface, public) do
    builder = SigningSurface.transcript_builder!(surface)
    apply(builder.module, builder.function, production_builder_args(surface, public))
  end

  defp key_deletion_semantic_context(transcript, public) do
    authority = transcript["authority_boundary"]

    %{
      signer: %{
        id: public["owner_id"],
        signing_key_id: Signature.compute_signing_key_id!(public)
      },
      deletion: %{
        scope_id: authority["scope_id"],
        old_key_version: authority["old_key_version"],
        rotation_completed_event_hash: authority["rotation_completed_event_hash"],
        deleted_secret_ids_hash: authority["deleted_secret_ids_hash"]
      }
    }
  end

  defp plugin_semantic_context(%{"actor" => actor, "approval" => approval}) do
    %{
      actor: %{
        device_id: actor["device_id"],
        user_id: actor["user_id"],
        signing_key_id: actor["signing_key_id"]
      },
      approval_subject: approval
    }
  end

  defp plugin_semantic_context(%{"actor" => actor, "consent" => consent}) do
    %{
      actor: %{
        device_id: actor["device_id"],
        user_id: actor["user_id"],
        signing_key_id: actor["signing_key_id"]
      },
      consent_subject: consent
    }
  end

  defp plugin_semantic_context(%{"subject" => subject}) do
    %{proxy_request_subject: subject}
  end

  defp refresh_plugin_consent_subject_hash(%{"consent" => consent} = transcript) do
    Map.put(transcript, "subject_hash", Hash.blake3_base64url(JCS.canonical_bytes!(consent)))
  end

  defp delete_nested_key(map, [key]), do: Map.delete(map, key)

  defp delete_nested_key(map, [key | rest]) do
    Map.update!(map, key, &delete_nested_key(&1, rest))
  end

  defp put_nested_key(map, [key], value), do: Map.put(map, key, value)

  defp put_nested_key(map, [key | rest], value) do
    Map.update!(map, key, &put_nested_key(&1, rest, value))
  end

  defp production_builder_args(%{signing_purpose: "pq_wrap"}, public) do
    payload = pq_wrap_payload_fixture()

    [
      public["owner_id"],
      payload["actor"],
      payload["authority_boundary"],
      payload["subject_hashes"]
    ]
  end

  defp production_builder_args(
         %{signing_purpose: "key_directory_checkpoint", variant: variant},
         public
       ) do
    [
      variant,
      public["owner_kind"],
      public["owner_id"],
      checkpoint_payload_fixture(public["owner_id"])
    ]
  end

  defp production_builder_args(
         %{signing_purpose: "key_directory_event", variant: variant},
         public
       ) do
    [
      variant,
      public["owner_kind"],
      public["owner_id"],
      key_directory_event_payload_fixture(variant, public)
    ]
  end

  defp production_builder_args(%{signing_purpose: "workspace_pin_bootstrap"}, public) do
    [
      public["owner_id"],
      "00000000-0000-4000-8000-000000000401",
      workspace_pin_bootstrap_fixture(public)
    ]
  end

  defp production_builder_args(%{signing_purpose: "recipient_bound_authorization"}, public) do
    signing_key_id = Hash.blake3_base64url("signing-key")

    [
      public["owner_id"],
      "00000000-0000-4000-8000-000000000402",
      "00000000-0000-4000-8000-000000000403",
      signing_key_id,
      recipient_bound_authorization_payload(signing_key_id)
    ]
  end

  defp production_builder_args(%{signing_purpose: "share_capability_authorization"}, _public) do
    [share_capability_authorization_params()]
  end

  defp production_builder_args(
         %{signing_purpose: "share_participant_device_authorization"},
         public
       ) do
    [
      %{
        share_id: "00000000-0000-4000-8000-000000000430",
        share_session_id: "00000000-0000-4000-8000-000000000431",
        share_participant_principal_id: "00000000-0000-4000-8000-000000000432",
        share_participant_device_id: public["owner_id"],
        participant_signing_key_id: Signature.compute_signing_key_id!(public),
        participant_encryption_key_id: Hash.blake3_base64url("participant-encryption"),
        capability_context_hash: Hash.blake3_base64url("capability-context"),
        share_created_event_hash: Hash.blake3_base64url("share-created"),
        latest_bootstrap_event_hash: Hash.blake3_base64url("latest-bootstrap"),
        scope_kind: "document",
        scope_id: "00000000-0000-4000-8000-000000000433",
        permission: "edit"
      }
    ]
  end

  defp production_builder_args(%{signing_purpose: "pop_request", variant: variant}, public) do
    [
      variant,
      public["owner_kind"],
      public["owner_id"],
      pop_actor_fixture(variant, public),
      "challenge",
      pop_session_fixture(variant),
      pop_resource_fixture(variant)
    ]
  end

  defp production_builder_args(%{signing_purpose: "genesis_device_bootstrap"}, public) do
    device_private =
      RefMD.TestCrypto.hybrid_signing_private_key_material(
        "device",
        "00000000-0000-4000-8000-000000000411"
      )

    device_public = RefMD.TestCrypto.hybrid_signing_public_key_material(device_private)

    encryption =
      RefMD.TestCrypto.hybrid_encryption_public_key_material(
        "device",
        device_public["owner_id"],
        deterministic_bytes("genesis-device-encryption", 32)
      )

    [
      %{
        user_id: public["owner_id"],
        device_id: device_public["owner_id"],
        device_public_material: device_public,
        device_hybrid_encryption_public_key_material: encryption.public,
        client_nonce:
          Base.url_encode64(deterministic_bytes("genesis-client-nonce", 16), padding: false),
        registration_challenge_hash: Hash.blake3_base64url("challenge"),
        identity_signing_key_id: Signature.compute_signing_key_id!(public),
        user_identity_public_key_hash: Hash.blake3_base64url("identity")
      }
    ]
  end

  defp production_builder_args(%{signing_purpose: "device_approval"}, public) do
    approved_public = fixed_public_material("device", "00000000-0000-4000-8000-000000000412")

    encryption_public =
      fixed_encryption_public_material("device", approved_public["owner_id"], "device-approval")

    commitments = device_approval_commitments(public, approved_public, encryption_public)

    [
      "00000000-0000-4000-8000-000000000413",
      public["owner_id"],
      approved_public["owner_id"],
      approved_public,
      encryption_public,
      Base.url_encode64(deterministic_bytes("device-approval-client-nonce", 16), padding: false),
      commitments
    ]
  end

  defp production_builder_args(%{signing_purpose: "plugin_bundle_approval"}, public) do
    actor = plugin_actor(public)

    [
      %{
        actor: actor,
        approval: plugin_bundle_approval_subject(actor)
      }
    ]
  end

  defp production_builder_args(%{signing_purpose: "plugin_consent_event"}, public) do
    actor = plugin_actor(public)

    [
      %{
        actor: actor,
        consent: plugin_consent_subject(actor)
      }
    ]
  end

  defp production_builder_args(%{signing_purpose: "plugin_network_proxy_request"}, public) do
    [
      %{
        subject: plugin_network_proxy_request_subject(public)
      }
    ]
  end

  defp production_builder_args(%{signing_purpose: "responder_prekey"}, public) do
    [
      public["owner_id"],
      %{"protocol" => "refmd.responder-prekey", "prekey_id" => "prekey"},
      %{
        "device_id" => public["owner_id"],
        "signing_key_id" => Signature.compute_signing_key_id!(public)
      },
      %{"challenge_hash" => Hash.blake3_base64url("challenge")}
    ]
  end

  defp production_builder_args(%{signing_purpose: "initiator_ake_commitment"}, public) do
    commitment = %{"protocol" => "refmd.initiator-ake-commitment", "operation_id" => "operation"}

    [
      public["owner_id"],
      commitment,
      %{
        "device_id" => public["owner_id"],
        "signing_key_id" => Signature.compute_signing_key_id!(public)
      },
      %{"x25519_ephemeral_public" => Hash.blake3_base64url("x25519")},
      %{
        "operation_id" => "operation",
        "context_hash" => Hash.blake3_base64url("context"),
        "directory_hash" => Hash.blake3_base64url("directory"),
        "recipient_hash" => Hash.blake3_base64url("recipient"),
        "server_challenge" => "challenge"
      }
    ]
  end

  defp production_builder_args(
         %{signing_purpose: "initial_key_delivery", variant: variant},
         public
       ) do
    [
      public["owner_id"],
      variant,
      %{"protocol" => "refmd.initial-key-delivery", "variant" => variant},
      %{
        "user_id" => "00000000-0000-4000-8000-000000000414",
        "device_id" => public["owner_id"],
        "signing_key_id" => Signature.compute_signing_key_id!(public)
      },
      %{
        "user_id" => "00000000-0000-4000-8000-000000000415",
        "device_id" => "00000000-0000-4000-8000-000000000416",
        "encryption_key_id" => Hash.blake3_base64url("recipient-encryption-key")
      },
      %{
        "ake_transcript_hash" => Hash.blake3_base64url("ake"),
        "initiator_commitment_hash" => Hash.blake3_base64url("commitment"),
        "purpose" => variant,
        "operation_id" => "operation"
      },
      %{
        "delivery_id" => "delivery",
        "context_hash" => Hash.blake3_base64url("context"),
        "payload_kind" => "payload",
        "ciphertext_hash" => Hash.blake3_base64url("ciphertext")
      },
      %{"sender_authority_kind" => "device"}
    ]
  end

  defp production_builder_args(%{signing_purpose: "pin_gossip_statement"}, public) do
    [public["owner_id"], %{"statement" => "security-vector"}]
  end

  defp production_builder_args(%{signing_purpose: "device_revocation"}, public) do
    [
      "00000000-0000-4000-8000-000000000417",
      public["owner_id"],
      Signature.compute_signing_key_id!(public),
      "00000000-0000-4000-8000-000000000418",
      "self_revocation",
      1_775_000_000_000
    ]
  end

  defp production_builder_args(
         %{signing_purpose: "device_key_deletion_proof", variant: variant},
         public
       ) do
    [
      device_key_deletion_payload_fixture(public["owner_id"], variant),
      %{
        "device_id" => public["owner_id"],
        "signing_key_id" => Signature.compute_signing_key_id!(public),
        "user_id" => "00000000-0000-4000-8000-000000000417"
      }
    ]
  end

  defp production_builder_args(%{signing_purpose: "recovery_device_approval"}, public) do
    approved_private =
      RefMD.TestCrypto.hybrid_signing_private_key_material(
        "device",
        "00000000-0000-4000-8000-000000000418"
      )

    approved_public = RefMD.TestCrypto.hybrid_signing_public_key_material(approved_private)

    encryption =
      RefMD.TestCrypto.hybrid_encryption_public_key_material(
        "device",
        approved_public["owner_id"],
        deterministic_bytes("recovery-device-approval-encryption", 32)
      )

    [
      %{
        user_id: public["owner_id"],
        approving_signing_key_id: Signature.compute_signing_key_id!(public),
        approving_key_checkpoint_sequence: 1,
        approving_key_checkpoint_hash: Hash.blake3_base64url("checkpoint"),
        pending_registration_id: approved_public["owner_id"],
        pending_registration_challenge_hash: Hash.blake3_base64url("challenge"),
        recovery_session_transcript_hash: Hash.blake3_base64url("session"),
        recovery_capability_hash: Hash.blake3_base64url("capability"),
        pending_registration_binding_hash: Hash.blake3_base64url("binding"),
        approved_device_id: approved_public["owner_id"],
        approved_device_public_material: approved_public,
        approved_device_hybrid_encryption_public_key_material: encryption.public,
        client_nonce:
          Base.url_encode64(deterministic_bytes("recovery-device-approval-client-nonce", 16),
            padding: false
          ),
        target_key_checkpoint_sequence: 1,
        target_key_checkpoint_hash: Hash.blake3_base64url("target")
      }
    ]
  end

  defp production_builder_args(%{signing_purpose: "recovery_session"}, public) do
    [
      %{
        user_id: public["owner_id"],
        recipient_device_id: "00000000-0000-4000-8000-000000000419",
        pending_registration_id: "00000000-0000-4000-8000-000000000420",
        recovery_session_id: "00000000-0000-4000-8000-000000000421",
        server_challenge_hash: Hash.blake3_base64url("challenge"),
        recovered_identity_signing_key_id: Signature.compute_signing_key_id!(public),
        recovery_authorization_key_id: Hash.blake3_base64url("authorization"),
        candidate_user_checkpoint_sequence: 1,
        candidate_user_checkpoint_hash: Hash.blake3_base64url("checkpoint"),
        candidate_user_event_head_sequence: 1,
        candidate_user_event_head_hash: Hash.blake3_base64url("event"),
        recovery_capability_hash: Hash.blake3_base64url("capability"),
        pending_registration_binding_hash: Hash.blake3_base64url("binding")
      }
    ]
  end

  defp production_builder_args(%{signing_purpose: "recovery_authorization_proof"}, public) do
    [
      %{
        user_id: public["owner_id"],
        recovery_authorization_key_id: Signature.compute_signing_key_id!(public),
        recipient_device_id: "00000000-0000-4000-8000-000000000419",
        pending_registration_binding_hash: Hash.blake3_base64url("binding"),
        server_challenge_hash: Hash.blake3_base64url("challenge")
      }
    ]
  end

  defp production_builder_args(%{signing_purpose: purpose}, public)
       when purpose in ["document_update", "document_snapshot"] do
    [document_operation_params_fixture(purpose, public)]
  end

  defp production_builder_args(%{signing_purpose: "editor_ephemeral"}, public) do
    [
      %{
        owner_kind: public["owner_kind"],
        owner_id: public["owner_id"],
        actor_user_id: "00000000-0000-4000-8000-000000000422",
        actor_device_id: public["owner_id"],
        signing_key_id: Signature.compute_signing_key_id!(public),
        workspace_id: "00000000-0000-4000-8000-000000000401",
        public_data: %{
          "authorityId" => "00000000-0000-4000-8000-000000000401",
          "docId" => "00000000-0000-4000-8000-000000000423",
          "keyCheckpointHash" => Hash.blake3_base64url("checkpoint"),
          "keyCheckpointSequence" => 1
        },
        authority_boundary: %{
          "workspace_event_head_sequence" => 1,
          "workspace_event_head_hash" => Hash.blake3_base64url("checkpoint"),
          "actor_active_proof_hash" => Hash.blake3_base64url("actor-active-proof"),
          "document_permission_proof_hash" => Hash.blake3_base64url("document-permission-proof"),
          "expires_event_sequence" => 2
        },
        ciphertext:
          Base.url_encode64(deterministic_bytes("editor-ephemeral-ciphertext", 32),
            padding: false
          ),
        nonce:
          Base.url_encode64(deterministic_bytes("editor-ephemeral-nonce", 24), padding: false)
      }
    ]
  end

  defp production_builder_args(%{signing_purpose: "editor_ephemeral_session"}, public) do
    [
      %{
        owner_kind: public["owner_kind"],
        owner_id: public["owner_id"],
        workspace_id: "00000000-0000-4000-8000-000000000401",
        document_id: "00000000-0000-4000-8000-000000000423",
        channel_id: "00000000-0000-4000-8000-000000000423",
        actor_user_id: "00000000-0000-4000-8000-000000000424",
        actor_device_id: public["owner_id"],
        signing_key_id: Signature.compute_signing_key_id!(public),
        session_id: "00000000-0000-4000-8000-000000000425",
        proof_direction: "join",
        proof_type: "session_admission",
        session_nonce: Hash.blake3_base64url("session-nonce"),
        counter: 1,
        expires_event_sequence: 2,
        key_checkpoint_sequence: 1,
        key_checkpoint_hash: Hash.blake3_base64url("checkpoint"),
        authority_boundary: %{
          "workspace_event_head_sequence" => 1,
          "workspace_event_head_hash" => Hash.blake3_base64url("head"),
          "actor_active_proof_hash" => Hash.blake3_base64url("actor"),
          "document_permission_proof_hash" => Hash.blake3_base64url("permission")
        }
      }
    ]
  end

  defp recipient_bound_authorization_payload(signing_key_id) do
    %{
      "protocol" => "refmd.recipient-bound-authorization",
      "version" => 1,
      "authorization_id" => "00000000-0000-4000-8000-000000000404",
      "redeem_attempt_id" => "00000000-0000-4000-8000-000000000405",
      "workspace_id" => "00000000-0000-4000-8000-000000000406",
      "context_kind" => "guest_invitation",
      "context_id" => "00000000-0000-4000-8000-000000000407",
      "resource_hash" => Hash.blake3_base64url("resource"),
      "recipient" => %{
        "recipient_kind" => "guest",
        "recipient_principal_id" => "00000000-0000-4000-8000-000000000408",
        "recipient_device_id" => "00000000-0000-4000-8000-000000000409",
        "encryption_key_id" => Hash.blake3_base64url("encryption-key")
      },
      "workspace_pin_bootstrap_hash" => Hash.blake3_base64url("workspace-pin-bootstrap"),
      "current_checkpoint_sequence" => 45,
      "current_checkpoint_hash" => Hash.blake3_base64url("checkpoint"),
      "current_event_head_sequence" => 44,
      "current_event_head_hash" => Hash.blake3_base64url("event-head"),
      "redeem_authority_signing_key_id" => signing_key_id,
      "recipient_redeem_nonce" => Base.url_encode64(:binary.copy(<<1>>, 32), padding: false),
      "recipient_nonce_state_hash" => Hash.blake3_base64url("nonce-state"),
      "live_redeem_challenge_hash" => Hash.blake3_base64url("live-challenge"),
      "redeem_freshness_proof_hash" => Hash.blake3_base64url("freshness-proof"),
      "not_after_event_sequence" => 45
    }
  end

  defp pop_actor_fixture(variant, public)
       when variant in ["http_share_participant_device", "channel_share_participant_device"] do
    %{
      "signer_kind" => "share_participant_device",
      "share_id" => "00000000-0000-4000-8000-000000000420",
      "share_participant_principal_id" => "00000000-0000-4000-8000-000000000410",
      "share_participant_device_id" => public["owner_id"],
      "signing_key_id" => Signature.compute_signing_key_id!(public),
      "key_scope_kind" => "workspace",
      "key_scope_id" => "00000000-0000-4000-8000-000000000421",
      "key_checkpoint_sequence" => 1,
      "key_checkpoint_hash" => Hash.blake3_base64url("pop-workspace-checkpoint")
    }
  end

  defp pop_actor_fixture(_variant, public) do
    %{
      "signer_kind" => "device",
      "user_id" => "00000000-0000-4000-8000-000000000410",
      "device_id" => public["owner_id"],
      "signing_key_id" => Signature.compute_signing_key_id!(public),
      "key_scope_kind" => "user",
      "key_scope_id" => "00000000-0000-4000-8000-000000000410",
      "key_checkpoint_sequence" => 1,
      "key_checkpoint_hash" => Hash.blake3_base64url("pop-user-checkpoint")
    }
  end

  defp pop_session_fixture(variant)
       when variant in ["http_share_participant_device", "channel_share_participant_device"] do
    %{
      "session_id_hash" => Hash.blake3_base64url("session"),
      "session_kind" => "share_participant",
      "share_id" => "00000000-0000-4000-8000-000000000420",
      "is_recovery" => false
    }
  end

  defp pop_session_fixture(_variant) do
    %{
      "session_id_hash" => Hash.blake3_base64url("session"),
      "session_kind" => "user",
      "is_recovery" => false
    }
  end

  defp pq_wrap_payload_fixture do
    %{
      "actor" => %{
        "device_id" => "00000000-0000-4000-8000-000000000202",
        "key_scope_id" => "00000000-0000-4000-8000-000000000401",
        "key_scope_kind" => "workspace",
        "key_checkpoint_hash" => Hash.blake3_base64url("checkpoint"),
        "key_checkpoint_sequence" => 1,
        "signer_kind" => "device",
        "signing_key_id" => Hash.blake3_base64url("signing-key"),
        "user_id" => "00000000-0000-4000-8000-000000000417"
      },
      "authority_boundary" => %{
        "covered_event_head_hash" => Hash.blake3_base64url("head"),
        "covered_event_head_sequence" => 1,
        "event_hash" => Hash.blake3_base64url("event"),
        "operation_checkpoint_hash" => Hash.blake3_base64url("checkpoint"),
        "operation_checkpoint_sequence" => 1,
        "scope_id" => "00000000-0000-4000-8000-000000000401",
        "scope_kind" => "workspace"
      },
      "subject_hashes" => %{
        "aad_hash" => Hash.blake3_base64url("aad"),
        "hpke_info_hash" => Hash.blake3_base64url("hpke-info"),
        "resource_hash" => Hash.blake3_base64url("resource"),
        "wrap_body_hash" => Hash.blake3_base64url("wrap-body"),
        "wrap_event_body_hash" => Hash.blake3_base64url("wrap-event-body"),
        "wrap_event_hash" => Hash.blake3_base64url("wrap-event")
      }
    }
  end

  defp checkpoint_payload_fixture(owner_id) do
    %{
      "allowed_suite_ids" => ["refmd-v2-hybrid-signature-ed25519-mldsa65"],
      "covered_event_head" => %{
        "head_hash" => Hash.blake3_base64url("head"),
        "head_sequence" => 1
      },
      "min_suite_rank" => 1000,
      "authority_boundary" => %{"required_authority" => "tofu_root"},
      "previous_checkpoint_hash" => Hash.blake3_base64url("previous-checkpoint"),
      "scope_id" => owner_id,
      "scope_kind" => "workspace",
      "sequence" => 1,
      "signer" => %{
        "signer_kind" => "device",
        "user_id" => "00000000-0000-4000-8000-000000000417",
        "device_id" => owner_id,
        "signing_key_id" => Hash.blake3_base64url("signing-key")
      },
      "suite_policy_version" => 1
    }
  end

  defp key_directory_event_payload_fixture(variant, public) do
    owner_id = public["owner_id"]

    %{
      "actor" => key_directory_actor_fixture(public),
      "body" => %{"event_type" => variant, "resource_id" => "refmd.security-vector"},
      "event_type" => variant,
      "authority_boundary" => %{
        "scope_kind" => "workspace",
        "scope_id" => owner_id,
        "checkpoint_sequence" => 1,
        "checkpoint_hash" => Hash.blake3_base64url("checkpoint"),
        "required_authority" => "event_type_authorized_actor"
      },
      "previous_event_hash" => Hash.blake3_base64url("previous-event"),
      "scope_id" => owner_id,
      "scope_kind" => "workspace",
      "sequence" => 1
    }
  end

  defp key_directory_actor_fixture(%{
         "owner_kind" => "share_participant_device",
         "owner_id" => owner_id
       }) do
    %{
      "signer_kind" => "share_participant_device",
      "share_id" => "00000000-0000-4000-8000-000000000408",
      "share_participant_principal_id" => "00000000-0000-4000-8000-000000000407",
      "share_participant_device_id" => owner_id,
      "signing_key_id" => Hash.blake3_base64url("signing-key")
    }
  end

  defp key_directory_actor_fixture(%{"owner_kind" => "identity", "owner_id" => owner_id}) do
    %{
      "signer_kind" => "identity",
      "user_id" => owner_id,
      "signing_key_id" => Hash.blake3_base64url("signing-key")
    }
  end

  defp key_directory_actor_fixture(%{"owner_id" => owner_id}) do
    %{
      "signer_kind" => "device",
      "user_id" => "00000000-0000-4000-8000-000000000417",
      "device_id" => owner_id,
      "signing_key_id" => Hash.blake3_base64url("signing-key")
    }
  end

  defp workspace_pin_bootstrap_fixture(public) do
    workspace_id = "00000000-0000-4000-8000-000000000401"
    checkpoint_hash = Hash.blake3_base64url("checkpoint")
    event_head_hash = Hash.blake3_base64url("head")

    %{
      "protocol" => "refmd.workspace-pin-bootstrap",
      "version" => 1,
      "workspace_id" => workspace_id,
      "checkpoint_sequence" => 45,
      "checkpoint_hash" => checkpoint_hash,
      "event_head_sequence" => 44,
      "event_head_hash" => event_head_hash,
      "suite_policy_version" => 1,
      "min_suite_rank" => 1000,
      "allowed_suite_ids_hash" => Hash.blake3_base64url("allowed-suite-ids"),
      "issuer" => %{
        "signer_kind" => "device",
        "user_id" => "00000000-0000-4000-8000-000000000417",
        "device_id" => public["owner_id"],
        "signing_key_id" => Signature.compute_signing_key_id!(public),
        "key_scope_kind" => "workspace",
        "key_scope_id" => workspace_id,
        "key_checkpoint_sequence" => 44,
        "key_checkpoint_hash" => checkpoint_hash
      },
      "issuing_event_hash" => event_head_hash,
      "expires_event_sequence" => 9_007_199_254_740_991,
      "bootstrap_nonce" => Hash.blake3_base64url("workspace-pin-bootstrap-nonce")
    }
  end

  defp pop_resource_fixture("http_" <> _variant) do
    %{
      "body_hash" => Hash.blake3_base64url(""),
      "canonical_query" => "",
      "method" => "GET",
      "path" => "/api/security-vector",
      "query_hash" => Hash.blake3_base64url("")
    }
  end

  defp pop_resource_fixture("channel_share_participant_device") do
    %{
      "channel_event" => "phx_join",
      "document_id" => "00000000-0000-4000-8000-000000000423",
      "event_name" => "phx_join",
      "join_push_kind" => "document_join",
      "payload_hash" => Hash.blake3_base64url("payload"),
      "scope_kind" => "share",
      "share_id" => "00000000-0000-4000-8000-000000000408",
      "topic" => "document:00000000-0000-4000-8000-000000000423"
    }
  end

  defp pop_resource_fixture("channel_" <> _variant) do
    %{
      "channel_event" => "phx_join",
      "document_id" => "00000000-0000-4000-8000-000000000423",
      "event_name" => "phx_join",
      "join_push_kind" => "document_join",
      "payload_hash" => Hash.blake3_base64url("payload"),
      "scope_kind" => "user",
      "share_id" => "none",
      "topic" => "document:00000000-0000-4000-8000-000000000423"
    }
  end

  defp share_capability_authorization_params do
    %{
      token_hash: Hash.blake3_base64url("share-token"),
      workspace_pin_bootstrap_hash: Hash.blake3_base64url("workspace-pin-bootstrap"),
      share_id: "00000000-0000-4000-8000-000000000408",
      scope_kind: "document",
      scope_id: "00000000-0000-4000-8000-000000000409",
      permission: "view",
      password_protected: false,
      created_event_hash: Hash.blake3_base64url("created"),
      latest_bootstrap_event_hash: Hash.blake3_base64url("latest"),
      capability_context_hash: Hash.blake3_base64url("context"),
      share_capability_secret_commitment: Hash.blake3_base64url("capability"),
      password_capability_secret_commitment: "none"
    }
  end

  defp device_approval_commitments(approver_public, approved_public, encryption_public) do
    target_client_nonce =
      Base.url_encode64(deterministic_bytes("device-approval-target-client-nonce", 16),
        padding: false
      )

    %{
      "approved_device_registration_sas_hash" => Hash.blake3_base64url("sas"),
      "approving_device_key_directory_proof_hash" => Hash.blake3_base64url("proof"),
      "approving_key_checkpoint_hash" => Hash.blake3_base64url("approver-checkpoint"),
      "approving_key_checkpoint_sequence" => 1,
      "approving_owner_id" => approver_public["owner_id"],
      "approving_owner_kind" => "device",
      "approving_signing_key_id" => Signature.compute_signing_key_id!(approver_public),
      "device_approval_kek_initial_delivery_commitments" => [
        delivery_commitment_fixture("device_approval_kek_initial", %{
          "workspace_id" => "00000000-0000-4000-8000-000000000401",
          "key_version" => 1
        })
      ],
      "pending_registration_challenge_hash" => Hash.blake3_base64url("challenge"),
      "pending_registration_id" => approved_public["owner_id"],
      "target_device_client_nonce_hash" =>
        target_client_nonce |> Encoding.decode_base64url!() |> Hash.blake3_base64url(),
      "target_device_encryption_key_id" =>
        HybridEncryptionMaterial.compute_key_id!(encryption_public),
      "target_device_hybrid_encryption_public_key_material_hash" =>
        Hash.blake3_base64url(JCS.canonical_bytes!(encryption_public)),
      "target_device_hybrid_signing_public_key_material_hash" =>
        Hash.blake3_base64url(JCS.canonical_bytes!(approved_public)),
      "target_device_id" => approved_public["owner_id"],
      "target_device_signing_key_id" => Signature.compute_signing_key_id!(approved_public),
      "target_key_checkpoint_hash" => Hash.blake3_base64url("target-checkpoint"),
      "target_key_checkpoint_sequence" => 1,
      "trust_transfer_delivery_commitment" =>
        delivery_commitment_fixture("trust_transfer", %{
          "ake_session_id" => "trust-transfer",
          "document_rollback_pin_set_hash" => Hash.blake3_base64url("rollback")
        }),
      "umk_distribution_delivery_commitment" =>
        delivery_commitment_fixture("umk_distribution", %{})
    }
  end

  defp delivery_commitment_fixture(purpose, extra) do
    Map.merge(
      %{
        "purpose" => purpose,
        "variant" => purpose,
        "delivery_id" => "#{purpose}-delivery",
        "recipient_device_id" => "00000000-0000-4000-8000-000000000412",
        "sender_device_id" => "00000000-0000-4000-8000-000000000202",
        "delivery_record_hash" => Hash.blake3_base64url("#{purpose}-record"),
        "key_checkpoint_hash" => Hash.blake3_base64url("#{purpose}-checkpoint")
      },
      extra
    )
  end

  defp device_key_deletion_payload_fixture(device_id, variant) do
    %{
      "deleted_secret_ids" => ["dek:1"],
      "deleted_secret_ids_hash" => Hash.blake3_base64url("deleted-secret-ids"),
      "deleted_storage_classes" => ["local"],
      "deletion_proof_kind" => variant,
      "device_id" => device_id,
      "old_key_version" => 1,
      "rotation_completed_event_hash" => Hash.blake3_base64url("rotation-completed"),
      "rotation_kind" => "workspace_key_rotation",
      "scope_id" => "00000000-0000-4000-8000-000000000401",
      "scope_kind" => "workspace",
      "workspace_id" => "00000000-0000-4000-8000-000000000401"
    }
  end

  defp document_operation_params_fixture(purpose, public) do
    signing_key_id = Signature.compute_signing_key_id!(public)

    update_public_data = %{
      "clock" => 0,
      "minDekVersion" => 1,
      "refSnapshotId" => "00000000-0000-4000-8000-000000000424",
      "timestamp" => 1,
      "updateHash" => Hash.blake3_base64url("update"),
      "writeSessionCounter" => 1,
      "writeSessionEventHash" => Hash.blake3_base64url("write-session"),
      "writeSessionId" => Hash.blake3_base64url("write-session-id")
    }

    snapshot_authority_boundary = %{
      "admission_event_type" => purpose <> "_accepted",
      "admission_nonce" => Hash.blake3_base64url("nonce"),
      "document_permission_proof_hash" => Hash.blake3_base64url("permission"),
      "min_dek_version" => 1,
      "previous_workspace_event_hash" => Hash.blake3_base64url("head"),
      "previous_workspace_event_sequence" => 1
    }

    update_authority_boundary = %{
      "document_permission_proof_hash" => Hash.blake3_base64url("permission"),
      "min_dek_version" => 1,
      "write_session_counter" => 1,
      "write_session_event_hash" => Hash.blake3_base64url("write-session"),
      "write_session_id" => Hash.blake3_base64url("write-session-id")
    }

    %{
      owner_kind: public["owner_kind"],
      owner_id: public["owner_id"],
      workspace_id: "00000000-0000-4000-8000-000000000401",
      actor_user_id: "00000000-0000-4000-8000-000000000417",
      actor_device_id: public["owner_id"],
      signing_key_id: signing_key_id,
      public_data:
        maybe_put_document_operation_data(
          %{
            "authorityId" => "00000000-0000-4000-8000-000000000401",
            "authorityKind" =>
              if(public["owner_kind"] == "share_participant_device",
                do: "share_participant_device",
                else: "workspace_device"
              ),
            "authorityContextKey" => signing_key_id,
            "authorityPermissionVersion" => 1,
            "authorityScopeId" => "00000000-0000-4000-8000-000000000402",
            "docId" => "00000000-0000-4000-8000-000000000423",
            "keyCheckpointHash" => Hash.blake3_base64url("checkpoint"),
            "keyCheckpointSequence" => 1,
            "keyVersion" => 1,
            "ownerId" => public["owner_id"],
            "ownerKind" => public["owner_kind"],
            "signingKeyId" => signing_key_id
          },
          purpose,
          update_public_data
        ),
      authority_boundary:
        if(purpose == "document_update",
          do: update_authority_boundary,
          else: snapshot_authority_boundary
        ),
      ciphertext:
        Base.url_encode64(deterministic_bytes("document-operation-ciphertext", 48),
          padding: false
        ),
      nonce:
        Base.url_encode64(deterministic_bytes("document-operation-nonce", 24), padding: false)
    }
  end

  defp deterministic_bytes(label, size)
       when is_binary(label) and is_integer(size) and size >= 0 do
    deterministic_bytes(label, 0, <<>>, size)
  end

  defp deterministic_bytes(_label, _counter, bytes, size) when byte_size(bytes) >= size do
    binary_part(bytes, 0, size)
  end

  defp deterministic_bytes(label, counter, bytes, size) do
    deterministic_bytes(
      label,
      counter + 1,
      bytes <> :crypto.hash(:sha256, [label, <<counter::32>>]),
      size
    )
  end

  defp maybe_put_document_operation_data(public_data, "document_snapshot", _update_public_data) do
    Map.merge(public_data, %{
      "parentProofHash" => "GENESIS",
      "parentSnapshotId" => "GENESIS",
      "parentSnapshotUpdateClocks" => %{},
      "snapshotId" => "00000000-0000-4000-8000-000000000425"
    })
  end

  defp maybe_put_document_operation_data(public_data, _, update_public_data) do
    Map.merge(public_data, update_public_data)
  end

  defp plugin_actor(public) do
    %{
      "signer_kind" => "device",
      "user_id" => "00000000-0000-4000-8000-000000000426",
      "device_id" => public["owner_id"],
      "signing_key_id" => Signature.compute_signing_key_id!(public),
      "key_scope_kind" => "workspace",
      "key_scope_id" => "00000000-0000-4000-8000-000000000427",
      "key_checkpoint_sequence" => 1,
      "key_checkpoint_hash" => Hash.blake3_base64url("plugin-checkpoint")
    }
  end

  defp plugin_bundle_approval_subject(actor) do
    %{
      "plugin_id" => "com.example.notes",
      "package_id" => "00000000-0000-4000-8000-000000000429",
      "application_scope_kind" => "workspace",
      "workspace_id" => actor["key_scope_id"],
      "owner_scope_kind" => "workspace",
      "owner_workspace_id" => actor["key_scope_id"],
      "version" => "1.0.0",
      "source_kind" => "local_upload",
      "source_url_hash" => "NO_SOURCE_URL",
      "archive_hash" => Hash.blake3_base64url("plugin-archive"),
      "bundle_hash" => Hash.blake3_base64url("plugin-bundle"),
      "manifest_hash" => Hash.blake3_base64url("plugin-manifest"),
      "main_js_hash" => Hash.blake3_base64url("plugin-main"),
      "styles_css_hash" => Hash.blake3_base64url("plugin-styles"),
      "resource_manifest_hash" => Hash.blake3_base64url("plugin-resources"),
      "permissions_hash" => Hash.blake3_base64url("plugin-permissions"),
      "endpoint_hash" => Hash.blake3_base64url("plugin-endpoints"),
      "renderer_slots_hash" => Hash.blake3_base64url("plugin-renderer-slots"),
      "document_scope_hash" => Hash.blake3_base64url("plugin-document-scopes"),
      "approver_user_id" => actor["user_id"],
      "approver_device_id" => actor["device_id"],
      "approval_epoch" => 1,
      "previous_approval_event_hash" => "GENESIS",
      "created_at_ms" => 1_775_000_000_000
    }
  end

  defp plugin_consent_subject(actor) do
    %{
      "plugin_id" => "com.example.notes",
      "package_id" => "00000000-0000-4000-8000-000000000429",
      "application_id" => "00000000-0000-4000-8000-000000000428",
      "activation_id" => "00000000-0000-4000-8000-000000000430",
      "owner_scope_kind" => "workspace",
      "application_scope_kind" => "workspace",
      "version" => "1.0.0",
      "bundle_hash" => Hash.blake3_base64url("plugin-bundle"),
      "manifest_hash" => Hash.blake3_base64url("plugin-manifest"),
      "resource_manifest_hash" => Hash.blake3_base64url("plugin-resources"),
      "permissions_hash" => Hash.blake3_base64url("plugin-permissions"),
      "endpoint_hash" => Hash.blake3_base64url("plugin-endpoints"),
      "document_scope_hash" => Hash.blake3_base64url("plugin-document-scopes"),
      "signer_device_id" => actor["device_id"],
      "signer_user_id" => actor["user_id"],
      "user_id" => actor["user_id"],
      "device_id" => actor["device_id"],
      "workspace_id" => actor["key_scope_id"],
      "consent_epoch" => 1,
      "previous_event_hash" => "GENESIS",
      "decision" => "allow"
    }
  end

  defp plugin_network_proxy_request_subject(public) do
    %{
      "protocol" => "refmd.plugin-network-proxy-request-subject",
      "version" => 1,
      "request_id" => "request-0001",
      "proxy" => %{
        "id" => "workspace-proxy",
        "scope" => "workspace",
        "origin" => "https://proxy.example/refmd"
      },
      "target" => %{
        "url" => "https://api.example.test/v1/search",
        "method" => "POST",
        "headers" => %{"accept" => "application/json", "content-type" => "application/json"},
        "body_text" => ~s({"query":"notes"})
      },
      "endpoint" => %{
        "id" => "search",
        "max_request_bytes" => 4096,
        "max_response_bytes" => 65_536,
        "credential_audience" => "https://api.example.test"
      },
      "runtime" => %{
        "workspace_id" => "00000000-0000-4000-8000-000000000427",
        "plugin_id" => "com.example.notes",
        "package_id" => "00000000-0000-4000-8000-000000000429",
        "application_id" => "00000000-0000-4000-8000-000000000428",
        "activation_id" => "00000000-0000-4000-8000-000000000430",
        "frame_generation" => 2,
        "user_id" => "00000000-0000-4000-8000-000000000426",
        "device_id" => public["owner_id"],
        "owner_scope_kind" => "workspace",
        "consent_epoch" => 1,
        "capability_grant_id" => "grant-0001",
        "request_id" => "request-0001",
        "credential_handle_used" => true
      }
    }
  end

  defp expected_active_surface_pairs do
    key_directory_events = [
      "wrap_issued",
      "identity_key_added",
      "device_key_added",
      "member_added",
      "member_role_changed",
      "member_removed",
      "signing_key_revoked",
      "encryption_key_revoked",
      "suite_policy_changed",
      "share_created",
      "share_metadata_updated",
      "share_key_scope_added",
      "share_key_scope_replaced",
      "share_key_scope_removed",
      "share_exclusion_changed",
      "share_revoked",
      "recipient_bound_delivery_admitted",
      "workspace_invitation_created",
      "workspace_invitation_bootstrap_updated",
      "workspace_invitation_revoked",
      "workspace_invitation_redeemed",
      "guest_invitation_created",
      "guest_invitation_bootstrap_updated",
      "guest_invitation_revoked",
      "guest_invitation_redeemed",
      "guest_grant_revoked",
      "guest_device_revoked",
      "rotation_started",
      "rotation_completed",
      "old_key_deleted",
      "document_update_accepted",
      "document_write_session_admitted",
      "document_write_state_changed",
      "document_snapshot_accepted"
    ]

    [
      {"pq_wrap", "none"},
      {"workspace_pin_bootstrap", "none"},
      {"recipient_bound_authorization", "none"},
      {"share_capability_authorization", "none"},
      {"share_participant_device_authorization", "none"},
      {"genesis_device_bootstrap", "none"},
      {"device_approval", "none"},
      {"plugin_bundle_approval", "none"},
      {"plugin_consent_event", "none"},
      {"plugin_network_proxy_request", "none"},
      {"responder_prekey", "none"},
      {"initiator_ake_commitment", "none"},
      {"recovery_device_approval", "none"},
      {"device_revocation", "none"},
      {"recovery_session", "none"},
      {"recovery_authorization_proof", "none"},
      {"pin_gossip_statement", "none"}
    ] ++
      Enum.map(
        [
          "identity_initial",
          "workspace_initial",
          "identity_active",
          "identity_rotation",
          "workspace_authorized",
          "invitation_redeem_authority",
          "share_participant_document_operation",
          "device_authorized"
        ],
        &{"key_directory_checkpoint", &1}
      ) ++
      Enum.map(key_directory_events, &{"key_directory_event", &1}) ++
      Enum.map(
        [
          "http_user_device",
          "http_share_participant_device",
          "channel_user_device",
          "channel_share_participant_device"
        ],
        &{"pop_request", &1}
      ) ++
      Enum.map(
        ["umk_distribution", "device_approval_kek_initial", "trust_transfer"],
        &{"initial_key_delivery", &1}
      ) ++
      Enum.map(
        ["device_key_deletion_proof", "identity_key_deletion_proof"],
        &{"device_key_deletion_proof", &1}
      ) ++
      Enum.map(["workspace_device", "share_participant_device"], &{"document_update", &1}) ++
      Enum.map(["workspace_device", "share_participant_device"], &{"document_snapshot", &1}) ++
      Enum.map(["workspace_device", "share_participant_device"], &{"editor_ephemeral", &1}) ++
      Enum.map(
        ["workspace_device", "share_participant_device"],
        &{"editor_ephemeral_session", &1}
      )
  end

  defp stateful_semantic_surface_pairs do
    key_directory_checkpoint_variants = [
      "identity_initial",
      "workspace_initial",
      "identity_active",
      "identity_rotation",
      "workspace_authorized",
      "invitation_redeem_authority",
      "share_participant_document_operation",
      "device_authorized"
    ]

    [
      {"genesis_device_bootstrap", "none"},
      {"device_approval", "none"},
      {"plugin_bundle_approval", "none"},
      {"plugin_consent_event", "none"},
      {"plugin_network_proxy_request", "none"},
      {"recovery_device_approval", "none"},
      {"device_revocation", "none"},
      {"recovery_session", "none"},
      {"workspace_pin_bootstrap", "none"},
      {"share_capability_authorization", "none"},
      {"share_participant_device_authorization", "none"}
    ] ++
      Enum.map(
        ["device_key_deletion_proof", "identity_key_deletion_proof"],
        &{"device_key_deletion_proof", &1}
      ) ++
      Enum.map(key_directory_checkpoint_variants, &{"key_directory_checkpoint", &1}) ++
      Enum.map(Signature.key_directory_event_variants(), &{"key_directory_event", &1}) ++
      Enum.map(
        ["umk_distribution", "device_approval_kek_initial", "trust_transfer"],
        &{"initial_key_delivery", &1}
      ) ++
      Enum.map(
        [
          "http_user_device",
          "http_share_participant_device",
          "channel_user_device",
          "channel_share_participant_device"
        ],
        &{"pop_request", &1}
      ) ++
      Enum.map(["workspace_device", "share_participant_device"], &{"document_update", &1}) ++
      Enum.map(["workspace_device", "share_participant_device"], &{"document_snapshot", &1}) ++
      Enum.map(["workspace_device", "share_participant_device"], &{"editor_ephemeral", &1}) ++
      Enum.map(
        ["workspace_device", "share_participant_device"],
        &{"editor_ephemeral_session", &1}
      )
  end

  defp expected_disabled_surface_pairs do
    [
      {"trust_transfer", "none"},
      {"snapshot_proof", "workspace_device"},
      {"snapshot_proof", "share_participant_device"}
    ]
  end
end
