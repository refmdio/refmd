defmodule RefMDWeb.ApiSpecTest do
  use ExUnit.Case, async: true

  alias RefMDWeb.ApiSpec

  @root Path.expand("../..", __DIR__)

  test "sandbox document GET is session navigation and POST remains RRP protected" do
    spec = ApiSpec.spec()

    get_operation =
      spec.paths
      |> Map.fetch!("/api/plugin-runtime/sandbox-documents/{session_id}")
      |> Map.fetch!(:get)

    post_operation =
      spec.paths
      |> Map.fetch!(
        "/api/workspaces/{workspace_id}/plugin-runtime/{application_id}/sandbox-documents"
      )
      |> Map.fetch!(:post)

    assert get_operation.security == [%{"user_session" => []}]
    refute header_parameter?(get_operation, "x-refmd-rrp-device-id")
    refute header_parameter?(get_operation, "x-refmd-rrp-challenge")
    refute header_parameter?(get_operation, "x-refmd-rrp-signature-transport")
    refute header_parameter?(get_operation, "x-refmd-rrp-actor-variant")

    assert header_parameter?(post_operation, "x-refmd-rrp-device-id")
    assert header_parameter?(post_operation, "x-refmd-rrp-challenge")
    assert header_parameter?(post_operation, "x-refmd-rrp-signature-transport")
    assert header_parameter?(post_operation, "x-refmd-rrp-actor-variant")
  end

  test "generated TypeScript schema keeps sandbox document GET RRP-free" do
    schema =
      @root
      |> Path.join("assets/src/shared/api/schema.d.ts")
      |> File.read!()

    get_operation =
      operation_block(schema, "get_api_plugin_runtime_sandbox_documents_by_session_id")

    post_operation =
      operation_block(
        schema,
        "post_api_workspaces_by_workspace_id_plugin_runtime_by_application_id_sandbox_documents"
      )

    assert get_operation =~ "header?: never;"
    refute get_operation =~ "\"x-refmd-rrp-device-id\""
    refute get_operation =~ "\"x-refmd-rrp-challenge\""
    refute get_operation =~ "\"x-refmd-rrp-signature-transport\""
    refute get_operation =~ "\"x-refmd-rrp-actor-variant\""

    assert post_operation =~ "\"x-refmd-rrp-device-id\": string;"
    assert post_operation =~ "\"x-refmd-rrp-challenge\": string;"
    assert post_operation =~ "\"x-refmd-rrp-signature-transport\": string;"
    assert post_operation =~ "\"x-refmd-rrp-actor-variant\": \"user_device\";"
  end

  test "generated key directory contract exposes only the current document write session event" do
    openapi_path = Path.join(@root, "assets/openapi.json")
    openapi_source = File.read!(openapi_path)
    openapi = Jason.decode!(openapi_source)
    schema = File.read!(Path.join(@root, "assets/src/shared/api/schema.d.ts"))

    for generated_contract <- [openapi_source, schema] do
      assert generated_contract =~ "document_write_session_admitted"
      refute generated_contract =~ "document_update_accepted"
    end

    session_variants =
      openapi
      |> get_in([
        "components",
        "schemas",
        "KeyDirectoryEnvelope",
        "properties",
        "payload",
        "oneOf"
      ])
      |> Enum.flat_map(&Map.get(&1, "oneOf", []))
      |> Enum.filter(fn schema ->
        Enum.any?(Map.get(schema, "oneOf", []), fn variant ->
          get_in(variant, ["properties", "event_type", "enum"]) ==
            ["document_write_session_admitted"]
        end)
      end)
      |> Enum.flat_map(&Map.fetch!(&1, "oneOf"))

    assert length(session_variants) == 4

    grouped_variants =
      Enum.group_by(session_variants, fn variant ->
        get_in(variant, ["properties", "body", "properties", "authority_kind", "enum"])
      end)

    assert Map.keys(grouped_variants) |> Enum.sort() ==
             [["share_participant_device"], ["workspace_device"]]

    assert length(grouped_variants[["workspace_device"]]) == 2
    assert length(grouped_variants[["share_participant_device"]]) == 2

    base_body_fields =
      ~w(actor_hash authority_kind authority_scope_id document_id document_permission_proof_hash event_type expires_at_ms issued_at_ms max_ciphertext_bytes max_update_count min_dek_version previous_workspace_event_hash previous_workspace_event_sequence session_id session_nonce workspace_id)

    share_body_fields =
      base_body_fields ++ ~w(share_authority_kind share_id share_permission share_session_id)

    Enum.each(session_variants, fn variant ->
      body = get_in(variant, ["properties", "body"])

      assert body["additionalProperties"] == false

      assert get_in(body, ["properties", "event_type", "enum"]) ==
               ["document_write_session_admitted"]
    end)

    Enum.each(grouped_variants[["workspace_device"]], fn variant ->
      body = get_in(variant, ["properties", "body"])
      assert Enum.sort(Map.keys(body["properties"])) == Enum.sort(base_body_fields)
      assert Enum.sort(body["required"]) == Enum.sort(base_body_fields)
    end)

    Enum.each(grouped_variants[["share_participant_device"]], fn variant ->
      body = get_in(variant, ["properties", "body"])

      assert Enum.sort(Map.keys(body["properties"])) == Enum.sort(share_body_fields)
      assert Enum.sort(body["required"]) == Enum.sort(share_body_fields)

      assert get_in(body, ["properties", "share_authority_kind", "enum"]) ==
               ["share_participant_device"]

      assert get_in(body, ["properties", "share_permission", "enum"]) == ["edit"]
    end)
  end

  test "generated contracts expose exactly the seven Signed PQ wrap purposes" do
    openapi_source = File.read!(Path.join(@root, "assets/openapi.json"))
    openapi = Jason.decode!(openapi_source)
    schema = File.read!(Path.join(@root, "assets/src/shared/api/schema.d.ts"))

    expected =
      ~w(workspace_device_kek_wrap workspace_member_kek_wrap share_participant_bootstrap_wrap share_link_secret_backup_wrap workspace_invitation_kek_wrap guest_invitation_workspace_kek_wrap guest_invitation_share_key_wrap)

    purpose_enums = collect_signed_pq_purpose_enums(openapi)
    assert purpose_enums != []
    assert Enum.all?(purpose_enums, &(Enum.sort(&1) == Enum.sort(expected)))

    resource_schemas =
      get_in(openapi, [
        "components",
        "schemas",
        "HybridKeyWrapFields",
        "properties",
        "resource",
        "oneOf"
      ])

    assert length(resource_schemas) == 7

    required_field_sets =
      MapSet.new(resource_schemas, fn resource -> MapSet.new(resource["required"]) end)

    refute MapSet.member?(
             required_field_sets,
             MapSet.new(
               ~w(workspace_id invitation_id recipient_user_id recipient_device_id recipient_encryption_key_id role_id kek_version token_hash)
             )
           )

    refute MapSet.member?(
             required_field_sets,
             MapSet.new(
               ~w(workspace_id guest_invitation_id recipient_user_id recipient_device_id recipient_encryption_key_id scope_kind scope_id permission kek_version token_hash)
             )
           )

    for removed <- [
          "workspace_invitation_package_key_wrap",
          "guest_invitation_package_key_wrap"
        ] do
      refute openapi_source =~ removed
      refute schema =~ removed
    end
  end

  test "device registration contract binds normal prekeys to a required server challenge" do
    openapi =
      @root
      |> Path.join("assets/openapi.json")
      |> File.read!()
      |> Jason.decode!()

    normal = get_in(openapi, ["components", "schemas", "CreateDeviceRegistrationRequest"])
    recovery = get_in(openapi, ["components", "schemas", "RecoverySessionRequest"])

    assert "ake_responder_prekeys" in normal["required"]
    refute Map.has_key?(normal, "oneOf")

    target_registration = recovery["properties"]["target_device_registration"]
    assert "target_device_registration" in recovery["required"]
    refute Map.has_key?(target_registration["properties"], "ake_responder_prekeys")
    refute Map.has_key?(target_registration["properties"], "registration_challenge")

    prekeys = normal["properties"]["ake_responder_prekeys"]
    umk_payload = prekeys["properties"]["umk_distribution"]["properties"]["payload"]
    trust_payload = prekeys["properties"]["trust_transfer"]["properties"]["payload"]

    approval_payload =
      get_in(prekeys, [
        "properties",
        "device_approval_kek_initial",
        "items",
        "properties",
        "prekey",
        "properties",
        "payload"
      ])

    for payload <- [umk_payload, trust_payload, approval_payload] do
      assert payload["additionalProperties"] == false
      assert "server_challenge" in payload["required"]
      assert payload["properties"]["server_challenge"] == %{"type" => "string"}
    end
  end

  defp header_parameter?(operation, name) do
    operation.parameters
    |> List.wrap()
    |> Enum.any?(fn parameter ->
      parameter_name(parameter) == name and parameter_in(parameter) in [:header, "header"]
    end)
  end

  defp parameter_name(%{name: name}) when is_atom(name), do: Atom.to_string(name)
  defp parameter_name(%{name: name}), do: name
  defp parameter_name(%{"name" => name}), do: name

  defp parameter_in(%{in: location}), do: location
  defp parameter_in(%{"in" => location}), do: location

  defp operation_block(schema, operation_name) do
    pattern =
      Regex.compile!(
        "^    #{Regex.escape(operation_name)}: \\{.*?(?=^    [A-Za-z0-9_]+: \\{|^};)",
        "ms"
      )

    assert [block] = Regex.run(pattern, schema)
    block
  end

  defp collect_signed_pq_purpose_enums(%{"purpose" => %{"enum" => enum}} = value)
       when is_list(enum) do
    current = if "workspace_device_kek_wrap" in enum, do: [enum], else: []
    current ++ collect_signed_pq_purpose_enums(Map.delete(value, "purpose"))
  end

  defp collect_signed_pq_purpose_enums(value) when is_map(value) do
    value
    |> Map.values()
    |> Enum.flat_map(&collect_signed_pq_purpose_enums/1)
  end

  defp collect_signed_pq_purpose_enums(value) when is_list(value),
    do: Enum.flat_map(value, &collect_signed_pq_purpose_enums/1)

  defp collect_signed_pq_purpose_enums(_value), do: []
end
