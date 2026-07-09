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
end
