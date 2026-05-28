defmodule RefMD.Plugins.NetworkEndpointAppOriginTest do
  use ExUnit.Case, async: false

  alias RefMD.Plugins.Artifact

  setup do
    original = Application.get_env(:refmd, RefMDWeb.Endpoint)

    Application.put_env(
      :refmd,
      RefMDWeb.Endpoint,
      Keyword.put(original, :url, scheme: "https", host: "app.refmd.example", port: 443)
    )

    on_exit(fn -> Application.put_env(:refmd, RefMDWeb.Endpoint, original) end)
  end

  test "rejects manifest network endpoints targeting the configured app origin" do
    endpoint = %{
      "id" => "app-origin",
      "url" => "https://app.refmd.example/api/documents",
      "methods" => ["POST"],
      "routes" => ["proxy"],
      "allowedHeaders" => ["content-type"],
      "bodySchema" => "json"
    }

    assert {:error, :plugin_manifest_invalid_network_endpoint} =
             plugin_archive_path(%{
               "manifest.json" => Jason.encode!(network_endpoint_manifest([endpoint])),
               "main.js" => "export default {};"
             })
             |> Artifact.candidate_attrs_from_archive_path(:local_upload, nil, %{})
  end

  defp network_endpoint_manifest(endpoints) do
    %{
      "scope" => %{
        "supportedOwnerScopes" => ["workspace"],
        "defaultOwnerScope" => "workspace",
        "workspaceApplication" => "required"
      },
      "id" => "com.example.app-origin-network-endpoint",
      "version" => "1.0.0",
      "permissions" => ["network:fetch"],
      "network" => %{"endpoints" => endpoints},
      "rendererSlots" => [],
      "documentScopes" => []
    }
  end

  defp plugin_archive_path(entries) do
    path =
      Path.join(
        System.tmp_dir!(),
        "refmd-plugin-#{System.unique_integer([:positive, :monotonic])}.zip"
      )

    zip_entries = Enum.map(entries, fn {name, bytes} -> {String.to_charlist(name), bytes} end)
    {:ok, _filename} = :zip.create(String.to_charlist(path), zip_entries)
    path
  end
end
