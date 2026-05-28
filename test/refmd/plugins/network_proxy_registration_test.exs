defmodule RefMD.Plugins.NetworkProxyRegistrationTest do
  use ExUnit.Case, async: false

  alias RefMD.Plugins.NetworkProxyRegistration

  setup do
    previous = Application.get_env(:refmd, RefMDWeb.Endpoint, [])

    endpoint_config =
      Keyword.put(previous, :url, scheme: "https", host: "app.refmd.example", port: 443)

    Application.put_env(:refmd, RefMDWeb.Endpoint, endpoint_config)

    on_exit(fn ->
      Application.put_env(:refmd, RefMDWeb.Endpoint, previous)
    end)
  end

  test "rejects configured app origin proxy base urls with noncanonical host spelling" do
    for base_url <- [
          "https://app.refmd.example/proxy",
          "https://App.RefMD.Example./proxy"
        ] do
      assert {:error, :invalid_proxy_registration} =
               NetworkProxyRegistration.normalize(
                 %{
                   "id" => "workspace-proxy",
                   "label" => "Workspace Proxy",
                   "base_url" => base_url,
                   "scope" => "workspace",
                   "enabled" => true
                 },
                 "workspace"
               )
    end
  end

  test "normalizes external proxy host spelling and default https port" do
    assert {:ok, proxy} =
             NetworkProxyRegistration.normalize(
               %{
                 "id" => "workspace-proxy",
                 "label" => "Workspace Proxy",
                 "base_url" => "https://Proxy.Example.:443/refmd/",
                 "scope" => "workspace",
                 "enabled" => true
               },
               "workspace"
             )

    assert proxy["base_url"] == "https://proxy.example/refmd"
  end
end
