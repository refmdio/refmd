defmodule RefMDWeb.EndpointHeaderSizeTest do
  use ExUnit.Case, async: false

  @pop_signature_transport_size 6 * 1024
  @cookie_size 10 * 1024

  test "Bandit endpoint accepts phase6-sized PoP header transport with total headers over 16KB" do
    {:ok, _} = Application.ensure_all_started(:inets)

    server = start_supervised!({Bandit, bandit_options()})
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)

    url = String.to_charlist("http://127.0.0.1:#{port}/api/openapi.json")

    headers = [
      {~c"x-pop-signature-transport",
       String.duplicate("A", @pop_signature_transport_size) |> String.to_charlist()},
      {~c"cookie", String.to_charlist("_refmd_key=" <> String.duplicate("c", @cookie_size))}
    ]

    assert {:ok, {{_, 200, _}, _headers, body}} =
             :httpc.request(:get, {url, headers}, [], body_format: :binary)

    assert body =~ ~s("openapi")
  end

  defp bandit_options do
    endpoint_http_config =
      :refmd
      |> Application.fetch_env!(RefMDWeb.Endpoint)
      |> Keyword.fetch!(:http)

    [
      plug: RefMDWeb.Endpoint,
      scheme: :http,
      ip: {127, 0, 0, 1},
      port: 0
    ] ++
      Keyword.take(endpoint_http_config, [
        :http_1_options,
        :http_2_options
      ])
  end
end
