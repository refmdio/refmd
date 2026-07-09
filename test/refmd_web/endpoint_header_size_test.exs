defmodule RefMDWeb.EndpointHeaderSizeTest do
  use ExUnit.Case, async: false

  @rrp_signature_transport_size 6 * 1024
  @cookie_size 10 * 1024
  @max_update_payload_raw_bytes 1_048_576

  test "Bandit endpoint accepts phase6-sized RRP header transport with total headers over 16KB" do
    {:ok, _} = Application.ensure_all_started(:inets)

    server = start_supervised!({Bandit, bandit_options()})
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)

    url = String.to_charlist("http://127.0.0.1:#{port}/api/openapi.json")

    headers = [
      {~c"x-refmd-e2e-rate-limit-bypass", ~c"1"},
      {~c"x-refmd-rrp-signature-transport",
       String.duplicate("A", @rrp_signature_transport_size) |> String.to_charlist()},
      {~c"cookie", String.to_charlist("__Host-refmd-key=" <> String.duplicate("c", @cookie_size))}
    ]

    assert {:ok, {{_, 200, _}, _headers, body}} =
             :httpc.request(:get, {url, headers}, [], body_format: :binary)

    assert body =~ ~s("openapi")
  end

  test "document websocket caps frame size before channel payload parsing" do
    assert [
             {"/api/socket", RefMDWeb.UserSocket,
              [
                websocket: websocket_options,
                longpoll: false
              ]}
           ] = RefMDWeb.Endpoint.__sockets__()

    assert Keyword.fetch!(websocket_options, :max_frame_size) == 1_250_000
    assert Keyword.fetch!(websocket_options, :max_frame_size) > @max_update_payload_raw_bytes
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
