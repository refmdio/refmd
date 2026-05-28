defmodule RefMDWeb.Plugs.CSPTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMDWeb.Plugs.CSP

  setup do
    original = System.get_env("ENABLE_SWAGGER")
    System.delete_env("ENABLE_SWAGGER")

    on_exit(fn ->
      if original do
        System.put_env("ENABLE_SWAGGER", original)
      else
        System.delete_env("ENABLE_SWAGGER")
      end
    end)
  end

  test "production parent app CSP stays strict for plugin runtime", %{conn: conn} do
    conn = CSP.call(conn, [])
    [csp] = get_resp_header(conn, "content-security-policy")
    directives = csp_directives(csp)

    assert Map.fetch!(directives, "default-src") == ["'self'"]
    assert Map.fetch!(directives, "script-src") == ["'self'"]
    assert Map.fetch!(directives, "frame-src") == ["'self'"]
    assert Map.fetch!(directives, "frame-ancestors") == ["'none'"]
    assert Map.fetch!(directives, "object-src") == ["'none'"]

    refute_source_tokens(directives, "script-src", [
      "'unsafe-inline'",
      "'unsafe-eval'",
      "blob:",
      "data:"
    ])

    refute Enum.any?(Map.fetch!(directives, "script-src"), &String.starts_with?(&1, "'sha256-"))
    refute Enum.any?(Map.fetch!(directives, "script-src"), &String.starts_with?(&1, "'nonce-"))
    refute_source_tokens(directives, "frame-src", ["blob:", "data:"])
    assert get_resp_header(conn, "x-frame-options") == ["DENY"]
  end

  defp csp_directives(csp) do
    csp
    |> String.split(";")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Map.new(fn directive ->
      [name | sources] = String.split(directive, ~r/\s+/, trim: true)
      {name, sources}
    end)
  end

  defp refute_source_tokens(directives, name, forbidden_sources) do
    sources = Map.fetch!(directives, name)

    for source <- forbidden_sources do
      refute source in sources, "#{name} must not include #{source}"
    end
  end
end
