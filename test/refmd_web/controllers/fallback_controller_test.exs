defmodule RefMDWeb.FallbackControllerTest do
  use RefMDWeb.ConnCase, async: true

  test "serves the app shell without caching it", %{conn: conn} do
    conn = get(conn, "/dashboard")

    assert response(conn, 200) =~ ~s(<div id="root">)
    assert get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]
    assert get_resp_header(conn, "cache-control") == ["no-store"]
  end

  test "does not serve the app shell for missing hashed assets", %{conn: conn} do
    conn = get(conn, "/assets/missing-route-chunk.js")

    assert response(conn, 404) == "Not Found"
    refute get_resp_header(conn, "content-type") == ["text/html; charset=utf-8"]
  end
end
