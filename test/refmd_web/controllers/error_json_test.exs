defmodule RefMDWeb.ErrorJSONTest do
  use RefMDWeb.ConnCase, async: true

  test "renders 404" do
    assert RefMDWeb.ErrorJSON.render("404.json", %{}) == %{errors: %{detail: "Not Found"}}
  end

  test "renders 500" do
    assert RefMDWeb.ErrorJSON.render("500.json", %{}) ==
             %{errors: %{detail: "Internal Server Error"}}
  end
end
