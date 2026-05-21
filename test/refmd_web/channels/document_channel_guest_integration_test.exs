defmodule RefMDWeb.DocumentChannelGuestIntegrationTest do
  use RefMDWeb.ChannelIntegrationCase, async: false

  alias RefMD.Workspaces

  test "guest write integration rejects missing invitation instead of disabling the flow" do
    assert {:error, :not_found} = Workspaces.redeem_guest_invitation("x", %{}, %{})
  end
end
