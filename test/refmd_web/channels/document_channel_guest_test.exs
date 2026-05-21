defmodule RefMDWeb.DocumentChannelGuestTest do
  use RefMDWeb.ChannelIntegrationCase, async: false

  alias RefMD.Workspaces

  test "guest invitation onboarding entrypoint is available" do
    assert [] = Workspaces.list_guest_invitations(Ecto.UUID.generate())
  end
end
