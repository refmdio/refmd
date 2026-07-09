defmodule RefMD.UsersTest do
  use RefMD.DataCase, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Users
  alias RefMD.Users.User

  test "unlink_external_account_preserving_login keeps one OAuth method under concurrent deletes" do
    user_id = create_user("oauth-unlink-race@example.com")
    create_oauth_master_key(user_id)

    {:ok, _google} =
      Users.create_user_external_account(%{
        user_id: user_id,
        provider: "google",
        provider_user_id: "oauth-unlink-race-google",
        email: "oauth-unlink-race@example.com"
      })

    {:ok, _github} =
      Users.create_user_external_account(%{
        user_id: user_id,
        provider: "github",
        provider_user_id: "oauth-unlink-race-github",
        email: "oauth-unlink-race@example.com"
      })

    parent = self()

    tasks =
      for provider <- ["google", "github"] do
        Task.async(fn ->
          Sandbox.allow(Repo, parent, self())
          Users.unlink_external_account_preserving_login(user_id, provider)
        end)
      end

    results = Enum.map(tasks, &Task.await(&1, 5_000))

    assert Enum.count(results, &match?({:ok, :ok}, &1)) == 1
    assert Enum.count(results, &match?({:error, :last_auth_method_required}, &1)) == 1
    assert length(Users.get_user_external_accounts(user_id)) == 1
  end

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email,
      account_type: "registered"
    })

    user_id
  end

  defp create_oauth_master_key(user_id) do
    recovery = recovery_authorization_material(user_id)

    {:ok, _master_key} =
      Encryption.create_user_encrypted_master_key(%{
        user_id: user_id,
        auth_type: "oauth",
        recovery_encrypted_umk: <<4::256>>,
        recovery_nonce: <<5::192>>,
        recovery_authorization_public_material: recovery.public,
        recovery_authorization_key_id: recovery.key_id
      })
  end
end
