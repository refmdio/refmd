defmodule RefMDWeb.Plugs.RequireAuthTest do
  use RefMDWeb.ConnCase, async: true

  alias RefMD.Auth
  alias RefMD.Documents
  alias RefMD.Repo
  alias RefMD.Sharing
  alias RefMD.Users.User
  alias RefMD.Workspaces
  alias RefMDWeb.Plugs.RequireAuth

  defp create_user(email) do
    user_id = Ecto.UUID.generate()

    Repo.insert!(%User{
      id: user_id,
      email: email,
      name: email
    })

    user_id
  end

  defp create_document(workspace_id, created_by) do
    {:ok, document} =
      Documents.create_document(%{
        "id" => Ecto.UUID.generate(),
        "workspace_id" => workspace_id,
        "doc_type" => "document",
        "parent_id" => nil,
        "title" => "Untitled",
        "encrypted_title" => <<1, 2, 3>>,
        "encrypted_title_nonce" => :crypto.strong_rand_bytes(24),
        "encrypted_title_key_version" => 1,
        "created_by" => created_by
      })

    document
  end

  defp create_share(document, owner_id) do
    share_slug = Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
    workspace_pin_bootstrap_hash = Process.get(:workspace_pin_bootstrap_hash)

    attrs =
      with_test_share_security_artifacts(document, owner_id, %{
        "id" => Ecto.UUID.generate(),
        "scope" => "document",
        "share_slug" => share_slug,
        "token_prefix" => String.slice(share_slug, 0, 4),
        "permission" => "view",
        "password_protected" => false,
        "authorization_public_key_material" =>
          share_capability_public_key_material_for_slug(open_admission_key(), share_slug),
        "share_capability_secret_commitment" => open_share_capability_secret_commitment(),
        "authenticated_workspace_pin_bootstrap_hash" => workspace_pin_bootstrap_hash,
        "encrypted_dek" => :crypto.strong_rand_bytes(48),
        "nonce" => :crypto.strong_rand_bytes(24)
      })

    {:ok, created} = Sharing.create_share(document, owner_id, attrs)

    created
  end

  setup do
    owner_id = create_user("owner-require-auth@example.com")
    {:ok, workspace} = Workspaces.create_default_workspace(owner_id, "RequireAuth Workspace")
    {_member, role} = Workspaces.get_member_with_role(workspace.id, owner_id)
    insert_test_workspace_key_directory!(workspace.id, owner_id, role.id)
    Process.put(:workspace_pin_bootstrap_hash, test_workspace_pin_bootstrap_hash!(workspace.id))
    document = create_document(workspace.id, owner_id)
    created = create_share(document, owner_id)

    {:ok, _user_session, user_token} = Auth.create_session(owner_id)

    {:ok, bootstrapped} =
      bootstrap_share_participant(created, "Guest User")

    %{
      user_cookie: Base.url_encode64(user_token, padding: false),
      share_cookie: Base.url_encode64(bootstrapped.session_token, padding: false),
      share_id: created.share.id,
      principal_id: bootstrapped.participant.principal_id
    }
  end

  test "accepts a share participant session from the share session cookie when share scope is requested",
       %{
         conn: conn,
         share_cookie: share_cookie,
         share_id: share_id,
         principal_id: principal_id
       } do
    conn =
      conn
      |> put_req_header("cookie", "__Host-refmd-share-session=#{share_cookie}")
      |> put_req_header("x-refmd-session-scope", "share")
      |> RequireAuth.call(allow_share_participant: true)

    refute conn.halted
    assert conn.assigns.session_kind == :share_participant
    assert conn.assigns.current_share_id == share_id
    assert conn.assigns.share_participant_principal_id == principal_id
  end

  test "rejects a share participant session without the share scope selector", %{
    conn: conn,
    share_cookie: share_cookie
  } do
    conn =
      conn
      |> put_req_header("cookie", "__Host-refmd-share-session=#{share_cookie}")
      |> RequireAuth.call(allow_share_participant: true)

    assert conn.halted
    assert conn.status == 401
  end

  test "prefers the user session when both cookies are present and share scope is not requested",
       %{
         conn: conn,
         user_cookie: user_cookie,
         share_cookie: share_cookie
       } do
    conn =
      conn
      |> put_req_header(
        "cookie",
        "__Host-refmd-session=#{user_cookie}; __Host-refmd-share-session=#{share_cookie}"
      )
      |> RequireAuth.call(allow_share_participant: true)

    refute conn.halted
    assert conn.assigns.session_kind == :user
  end
end
