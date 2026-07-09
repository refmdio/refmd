defmodule RefMD.Auth.OAuthTest do
  use RefMD.DataCase, async: false

  import ExUnit.CaptureLog

  alias RefMD.Auth.OAuth
  alias RefMD.Users

  @redirect_uri "https://refmd.test/api/auth/oauth/google/callback"
  @github_redirect_uri "https://refmd.test/api/auth/oauth/github/callback"

  setup do
    oauth_config = Application.get_env(:refmd, :oauth)
    on_exit(fn -> Application.put_env(:refmd, :oauth, oauth_config) end)
    :ok
  end

  test "Google OAuth uses PKCE and no provider DPoP by default" do
    {:ok, authorization_url} = OAuth.start_authorization("google", @redirect_uri, "/docs")
    authorization = URI.parse(authorization_url)
    authorization_params = URI.decode_query(authorization.query)

    assert authorization.scheme == "https"
    assert authorization.host == "accounts.google.com"
    assert authorization_params["response_type"] == "code"
    assert authorization_params["code_challenge_method"] == "S256"
    assert authorization_params["code_challenge"] =~ ~r/^[A-Za-z0-9_-]{43}$/
    assert authorization_params["state"] =~ ~r/^[A-Za-z0-9_-]+$/
    assert authorization_params["nonce"] =~ ~r/^[A-Za-z0-9_-]+$/

    parent = self()

    request_fun = fn
      :post, "https://oauth2.googleapis.com/token", headers, body ->
        send(parent, {:google_token_request, headers, URI.decode_query(body)})

        {:ok, 200, [{"dpop-nonce", "nonce-1"}],
         Jason.encode!(%{
           "access_token" => "google-access-token",
           "token_type" => "Bearer",
           "id_token" => id_token(authorization_params["nonce"])
         })}

      :get, "https://openidconnect.googleapis.com/v1/userinfo", headers, "" ->
        send(parent, {:google_userinfo_request, headers})

        {:ok, 200, [],
         Jason.encode!(%{
           "sub" => "google-123",
           "email" => "Person@Example.com",
           "email_verified" => true,
           "name" => "Person"
         })}
    end

    assert {:ok, user, "/docs"} =
             OAuth.complete_authorization(
               "google",
               authorization_params["state"],
               "authorization-code",
               @redirect_uri,
               request_fun: request_fun
             )

    assert user.email == "person@example.com"
    assert Users.get_user_external_account("google", "google-123")

    assert_received {:google_token_request, token_headers, token_form}
    assert token_form["grant_type"] == "authorization_code"
    assert token_form["code"] == "authorization-code"
    assert token_form["code_verifier"] =~ ~r/^[A-Za-z0-9_-]{43}$/
    assert token_form["client_secret"] == "test-google-secret"

    refute header(token_headers, "dpop")

    assert_received {:google_userinfo_request, userinfo_headers}
    assert header!(userinfo_headers, "authorization") == "Bearer google-access-token"
    refute header(userinfo_headers, "dpop")
  end

  test "OAuth does not auto-link a new provider identity to an existing email account" do
    {:ok, existing_user} =
      Users.create_user(%{
        email: "existing-oauth@example.com",
        name: "Existing User",
        account_type: "registered"
      })

    {:ok, authorization_url} = OAuth.start_authorization("google", @redirect_uri, "/docs")

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    request_fun = fn
      :post, "https://oauth2.googleapis.com/token", _headers, _body ->
        {:ok, 200, [],
         Jason.encode!(%{
           "access_token" => "google-access-token",
           "token_type" => "Bearer",
           "id_token" => id_token(authorization_params["nonce"])
         })}

      :get, "https://openidconnect.googleapis.com/v1/userinfo", _headers, "" ->
        {:ok, 200, [],
         Jason.encode!(%{
           "sub" => "google-existing-email",
           "email" => "Existing-OAuth@Example.com",
           "email_verified" => true,
           "name" => "Provider Identity"
         })}
    end

    assert {:error, :oauth_account_link_required} =
             OAuth.complete_authorization(
               "google",
               authorization_params["state"],
               "authorization-code",
               @redirect_uri,
               request_fun: request_fun
             )

    refute Users.get_user_external_account("google", "google-existing-email")
    assert Users.get_user_by_email("existing-oauth@example.com").id == existing_user.id
  end

  test "OAuth account link attaches a new provider to the bound user and session" do
    {:ok, user} =
      Users.create_user(%{
        email: "linked-user@example.com",
        name: "Linked User",
        account_type: "registered"
      })

    {:ok, _google_account} =
      Users.create_user_external_account(%{
        user_id: user.id,
        provider: "google",
        provider_user_id: "google-linked-user",
        email: user.email
      })

    session_id = Ecto.UUID.generate()

    {:ok, authorization_url} =
      OAuth.start_account_link(
        "github",
        @github_redirect_uri,
        "/dashboard?settings=account",
        user.id,
        session_id
      )

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    assert {:ok, %{purpose: "account_link", user: linked_user, return_to: return_to}} =
             OAuth.complete_callback(
               "github",
               authorization_params["state"],
               "github-code",
               @github_redirect_uri,
               request_fun: github_request_fun("github-linked-user", "linked-user@example.com"),
               session_context: %{user_id: user.id, session_id: session_id}
             )

    assert linked_user.id == user.id
    assert return_to == "/dashboard?settings=account"

    github_account = Users.get_user_external_account_for_user(user.id, "github")
    assert github_account.provider_user_id == "github-linked-user"
    assert github_account.email == "linked-user@example.com"
  end

  test "OAuth login completion rejects account link states before side effects" do
    {:ok, user} =
      Users.create_user(%{
        email: "login-api-link-state@example.com",
        name: "Login API Link State",
        account_type: "registered"
      })

    session_id = Ecto.UUID.generate()

    {:ok, authorization_url} =
      OAuth.start_account_link("github", @github_redirect_uri, "/", user.id, session_id)

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    request_fun = fn _method, _url, _headers, _body ->
      flunk("login completion must reject account_link state before provider requests")
    end

    assert {:error, :invalid_oauth_state} =
             OAuth.complete_authorization(
               "github",
               authorization_params["state"],
               "github-code",
               @github_redirect_uri,
               request_fun: request_fun,
               session_context: %{user_id: user.id, session_id: session_id}
             )

    refute Users.get_user_external_account_for_user(user.id, "github")
  end

  test "OAuth account link rejects a callback for a different session" do
    {:ok, user} =
      Users.create_user(%{
        email: "session-bound@example.com",
        name: "Session Bound",
        account_type: "registered"
      })

    {:ok, authorization_url} =
      OAuth.start_account_link("github", @github_redirect_uri, "/", user.id, Ecto.UUID.generate())

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    assert {:error, :invalid_oauth_state} =
             OAuth.complete_callback(
               "github",
               authorization_params["state"],
               "github-code",
               @github_redirect_uri,
               request_fun: github_request_fun("github-session-bound", user.email),
               session_context: %{user_id: user.id, session_id: Ecto.UUID.generate()}
             )

    refute Users.get_user_external_account_for_user(user.id, "github")
  end

  test "OAuth account link rejects provider identities linked to another user" do
    {:ok, user} =
      Users.create_user(%{
        email: "link-owner@example.com",
        name: "Link Owner",
        account_type: "registered"
      })

    {:ok, other_user} =
      Users.create_user(%{
        email: "provider-owner@example.com",
        name: "Provider Owner",
        account_type: "registered"
      })

    {:ok, _external_account} =
      Users.create_user_external_account(%{
        user_id: other_user.id,
        provider: "github",
        provider_user_id: "github-conflict",
        email: other_user.email
      })

    session_id = Ecto.UUID.generate()

    {:ok, authorization_url} =
      OAuth.start_account_link("github", @github_redirect_uri, "/", user.id, session_id)

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    assert {:error, :oauth_external_account_conflict} =
             OAuth.complete_callback(
               "github",
               authorization_params["state"],
               "github-code",
               @github_redirect_uri,
               request_fun: github_request_fun("github-conflict", "link-owner@example.com"),
               session_context: %{user_id: user.id, session_id: session_id}
             )

    refute Users.get_user_external_account_for_user(user.id, "github")
  end

  test "Google OAuth can use provider DPoP when explicitly enabled" do
    put_google_dpop_config()

    {:ok, authorization_url} = OAuth.start_authorization("google", @redirect_uri, "/docs")

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    assert authorization_params["nonce"] =~ ~r/^[A-Za-z0-9_-]+$/

    parent = self()

    request_fun = fn
      :post, "https://oauth2.googleapis.com/token", headers, body ->
        send(parent, {:google_token_request, headers, URI.decode_query(body)})

        {:ok, 200, [{"dpop-nonce", "nonce-1"}],
         Jason.encode!(%{
           "access_token" => "google-access-token",
           "token_type" => "Bearer",
           "id_token" => id_token(authorization_params["nonce"])
         })}

      :get, "https://openidconnect.googleapis.com/v1/userinfo", headers, "" ->
        send(parent, {:google_userinfo_request, headers})

        {:ok, 200, [],
         Jason.encode!(%{
           "sub" => "google-dpop",
           "email" => "Dpop@Example.com",
           "email_verified" => true,
           "name" => "DPoP"
         })}
    end

    assert {:ok, user, "/docs"} =
             OAuth.complete_authorization(
               "google",
               authorization_params["state"],
               "authorization-code",
               @redirect_uri,
               request_fun: request_fun
             )

    assert user.email == "dpop@example.com"
    assert_received {:google_token_request, token_headers, _token_form}

    token_dpop = header!(token_headers, "dpop")
    {token_dpop_header, token_dpop_payload} = decode_jwt(token_dpop)
    assert token_dpop_header["typ"] == "dpop+jwt"
    assert token_dpop_header["alg"] == "ES256"
    assert token_dpop_header["jwk"]["kty"] == "EC"
    assert token_dpop_payload["htm"] == "POST"
    assert token_dpop_payload["htu"] == "https://oauth2.googleapis.com/token"
    assert token_dpop_payload["jti"] == authorization_code_jti("authorization-code")
    refute Map.has_key?(token_dpop_payload, "ath")

    assert_received {:google_userinfo_request, userinfo_headers}
    assert header!(userinfo_headers, "authorization") == "Bearer google-access-token"
    refute header(userinfo_headers, "dpop")
  end

  test "GitHub OAuth uses PKCE and does not send provider DPoP when unsupported" do
    redirect_uri = "https://refmd.test/api/auth/oauth/github/callback"
    {:ok, authorization_url} = OAuth.start_authorization("github", redirect_uri, "/")

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    parent = self()

    request_fun = fn
      :post, "https://github.com/login/oauth/access_token", headers, body ->
        send(parent, {:github_token_request, headers, URI.decode_query(body)})
        {:ok, 200, [], Jason.encode!(%{"access_token" => "github-access-token"})}

      :get, "https://api.github.com/user", headers, "" ->
        send(parent, {:github_user_request, headers})
        {:ok, 200, [], Jason.encode!(%{"id" => 42, "login" => "octo"})}

      :get, "https://api.github.com/user/emails", headers, "" ->
        send(parent, {:github_email_request, headers})

        {:ok, 200, [],
         Jason.encode!([
           %{"email" => "octo@example.com", "primary" => true, "verified" => true}
         ])}
    end

    assert {:ok, user, "/"} =
             OAuth.complete_authorization(
               "github",
               authorization_params["state"],
               "github-code",
               redirect_uri,
               request_fun: request_fun
             )

    assert user.email == "octo@example.com"
    assert Users.get_user_external_account("github", "42")

    assert_received {:github_token_request, token_headers, token_form}
    assert token_form["code_verifier"] =~ ~r/^[A-Za-z0-9_-]{43}$/
    assert token_form["client_secret"] == "test-github-secret"
    refute header(token_headers, "dpop")

    assert_received {:github_user_request, github_user_headers}
    assert header!(github_user_headers, "authorization") == "Bearer github-access-token"
    refute header(github_user_headers, "dpop")

    assert_received {:github_email_request, github_email_headers}
    refute header(github_email_headers, "dpop")
  end

  test "Google OAuth DPoP nonce retry preserves authorization-code-bound jti" do
    put_google_dpop_config()

    {:ok, authorization_url} = OAuth.start_authorization("google", @redirect_uri, "/")

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    parent = self()

    request_fun = fn
      :post, "https://oauth2.googleapis.com/token", headers, body ->
        send(parent, {:google_token_request, headers, URI.decode_query(body)})

        receive do
          :token_retry ->
            {:ok, 200, [],
             Jason.encode!(%{
               "access_token" => "google-access-token",
               "token_type" => "Bearer",
               "id_token" => id_token(authorization_params["nonce"])
             })}
        after
          0 ->
            send(parent, :token_retry)
            {:ok, 400, [{"dpop-nonce", "nonce-1"}], Jason.encode!(%{"error" => "use_dpop_nonce"})}
        end

      :get, "https://openidconnect.googleapis.com/v1/userinfo", _headers, "" ->
        {:ok, 200, [],
         Jason.encode!(%{
           "sub" => "google-456",
           "email" => "Retry@example.com",
           "email_verified" => true
         })}
    end

    assert {:ok, user, "/"} =
             OAuth.complete_authorization(
               "google",
               authorization_params["state"],
               "retry-code",
               @redirect_uri,
               request_fun: request_fun
             )

    assert user.email == "retry@example.com"
    assert_received {:google_token_request, first_headers, _first_form}
    assert_received {:google_token_request, retry_headers, _retry_form}

    {_header, first_payload} = first_headers |> header!("dpop") |> decode_jwt()
    {_header, retry_payload} = retry_headers |> header!("dpop") |> decode_jwt()

    assert first_payload["jti"] == authorization_code_jti("retry-code")
    assert retry_payload["jti"] == authorization_code_jti("retry-code")
    assert retry_payload["nonce"] == "nonce-1"
  end

  test "Google OAuth does not retry DPoP nonce for non nonce-challenge errors" do
    put_google_dpop_config()

    {:ok, authorization_url} = OAuth.start_authorization("google", @redirect_uri, "/")

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    parent = self()

    request_fun = fn
      :post, "https://oauth2.googleapis.com/token", headers, body ->
        send(parent, {:google_token_request, headers, URI.decode_query(body)})

        {:ok, 400, [{"dpop-nonce", "nonce-1"}],
         Jason.encode!(%{"error" => "invalid_grant", "error_description" => "Bad Request"})}
    end

    assert {:error, {:oauth_token_exchange_failed, details}} =
             OAuth.complete_authorization(
               "google",
               authorization_params["state"],
               "invalid-grant-code",
               @redirect_uri,
               request_fun: request_fun
             )

    assert details.reason == "non_success"
    assert details.provider_error["error"] == "invalid_grant"
    assert_received {:google_token_request, _first_headers, _first_form}
    refute_received {:google_token_request, _retry_headers, _retry_form}
  end

  test "Google OAuth fails before redirect when client secret is missing" do
    Application.put_env(:refmd, :oauth,
      google: [client_id: "test-google-client"],
      github: [
        client_id: "test-github-client",
        client_secret: "test-github-secret"
      ]
    )

    assert {:error, {:oauth_provider_not_configured, details}} =
             OAuth.start_authorization("google", @redirect_uri, "/")

    assert details == %{provider: "google", missing: "client_secret"}
  end

  test "Google OAuth token exchange returns safe provider diagnostics" do
    {:ok, authorization_url} = OAuth.start_authorization("google", @redirect_uri, "/")

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    request_fun = fn
      :post, "https://oauth2.googleapis.com/token", _headers, _body ->
        {:ok, 400, [],
         Jason.encode!(%{
           "error" => "invalid_request",
           "error_description" => "client_secret is missing."
         })}
    end

    log =
      capture_log(fn ->
        assert {:error, {:oauth_token_exchange_failed, details}} =
                 OAuth.complete_authorization(
                   "google",
                   authorization_params["state"],
                   "authorization-code",
                   @redirect_uri,
                   request_fun: request_fun
                 )

        assert details.provider == "google"
        assert details.status == 400
        assert details.provider_error["error"] == "invalid_request"
        assert details.provider_error["error_description"] == "client_secret is missing."
      end)

    assert log =~ "OAuth token exchange failed provider=google"
    refute log =~ "authorization-code"
    refute log =~ "test-google-secret"
  end

  test "Google OAuth rejects an ID token nonce mismatch" do
    {:ok, authorization_url} = OAuth.start_authorization("google", @redirect_uri, "/")

    authorization_params =
      authorization_url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

    request_fun = fn
      :post, "https://oauth2.googleapis.com/token", _headers, _body ->
        {:ok, 200, [],
         Jason.encode!(%{
           "access_token" => "google-access-token",
           "token_type" => "Bearer",
           "id_token" => id_token("wrong-nonce")
         })}
    end

    assert {:error, :invalid_oauth_nonce} =
             OAuth.complete_authorization(
               "google",
               authorization_params["state"],
               "authorization-code",
               @redirect_uri,
               request_fun: request_fun
             )
  end

  defp header!(headers, name) do
    headers
    |> header(name)
    |> case do
      value when is_binary(value) -> value
      nil -> flunk("missing #{name} header")
    end
  end

  defp github_request_fun(provider_user_id, email) do
    fn
      :post, "https://github.com/login/oauth/access_token", _headers, _body ->
        {:ok, 200, [], Jason.encode!(%{"access_token" => "github-access-token"})}

      :get, "https://api.github.com/user", _headers, "" ->
        {:ok, 200, [], Jason.encode!(%{"id" => provider_user_id, "login" => "octo"})}

      :get, "https://api.github.com/user/emails", _headers, "" ->
        {:ok, 200, [],
         Jason.encode!([
           %{"email" => email, "primary" => true, "verified" => true}
         ])}
    end
  end

  defp header(headers, name) do
    Enum.find_value(headers, fn {header, value} ->
      if String.downcase(to_string(header)) == name, do: to_string(value)
    end)
  end

  defp decode_jwt(jwt) do
    [encoded_header, encoded_payload, _signature] = String.split(jwt, ".", parts: 3)

    {:ok, header} = encoded_header |> Base.url_decode64(padding: false) |> decode_json()
    {:ok, payload} = encoded_payload |> Base.url_decode64(padding: false) |> decode_json()

    {header, payload}
  end

  defp decode_json({:ok, bytes}), do: Jason.decode(bytes)

  defp authorization_code_jti(code),
    do: :sha256 |> :crypto.hash(code) |> Base.url_encode64(padding: false)

  defp id_token(nonce) do
    [
      base64url_json(%{"alg" => "none"}),
      base64url_json(%{"nonce" => nonce}),
      ""
    ]
    |> Enum.join(".")
  end

  defp base64url_json(value), do: value |> Jason.encode!() |> Base.url_encode64(padding: false)

  defp put_google_dpop_config do
    Application.put_env(:refmd, :oauth,
      google: [
        client_id: "test-google-client",
        client_secret: "test-google-secret",
        provider_dpop: true
      ],
      github: [
        client_id: "test-github-client",
        client_secret: "test-github-secret"
      ]
    )
  end
end
