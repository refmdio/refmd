defmodule RefMD.Auth.OAuth do
  @moduledoc false

  import Ecto.Query
  require Logger

  alias RefMD.Auth.OAuthState
  alias RefMD.Crypto.Hash
  alias RefMD.Repo
  alias RefMD.Users

  @login_purpose "login"
  @account_link_purpose "account_link"
  @state_ttl_seconds 10 * 60
  @providers %{
    "google" => %{
      authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
      token_endpoint: "https://oauth2.googleapis.com/token",
      userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo",
      scope: "openid email profile",
      enabled: true,
      client_secret_required: true
    },
    "github" => %{
      authorization_endpoint: "https://github.com/login/oauth/authorize",
      token_endpoint: "https://github.com/login/oauth/access_token",
      userinfo_endpoint: "https://api.github.com/user",
      emails_endpoint: "https://api.github.com/user/emails",
      scope: "read:user user:email",
      enabled: true,
      client_secret_required: true
    }
  }
  @provider_order ["google", "github"]

  def start_authorization(provider, redirect_uri, return_to)
      when is_binary(provider) and is_binary(redirect_uri) and is_binary(return_to) do
    with {:ok, config} <- provider_config(provider),
         {:ok, state} <- create_state(provider, redirect_uri, return_to, @login_purpose) do
      {:ok, authorization_url(config, state)}
    end
  end

  def start_authorization(_, _, _), do: {:error, :invalid_provider}

  def start_account_link(provider, redirect_uri, return_to, user_id, session_id)
      when is_binary(provider) and is_binary(redirect_uri) and is_binary(return_to) and
             is_binary(user_id) and is_binary(session_id) do
    with {:ok, config} <- provider_config(provider),
         {:ok, state} <-
           create_state(provider, redirect_uri, return_to, @account_link_purpose, %{
             user_id: user_id,
             session_id: session_id
           }) do
      {:ok, authorization_url(config, state)}
    end
  end

  def start_account_link(_, _, _, _, _), do: {:error, :invalid_provider}

  def complete_authorization(provider, state, code, redirect_uri, opts \\ [])

  def complete_authorization(provider, state, code, redirect_uri, opts)
      when is_binary(provider) and is_binary(state) and is_binary(code) and
             is_binary(redirect_uri) do
    opts = Keyword.put(opts, :expected_purpose, @login_purpose)

    case complete_callback(provider, state, code, redirect_uri, opts) do
      {:ok, %{purpose: @login_purpose, user: user, return_to: return_to}} ->
        {:ok, user, return_to}

      {:ok, %{purpose: @account_link_purpose}} ->
        {:error, :invalid_oauth_state}

      other ->
        other
    end
  end

  def complete_authorization(_, _, _, _, _), do: {:error, :invalid_oauth_callback}

  def complete_callback(provider, state, code, redirect_uri, opts \\ [])

  def complete_callback(provider, state, code, redirect_uri, opts)
      when is_binary(provider) and is_binary(state) and is_binary(code) and
             is_binary(redirect_uri) do
    request_fun = Keyword.get(opts, :request_fun, &http_request/4)
    session_context = Keyword.get(opts, :session_context)
    expected_purpose = Keyword.get(opts, :expected_purpose)

    with {:ok, config} <- provider_config(provider),
         {:ok, oauth_state} <- consume_state(provider, state, redirect_uri),
         :ok <- verify_expected_purpose(oauth_state, expected_purpose),
         :ok <- verify_pre_exchange_context(oauth_state, session_context),
         {:ok, token_result} <-
           exchange_code(
             config,
             code,
             oauth_state.code_verifier,
             oauth_state.redirect_uri,
             request_fun
           ),
         :ok <- verify_oauth_nonce(config, oauth_state, token_result),
         {:ok, identity} <- fetch_identity(config, token_result, request_fun) do
      complete_by_purpose(oauth_state, identity, session_context)
    end
  end

  def complete_callback(_, _, _, _, _), do: {:error, :invalid_oauth_callback}

  def delete_expired_states do
    now = DateTime.utc_now()

    from(s in OAuthState, where: s.expires_at < ^now or not is_nil(s.consumed_at))
    |> Repo.delete_all()
  end

  def available_providers do
    @provider_order
    |> Enum.filter(fn provider ->
      case provider_config(provider) do
        {:ok, _config} -> true
        {:error, _reason} -> false
      end
    end)
  end

  defp provider_config(provider) do
    case Map.fetch(@providers, provider) do
      {:ok, defaults} ->
        runtime = runtime_provider_config(provider)

        config =
          defaults
          |> Map.merge(runtime)
          |> Map.put(:provider, provider)

        cond do
          config[:enabled] == false ->
            {:error, {:oauth_provider_disabled, %{provider: config.provider}}}

          blank?(config[:client_id]) ->
            {:error, oauth_provider_config_error(config.provider, "client_id")}

          config[:client_secret_required] and blank?(config[:client_secret]) ->
            {:error, oauth_provider_config_error(config.provider, "client_secret")}

          true ->
            {:ok, config}
        end

      :error ->
        {:error, :invalid_provider}
    end
  end

  defp runtime_provider_config(provider) do
    provider_key = provider_key!(provider)

    :refmd
    |> Application.get_env(:oauth, [])
    |> Keyword.get(provider_key, [])
    |> Enum.into(%{})
  end

  defp create_state(provider, redirect_uri, return_to, purpose, context \\ %{}) do
    state = random_base64url(32)
    nonce = random_base64url(32)
    verifier = random_base64url(32)
    now = DateTime.utc_now()

    attrs = %{
      provider: provider,
      state_hash: state_hash(state),
      nonce: nonce,
      code_verifier: verifier,
      redirect_uri: redirect_uri,
      return_to: return_to,
      purpose: purpose,
      user_id: Map.get(context, :user_id),
      session_id_hash: context |> Map.get(:session_id) |> session_id_hash(),
      expires_at: DateTime.add(now, @state_ttl_seconds, :second)
    }

    with :ok <- validate_state_context(purpose, context),
         {:ok, oauth_state} <-
           %OAuthState{created_at: now} |> OAuthState.changeset(attrs) |> Repo.insert() do
      {:ok, Map.put(oauth_state, :state, state)}
    end
  end

  defp validate_state_context(@login_purpose, _context), do: :ok

  defp validate_state_context(@account_link_purpose, %{user_id: user_id, session_id: session_id})
       when is_binary(user_id) and is_binary(session_id),
       do: :ok

  defp validate_state_context(@account_link_purpose, _context), do: {:error, :invalid_oauth_state}
  defp validate_state_context(_purpose, _context), do: {:error, :invalid_oauth_state}

  defp verify_expected_purpose(_oauth_state, nil), do: :ok
  defp verify_expected_purpose(%{purpose: purpose}, purpose), do: :ok

  defp verify_expected_purpose(_oauth_state, _expected_purpose),
    do: {:error, :invalid_oauth_state}

  defp verify_pre_exchange_context(
         %{purpose: @account_link_purpose} = oauth_state,
         session_context
       ) do
    case validate_account_link_context(oauth_state, session_context) do
      {:ok, _user_id} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp verify_pre_exchange_context(_oauth_state, _session_context), do: :ok

  defp authorization_url(config, oauth_state) do
    query =
      %{
        "client_id" => config.client_id,
        "code_challenge" => pkce_challenge(oauth_state.code_verifier),
        "code_challenge_method" => "S256",
        "redirect_uri" => oauth_state.redirect_uri,
        "response_type" => "code",
        "scope" => config.scope,
        "state" => oauth_state.state
      }
      |> maybe_put_oidc_nonce(config, oauth_state)
      |> maybe_put_google_options(config)
      |> URI.encode_query()

    config.authorization_endpoint <> "?" <> query
  end

  defp maybe_put_google_options(params, %{provider: "google"}) do
    params
    |> Map.put("include_granted_scopes", "true")
  end

  defp maybe_put_google_options(params, _config), do: params

  defp maybe_put_oidc_nonce(params, %{provider: "google"}, oauth_state),
    do: Map.put(params, "nonce", oauth_state.nonce)

  defp maybe_put_oidc_nonce(params, _config, _oauth_state), do: params

  defp consume_state(provider, state, redirect_uri) do
    now = DateTime.utc_now()

    state_record =
      from(s in OAuthState,
        where:
          s.provider == ^provider and s.state_hash == ^state_hash(state) and
            s.redirect_uri == ^redirect_uri and is_nil(s.consumed_at) and s.expires_at > ^now
      )
      |> Repo.one()

    case state_record do
      nil ->
        {:error, :invalid_oauth_state}

      %OAuthState{} = oauth_state ->
        case mark_state_consumed(oauth_state.id, now) do
          1 -> {:ok, oauth_state}
          _ -> {:error, :invalid_oauth_state}
        end
    end
  end

  defp mark_state_consumed(id, now) do
    from(s in OAuthState, where: s.id == ^id and is_nil(s.consumed_at))
    |> Repo.update_all(set: [consumed_at: now])
    |> elem(0)
  end

  defp exchange_code(config, code, code_verifier, redirect_uri, request_fun) do
    dpop = maybe_dpop_key(config)

    form =
      %{
        "client_id" => config.client_id,
        "code" => code,
        "code_verifier" => code_verifier,
        "grant_type" => "authorization_code",
        "redirect_uri" => redirect_uri
      }
      |> maybe_put_form_value("client_secret", Map.get(config, :client_secret))

    headers = token_headers(config, dpop, code)

    case post_form(config.token_endpoint, form, headers, request_fun) do
      {:ok, status, response_headers, body} when status in 200..299 ->
        decode_token_response(body, dpop, response_headers)

      {:ok, status, response_headers, body} ->
        retry_exchange_with_dpop_nonce(
          config,
          form,
          dpop,
          code,
          response_headers,
          request_fun,
          {status, body}
        )

      {:error, reason} ->
        {:error, token_exchange_request_failure(config, reason)}
    end
  end

  defp maybe_put_form_value(form, _key, value) when value in [nil, ""], do: form
  defp maybe_put_form_value(form, key, value), do: Map.put(form, key, value)

  defp retry_exchange_with_dpop_nonce(
         config,
         _form,
         nil,
         _code,
         _headers,
         _request_fun,
         failure
       ) do
    {:error, token_exchange_failure(config, failure, "non_success")}
  end

  defp retry_exchange_with_dpop_nonce(config, form, dpop, code, headers, request_fun, failure) do
    {status, body} = failure

    with "use_dpop_nonce" <- provider_error_code(body),
         nonce when is_binary(nonce) <- response_header(headers, "dpop-nonce") do
      headers = token_headers(config, %{dpop | nonce: nonce}, code)

      case post_form(config.token_endpoint, form, headers, request_fun) do
        {:ok, status, _response_headers, body} when status in 200..299 ->
          decode_token_response(body, %{dpop | nonce: nonce})

        {:ok, status, _response_headers, body} ->
          {:error, token_exchange_failure(config, {status, body}, "dpop_nonce_retry_failed")}

        {:error, reason} ->
          {:error, token_exchange_request_failure(config, reason)}
      end
    else
      "use_dpop_nonce" ->
        {:error, token_exchange_failure(config, {status, body}, "use_dpop_nonce_without_header")}

      _ ->
        {:error, token_exchange_failure(config, failure, "non_success")}
    end
  end

  defp oauth_provider_config_error(provider, missing) do
    {:oauth_provider_not_configured, %{provider: provider, missing: missing}}
  end

  defp token_exchange_failure(config, {status, body}, reason) do
    provider_error = provider_error_details(body)

    Logger.warning(
      "OAuth token exchange failed provider=#{config.provider} status=#{status} reason=#{reason} provider_error=#{inspect(provider_error)}"
    )

    {:oauth_token_exchange_failed,
     %{
       provider: config.provider,
       status: status,
       reason: reason,
       provider_error: provider_error
     }}
  end

  defp token_exchange_request_failure(config, reason) do
    Logger.warning(
      "OAuth token exchange request failed provider=#{config.provider} reason=#{inspect(reason)}"
    )

    {:oauth_token_exchange_failed,
     %{
       provider: config.provider,
       reason: inspect(reason)
     }}
  end

  defp provider_error_details(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, decoded} when is_map(decoded) ->
        decoded
        |> Map.take(["error", "error_description", "error_uri"])
        |> Enum.map(fn {key, value} -> {key, truncate_log_value(value)} end)
        |> Enum.into(%{})

      _ ->
        %{"body" => "<non_json>"}
    end
  end

  defp provider_error_details(_body), do: %{"body" => "<non_binary>"}

  defp provider_error_code(body) when is_binary(body) do
    case Jason.decode(body) do
      {:ok, %{"error" => error}} when is_binary(error) -> error
      _ -> nil
    end
  end

  defp provider_error_code(_body), do: nil

  defp truncate_log_value(value) when is_binary(value) and byte_size(value) > 300 do
    binary_part(value, 0, 300) <> "..."
  end

  defp truncate_log_value(value), do: value

  defp token_headers(config, dpop, code) do
    [{"accept", "application/json"}]
    |> maybe_put_dpop_header(
      "POST",
      config.token_endpoint,
      nil,
      dpop,
      authorization_code_jti(code)
    )
  end

  defp decode_token_response(body, dpop, headers \\ []) do
    dpop = maybe_update_dpop_nonce(dpop, headers)

    case Jason.decode(body) do
      {:ok, %{"access_token" => access_token} = token} when is_binary(access_token) ->
        {:ok, %{access_token: access_token, token: token, dpop: dpop}}

      _ ->
        {:error, :oauth_token_exchange_failed}
    end
  end

  defp verify_oauth_nonce(%{provider: "google"}, %{nonce: nonce}, %{token: token})
       when is_binary(nonce) do
    with %{"id_token" => id_token} when is_binary(id_token) <- token,
         {:ok, %{"nonce" => ^nonce}} <- decode_jwt_payload(id_token) do
      :ok
    else
      _ -> {:error, :invalid_oauth_nonce}
    end
  end

  defp verify_oauth_nonce(%{provider: "google"}, _oauth_state, _token_result),
    do: {:error, :invalid_oauth_nonce}

  defp verify_oauth_nonce(_config, _oauth_state, _token_result), do: :ok

  defp decode_jwt_payload(jwt) when is_binary(jwt) do
    case String.split(jwt, ".", parts: 3) do
      [_header, payload, _signature] ->
        with {:ok, payload_json} <- Base.url_decode64(payload, padding: false),
             {:ok, claims} when is_map(claims) <- Jason.decode(payload_json) do
          {:ok, claims}
        else
          _ -> {:error, :invalid_jwt}
        end

      _ ->
        {:error, :invalid_jwt}
    end
  end

  defp maybe_update_dpop_nonce(nil, _headers), do: nil

  defp maybe_update_dpop_nonce(dpop, headers) do
    case response_header(headers, "dpop-nonce") do
      nil -> dpop
      nonce -> %{dpop | nonce: nonce}
    end
  end

  defp fetch_identity(%{provider: "google"} = config, token_result, request_fun) do
    headers =
      [{"authorization", authorization_header(token_result)}]
      |> maybe_put_resource_dpop_header("GET", config.userinfo_endpoint, token_result)

    with {:ok, status, _headers, body} when status in 200..299 <-
           request_fun.(:get, config.userinfo_endpoint, headers, ""),
         {:ok, info} <- Jason.decode(body),
         {:ok, subject} <- required_binary(info, "sub"),
         {:ok, email} <- verified_email(info),
         name <- Map.get(info, "name") || email_name(email) do
      {:ok,
       %{
         provider: "google",
         provider_user_id: subject,
         email: email,
         name: name
       }}
    else
      _ -> {:error, :oauth_userinfo_failed}
    end
  end

  defp fetch_identity(%{provider: "github"} = config, token_result, request_fun) do
    headers = [
      {"accept", "application/vnd.github+json"},
      {"authorization", "Bearer " <> token_result.access_token},
      {"user-agent", "RefMD"}
    ]

    with {:ok, status, _headers, body} when status in 200..299 <-
           request_fun.(:get, config.userinfo_endpoint, headers, ""),
         {:ok, user_info} <- Jason.decode(body),
         {:ok, provider_user_id} <- github_id(user_info),
         {:ok, email} <- github_email(config, headers, request_fun),
         name <- Map.get(user_info, "name") || Map.get(user_info, "login") || email_name(email) do
      {:ok,
       %{
         provider: "github",
         provider_user_id: provider_user_id,
         email: email,
         name: name
       }}
    else
      _ -> {:error, :oauth_userinfo_failed}
    end
  end

  defp github_email(config, headers, request_fun) do
    with {:ok, status, _headers, body} when status in 200..299 <-
           request_fun.(:get, config.emails_endpoint, headers, ""),
         {:ok, emails} when is_list(emails) <- Jason.decode(body),
         %{"email" => email} <-
           Enum.find(emails, fn email ->
             email["primary"] == true and email["verified"] == true and is_binary(email["email"])
           end) do
      {:ok, String.downcase(email)}
    else
      _ -> {:error, :oauth_email_unverified}
    end
  end

  defp complete_by_purpose(%{purpose: @login_purpose} = oauth_state, identity, _session_context) do
    with {:ok, user} <- find_or_create_user(identity) do
      {:ok, %{purpose: @login_purpose, user: user, return_to: oauth_state.return_to}}
    end
  end

  defp complete_by_purpose(
         %{purpose: @account_link_purpose} = oauth_state,
         identity,
         session_context
       ) do
    with {:ok, user_id} <- validate_account_link_context(oauth_state, session_context),
         {:ok, user} <- link_external_account(user_id, identity) do
      {:ok, %{purpose: @account_link_purpose, user: user, return_to: oauth_state.return_to}}
    end
  end

  defp complete_by_purpose(_oauth_state, _identity, _session_context),
    do: {:error, :invalid_oauth_state}

  defp validate_account_link_context(
         %{user_id: user_id, session_id_hash: session_id_hash},
         %{user_id: user_id, session_id: session_id}
       )
       when is_binary(user_id) and is_binary(session_id) and is_binary(session_id_hash) do
    if session_id_hash(session_id) == session_id_hash do
      {:ok, user_id}
    else
      {:error, :invalid_oauth_state}
    end
  end

  defp validate_account_link_context(_oauth_state, _session_context),
    do: {:error, :invalid_oauth_state}

  defp find_or_create_user(identity) do
    Repo.transaction(fn ->
      case Users.get_user_external_account(identity.provider, identity.provider_user_id) do
        %{user_id: user_id} = _external_account ->
          Users.get_user(user_id) || Repo.rollback(:oauth_user_missing)

        nil ->
          create_unlinked_oauth_user!(identity)
      end
    end)
  end

  defp link_external_account(user_id, identity) do
    Repo.transaction(fn ->
      cond do
        Users.get_user(user_id) == nil ->
          Repo.rollback(:oauth_user_missing)

        Users.get_user_external_account_for_user(user_id, identity.provider) != nil ->
          Repo.rollback(:oauth_external_account_conflict)

        provider_identity_linked_to_another_user?(user_id, identity) ->
          Repo.rollback(:oauth_external_account_conflict)

        true ->
          create_external_account!(user_id, identity)
          Users.get_user(user_id)
      end
    end)
  end

  defp provider_identity_linked_to_another_user?(user_id, identity) do
    case Users.get_user_external_account(identity.provider, identity.provider_user_id) do
      nil -> false
      %{user_id: ^user_id} -> false
      %{user_id: _other_user_id} -> true
    end
  end

  defp create_unlinked_oauth_user!(identity) do
    case Users.get_user_by_email(identity.email) do
      nil -> create_oauth_user!(identity)
      %RefMD.Users.User{} -> Repo.rollback(:oauth_account_link_required)
    end
  end

  defp create_oauth_user!(identity) do
    with {:ok, user} <-
           Users.create_user(%{
             email: identity.email,
             name: identity.name || email_name(identity.email),
             account_type: "registered"
           }),
         {:ok, _settings} <- Users.create_user_settings(user.id),
         {:ok, _workspace} <-
           RefMD.Workspaces.create_default_workspace(user.id, "#{user.name || "My"}'s Workspace") do
      create_external_account!(user.id, identity)
      user
    else
      {:error, %Ecto.Changeset{} = changeset} ->
        Repo.rollback(oauth_user_creation_error(changeset))

      {:error, reason} ->
        Repo.rollback(reason)
    end
  end

  defp oauth_user_creation_error(%Ecto.Changeset{errors: errors}) do
    if Keyword.has_key?(errors, :email) do
      :oauth_account_link_required
    else
      :oauth_user_creation_failed
    end
  end

  defp create_external_account!(user_id, identity) do
    case Users.create_user_external_account(%{
           user_id: user_id,
           provider: identity.provider,
           provider_user_id: identity.provider_user_id,
           email: identity.email
         }) do
      {:ok, account} -> account
      {:error, _changeset} -> Repo.rollback(:oauth_external_account_conflict)
    end
  end

  defp post_form(url, form, headers, request_fun) do
    body = URI.encode_query(form)

    request_fun.(:post, url, headers, body)
  end

  defp maybe_dpop_key(%{provider_dpop: true}), do: new_dpop_key()
  defp maybe_dpop_key(_config), do: nil

  defp maybe_put_dpop_header(headers, method, url, access_token, dpop) do
    maybe_put_dpop_header(headers, method, url, access_token, dpop, nil)
  end

  defp maybe_put_dpop_header(headers, _method, _url, _access_token, nil, _jti), do: headers

  defp maybe_put_dpop_header(headers, method, url, access_token, dpop, jti) do
    [{"dpop", dpop_proof(method, url, access_token, dpop, jti)} | headers]
  end

  defp maybe_put_resource_dpop_header(headers, method, url, %{
         access_token: access_token,
         dpop: dpop,
         token: %{"token_type" => token_type}
       })
       when is_binary(token_type) do
    if String.downcase(token_type) == "dpop" do
      maybe_put_dpop_header(headers, method, url, access_token, dpop)
    else
      headers
    end
  end

  defp maybe_put_resource_dpop_header(headers, _method, _url, _token_result), do: headers

  defp authorization_header(%{access_token: access_token, token: %{"token_type" => token_type}})
       when is_binary(token_type) do
    scheme = if String.downcase(token_type) == "dpop", do: "DPoP", else: "Bearer"
    scheme <> " " <> access_token
  end

  defp authorization_header(%{access_token: access_token}), do: "Bearer " <> access_token

  defp new_dpop_key do
    {public_key, private_key} = :crypto.generate_key(:ecdh, :prime256v1)
    <<4, x::binary-size(32), y::binary-size(32)>> = public_key

    %{
      public_key: public_key,
      private_key: private_key,
      jwk: %{
        "crv" => "P-256",
        "kty" => "EC",
        "x" => Base.url_encode64(x, padding: false),
        "y" => Base.url_encode64(y, padding: false)
      },
      nonce: nil
    }
  end

  defp dpop_proof(method, url, access_token, dpop, jti) do
    header = %{"alg" => "ES256", "typ" => "dpop+jwt", "jwk" => dpop.jwk}

    payload =
      %{
        "htm" => method,
        "htu" => url,
        "iat" => System.system_time(:second),
        "jti" => jti || random_base64url(16)
      }
      |> maybe_put("ath", access_token_hash(access_token))
      |> maybe_put("nonce", dpop.nonce)

    signing_input =
      base64url_json(header) <> "." <> base64url_json(payload)

    signature =
      :ecdsa
      |> :crypto.sign(:sha256, signing_input, [dpop.private_key, :prime256v1])
      |> der_ecdsa_to_raw()
      |> Base.url_encode64(padding: false)

    signing_input <> "." <> signature
  end

  defp authorization_code_jti(code),
    do: :sha256 |> :crypto.hash(code) |> Base.url_encode64(padding: false)

  defp der_ecdsa_to_raw(<<0x30, _len, 0x02, r_len, rest::binary>>) do
    r = binary_part(rest, 0, r_len)
    rest = binary_part(rest, r_len, byte_size(rest) - r_len)
    <<0x02, s_len, s::binary-size(s_len)>> = rest
    pad_integer(r) <> pad_integer(s)
  end

  defp pad_integer(value) do
    value = value |> :binary.bin_to_list() |> Enum.drop_while(&(&1 == 0)) |> :binary.list_to_bin()

    cond do
      byte_size(value) > 32 -> binary_part(value, byte_size(value) - 32, 32)
      byte_size(value) < 32 -> :binary.copy(<<0>>, 32 - byte_size(value)) <> value
      true -> value
    end
  end

  defp access_token_hash(nil), do: nil

  defp access_token_hash(access_token),
    do: :sha256 |> :crypto.hash(access_token) |> Base.url_encode64(padding: false)

  defp base64url_json(value), do: value |> Jason.encode!() |> Base.url_encode64(padding: false)

  defp pkce_challenge(verifier),
    do: :sha256 |> :crypto.hash(verifier) |> Base.url_encode64(padding: false)

  defp state_hash(state), do: :crypto.hash(:sha256, state)

  defp session_id_hash(nil), do: nil
  defp session_id_hash(session_id), do: Hash.blake3_base64url(session_id)

  defp random_base64url(bytes),
    do: bytes |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

  defp verified_email(%{"email" => email, "email_verified" => true}) when is_binary(email),
    do: {:ok, String.downcase(email)}

  defp verified_email(_), do: {:error, :oauth_email_unverified}

  defp required_binary(map, key) do
    case Map.get(map, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      _ -> {:error, :missing_field}
    end
  end

  defp github_id(%{"id" => id}) when is_integer(id), do: {:ok, Integer.to_string(id)}
  defp github_id(%{"id" => id}) when is_binary(id) and id != "", do: {:ok, id}
  defp github_id(_), do: {:error, :missing_field}

  defp email_name(email) do
    email
    |> String.split("@", parts: 2)
    |> List.first()
    |> case do
      "" -> "OAuth User"
      nil -> "OAuth User"
      name -> name
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp response_header(headers, name) do
    Enum.find_value(headers, fn {header, value} ->
      if String.downcase(to_string(header)) == name, do: to_string(value)
    end)
  end

  defp provider_key!("google"), do: :google
  defp provider_key!("github"), do: :github

  defp http_request(method, url, headers, body) do
    with :ok <- ensure_http_clients_started() do
      method
      |> :httpc.request(http_request_tuple(method, url, headers, body), http_options(url),
        body_format: :binary
      )
      |> normalize_http_response()
    end
  end

  defp http_request_tuple(:post, url, headers, body) do
    {String.to_charlist(url), charlist_headers(headers), ~c"application/x-www-form-urlencoded",
     body}
  end

  defp http_request_tuple(:get, url, headers, _body) do
    {String.to_charlist(url), charlist_headers(headers)}
  end

  defp http_options(url) do
    case URI.parse(url) do
      %URI{scheme: "https"} ->
        [
          ssl: [
            verify: :verify_peer,
            cacerts: :public_key.cacerts_get(),
            customize_hostname_check: [
              match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
            ]
          ]
        ]

      _ ->
        []
    end
  end

  defp charlist_headers(headers) do
    Enum.map(headers, fn {name, value} ->
      {String.to_charlist(name), String.to_charlist(value)}
    end)
  end

  defp normalize_http_response({:ok, {{_version, status, _reason}, headers, body}}) do
    {:ok, status, normalize_response_headers(headers), body || ""}
  end

  defp normalize_http_response({:error, _reason}), do: {:error, :oauth_provider_unavailable}

  defp normalize_response_headers(headers) do
    Enum.map(headers, fn {name, value} -> {to_string(name), to_string(value)} end)
  end

  defp ensure_http_clients_started do
    with :ok <- ensure_started(:ssl) do
      ensure_started(:inets)
    end
  end

  defp ensure_started(app) do
    case Application.ensure_all_started(app) do
      {:ok, _apps} -> :ok
      {:error, {:already_started, ^app}} -> :ok
      {:error, _reason} -> {:error, :oauth_provider_unavailable}
    end
  end

  defp blank?(value), do: not (is_binary(value) and String.trim(value) != "")
end
