defmodule RefMDWeb.PluginNetworkExecutorController do
  use RefMDWeb, :controller

  import Ecto.Query

  alias RefMD.Plugins

  alias RefMD.Plugins.{
    NetworkProxyRegistration,
    PluginActivation,
    PluginApplication,
    PluginBundle,
    PluginConsentEvent
  }

  alias RefMD.Repo
  alias RefMD.Security.AuditEvent
  alias RefMD.Users
  alias RefMD.Workspaces

  @session_salt "plugin-network-executor-session-v1"
  @session_max_age_seconds 60
  @max_executor_request_bytes 1_048_576
  @session_protocol "refmd.plugin-network-executor-session"
  @forbidden_request_headers ~w(
    accept-charset accept-encoding access-control-request-headers access-control-request-method
    connection content-length cookie cookie2 date dnt expect host keep-alive origin permissions-policy
    referer sec-fetch-dest sec-fetch-mode sec-fetch-site sec-fetch-user te trailer transfer-encoding
    upgrade via
  )

  @executor_script """
  (() => {
    const protocol = "refmd.plugin-network-executor";
    let used = false;
    const policy = JSON.parse(document.documentElement.dataset.executorPolicy || "{}");
    const targetOrigin = policy.target_origin;
    const targetUrl = policy.target_url;
    const executorToken = policy.executor_token;
    const method = policy.method;
    const route = policy.route;
    const bodySchema = policy.body_schema;
    const maxRequestBytes = policy.max_request_bytes;
    const headerNames = new Set(policy.header_names || []);
    const textEncoder = new TextEncoder();
    const headerEntries = (headers) => {
      const entries = [];
      headers.forEach((value, key) => {
        if (key !== "set-cookie" && key !== "set-cookie2") entries.push([key, value]);
      });
      return entries;
    };
    const requestHeaders = (headers) => {
      if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
        throw new Error("network executor headers invalid");
      }
      const normalized = {};
      for (const [name, value] of Object.entries(headers)) {
        const normalizedName = name.toLowerCase();
        if (!headerNames.has(normalizedName)) {
          throw new Error("network executor header policy mismatch");
        }
        if (typeof value !== "string") {
          throw new Error("network executor header value invalid");
        }
        normalized[normalizedName] = value;
      }
      if (Object.keys(normalized).length !== headerNames.size) {
        throw new Error("network executor header policy mismatch");
      }
      return normalized;
    };
    const requestBody = (body) => {
      if (body == null) return null;
      if (bodySchema === "none") throw new Error("network executor body forbidden");
      if (typeof body !== "string") throw new Error("network executor body invalid");
      if (textEncoder.encode(body).byteLength > maxRequestBytes) {
        throw new Error("network executor body too large");
      }
      return body;
    };
    window.addEventListener("message", (event) => {
      if (used || event.origin !== window.location.origin) return;
       const port = event.ports && event.ports[0];
       const request = event.data;
       if (!port || !request || request.protocol !== protocol || request.kind !== "execute") return;
       used = true;
       (async () => {
         try {
           if (!executorToken || request.executorToken !== executorToken) {
             throw new Error("network executor token mismatch");
           }
           if (request.route !== route) {
             throw new Error("network executor route mismatch");
           }
           if (request.method !== method) {
             throw new Error("network executor method mismatch");
           }
           const url = new URL(request.url);
          if (url.origin !== targetOrigin || url.toString() !== targetUrl) {
            throw new Error("network target policy mismatch");
          }
          const headers = requestHeaders(request.headers);
          const body = requestBody(request.body);
          const response = await fetch(url.toString(), {
            method,
            headers,
            body,
            mode: "cors",
            credentials: "omit",
            redirect: "manual"
          });
          port.postMessage({
            protocol,
            requestId: request.requestId,
            ok: true,
            status: response.status,
            headers: headerEntries(response.headers),
            bodyText: await response.text()
          });
        } catch (error) {
          port.postMessage({
            protocol,
            requestId: request && request.requestId,
            ok: false,
            message: error instanceof Error ? error.message : "network request failed"
          });
        } finally {
          port.close();
        }
      })();
    });
  })();
  """
  @script_hash :crypto.hash(:sha256, @executor_script) |> Base.encode64()

  @spec show(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def show(conn, %{"session_token" => session_token}) do
    with {:ok, policy} <- verify_session_token(session_token),
         {:ok, policy} <- canonical_session_policy(policy) do
      conn
      |> Plug.Conn.delete_resp_header("x-frame-options")
      |> put_resp_header("content-security-policy", executor_csp(policy["target_origin"]))
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_content_type("text/html")
      |> send_resp(200, executor_document(policy))
    else
      {:error, _reason} ->
        send_resp(conn, 400, "Bad Request")
    end
  end

  def show(conn, _params), do: send_resp(conn, 400, "Bad Request")

  @spec create_session(Plug.Conn.t(), map()) :: Plug.Conn.t()
  def create_session(conn, params) do
    user_id = conn.assigns.current_user_id
    device_id = conn.assigns.current_session.device_id

    with true <- is_binary(device_id),
         {:ok, policy} <- canonical_session_policy(params, [RefMD.AppOrigin.conn_origin(conn)]),
         :ok <- validate_runtime_bound_policy(policy, params, user_id, device_id),
         token <- Phoenix.Token.sign(RefMDWeb.Endpoint, @session_salt, policy) do
      json(conn, %{session_token: token})
    else
      false ->
        send_resp(conn, 403, "Forbidden")

      {:error, _reason} ->
        send_resp(conn, 400, "Bad Request")
    end
  end

  defp executor_document(policy) do
    escaped_policy = policy |> Jason.encode!() |> html_escape()

    """
    <!doctype html>
    <html data-executor-policy="#{escaped_policy}">
    <head><meta charset="utf-8"><title>Plugin network executor</title></head>
    <body><script>#{@executor_script}</script></body>
    </html>
    """
  end

  defp html_escape(value) do
    value
    |> String.replace("&", "&amp;")
    |> String.replace("\"", "&quot;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
  end

  defp verify_session_token(token) when is_binary(token) do
    Phoenix.Token.verify(RefMDWeb.Endpoint, @session_salt, token,
      max_age: @session_max_age_seconds
    )
  end

  defp verify_session_token(_token), do: {:error, :invalid_session_token}

  defp canonical_session_policy(params, extra_app_origins \\ [])

  defp canonical_session_policy(params, extra_app_origins) when is_map(params) do
    with {:ok, token} <- canonical_executor_token(Map.get(params, "executor_token")),
         {:ok, url, origin} <-
           canonical_target_url(Map.get(params, "target_url"), extra_app_origins),
         {:ok, route} <- canonical_route(Map.get(params, "route")),
         {:ok, method} <- canonical_method(Map.get(params, "method")),
         {:ok, header_names} <- canonical_header_names(Map.get(params, "header_names")),
         {:ok, body_schema} <- canonical_body_schema(Map.get(params, "body_schema")),
         {:ok, network_url, network_origin} <-
           canonical_network_target_url(
             Map.get(params, "network_target_url"),
             url,
             extra_app_origins
           ),
         {:ok, proxy_id} <- canonical_optional_string(Map.get(params, "proxy_id")),
         {:ok, network_method} <-
           canonical_method(Map.get(params, "network_method") || method),
         {:ok, network_header_names} <-
           canonical_header_names(Map.get(params, "network_header_names") || header_names),
         {:ok, network_body_schema} <-
           canonical_body_schema(Map.get(params, "network_body_schema") || body_schema),
         {:ok, max_request_bytes} <-
           canonical_max_request_bytes(Map.get(params, "max_request_bytes")),
         {:ok, max_response_bytes} <-
           canonical_max_response_bytes(Map.get(params, "max_response_bytes")),
         {:ok, request_bytes} <- canonical_request_bytes(Map.get(params, "request_bytes")),
         :ok <- validate_target_origin(Map.get(params, "target_origin"), origin),
         {:ok, runtime} <- canonical_runtime_binding(params) do
      {:ok,
       %{
         "protocol" => @session_protocol,
         "version" => 1,
         "executor_token" => token,
         "target_origin" => origin,
         "target_url" => url,
         "network_target_origin" => network_origin,
         "network_target_url" => network_url,
         "route" => route,
         "proxy_id" => proxy_id,
         "method" => method,
         "network_method" => network_method,
         "header_names" => header_names,
         "network_header_names" => network_header_names,
         "body_schema" => body_schema,
         "network_body_schema" => network_body_schema,
         "max_request_bytes" => max_request_bytes,
         "max_response_bytes" => max_response_bytes,
         "request_bytes" => request_bytes,
         "runtime" => runtime
       }}
    end
  end

  defp canonical_session_policy(_params, _extra_app_origins),
    do: {:error, :invalid_session_policy}

  defp canonical_runtime_binding(params) do
    params =
      if is_map(Map.get(params, "runtime")), do: Map.fetch!(params, "runtime"), else: params

    with {:ok, workspace_id} <- canonical_non_empty_string(Map.get(params, "workspace_id")),
         {:ok, plugin_id} <- canonical_non_empty_string(Map.get(params, "plugin_id")),
         {:ok, package_id} <- canonical_non_empty_string(Map.get(params, "package_id")),
         {:ok, application_id} <- canonical_non_empty_string(Map.get(params, "application_id")),
         {:ok, activation_id} <- canonical_non_empty_string(Map.get(params, "activation_id")),
         {:ok, owner_scope_kind} <-
           canonical_owner_scope_kind(Map.get(params, "owner_scope_kind")),
         {:ok, user_id} <- canonical_non_empty_string(Map.get(params, "user_id")),
         {:ok, device_id} <- canonical_non_empty_string(Map.get(params, "device_id")),
         {:ok, endpoint_id} <- canonical_non_empty_string(Map.get(params, "endpoint_id")),
         {:ok, state_head_hash} <- canonical_non_empty_string(Map.get(params, "state_head_hash")),
         {:ok, consent_head_hash} <-
           canonical_non_empty_string(Map.get(params, "consent_head_hash")),
         {:ok, bundle_hash} <- canonical_non_empty_string(Map.get(params, "bundle_hash")),
         {:ok, manifest_hash} <- canonical_non_empty_string(Map.get(params, "manifest_hash")),
         {:ok, consent_epoch} <- canonical_positive_integer(Map.get(params, "consent_epoch")),
         {:ok, frame_generation} <-
           canonical_positive_integer(Map.get(params, "frame_generation")),
         {:ok, capability_grant_id} <-
           canonical_non_empty_string(Map.get(params, "capability_grant_id")),
         {:ok, request_id} <- canonical_non_empty_string(Map.get(params, "request_id")),
         {:ok, credential_audience} <-
           canonical_optional_string(Map.get(params, "credential_audience")),
         {:ok, credential_handle_used} <-
           canonical_boolean(Map.get(params, "credential_handle_used")) do
      {:ok,
       %{
         "workspace_id" => workspace_id,
         "plugin_id" => plugin_id,
         "package_id" => package_id,
         "application_id" => application_id,
         "activation_id" => activation_id,
         "owner_scope_kind" => owner_scope_kind,
         "user_id" => user_id,
         "device_id" => device_id,
         "endpoint_id" => endpoint_id,
         "state_head_hash" => state_head_hash,
         "consent_head_hash" => consent_head_hash,
         "bundle_hash" => bundle_hash,
         "manifest_hash" => manifest_hash,
         "consent_epoch" => consent_epoch,
         "frame_generation" => frame_generation,
         "capability_grant_id" => capability_grant_id,
         "request_id" => request_id,
         "credential_audience" => credential_audience,
         "credential_handle_used" => credential_handle_used
       }}
    end
  end

  defp canonical_non_empty_string(value) when is_binary(value) do
    if String.trim(value) == "", do: {:error, :empty_runtime_binding}, else: {:ok, value}
  end

  defp canonical_non_empty_string(_value), do: {:error, :invalid_runtime_binding}

  defp canonical_owner_scope_kind(value) when value in ["workspace", "user"], do: {:ok, value}
  defp canonical_owner_scope_kind(_value), do: {:error, :invalid_runtime_binding}

  defp canonical_optional_string(nil), do: {:ok, nil}

  defp canonical_optional_string(value) when is_binary(value) do
    if String.trim(value) == "", do: {:error, :invalid_runtime_binding}, else: {:ok, value}
  end

  defp canonical_optional_string(_value), do: {:error, :invalid_runtime_binding}

  defp canonical_positive_integer(value) when is_integer(value) and value > 0, do: {:ok, value}

  defp canonical_positive_integer(_value), do: {:error, :invalid_runtime_binding}

  defp canonical_boolean(value) when is_boolean(value), do: {:ok, value}
  defp canonical_boolean(_value), do: {:error, :invalid_runtime_binding}

  defp validate_runtime_bound_policy(policy, params, user_id, device_id) do
    runtime = Map.fetch!(policy, "runtime")
    application_id = runtime["application_id"]

    with %PluginApplication{} = application <- Repo.get(PluginApplication, application_id),
         true <- runtime["workspace_id"] == application.workspace_id,
         true <- runtime["package_id"] == application.package_id,
         true <- runtime["plugin_id"] == application.plugin_id,
         true <- runtime["user_id"] == user_id,
         true <- runtime["device_id"] == device_id,
         {:ok, %PluginBundle{} = bundle} <-
           Plugins.current_bundle_with_pin(application.id, runtime["state_head_hash"]),
         true <- runtime["bundle_hash"] == bundle.bundle_hash,
         true <- runtime["manifest_hash"] == bundle.manifest_hash,
         {:ok, %PluginConsentEvent{} = consent} <-
           Plugins.allowed_consent_with_pin(
             application.id,
             user_id,
             device_id,
             runtime["consent_head_hash"]
           ),
         true <- runtime["activation_id"] == consent.activation_id,
         true <- runtime["owner_scope_kind"] == consent.owner_scope_kind,
         true <- runtime["consent_epoch"] == consent.consent_epoch,
         %PluginActivation{} = activation <- Repo.get(PluginActivation, runtime["activation_id"]),
         true <- activation.application_id == application.id,
         true <- activation.user_id == user_id,
         true <- activation.device_id == device_id or is_nil(activation.device_id),
         true <- activation.enabled == true,
         true <- is_nil(activation.deleted_at),
         true <-
           Plugins.current_sandbox_document_frame?(%{
             workspace_id: application.workspace_id,
             package_id: application.package_id,
             application_id: application.id,
             activation_id: activation.id,
             owner_scope_kind: runtime["owner_scope_kind"],
             user_id: user_id,
             device_id: device_id,
             state_head_hash: runtime["state_head_hash"],
             consent_head_hash: runtime["consent_head_hash"],
             consent_epoch: runtime["consent_epoch"],
             capability_grant_id: runtime["capability_grant_id"],
             frame_generation: runtime["frame_generation"]
           }),
         {:ok, endpoint} <- declared_network_endpoint(bundle, runtime["endpoint_id"]),
         :ok <-
           validate_proxy_registration_policy(policy, application.workspace_id, user_id, endpoint),
         :ok <- validate_endpoint_policy(policy, endpoint, runtime),
         :ok <- validate_network_audit(application, policy, params, runtime, user_id, device_id) do
      :ok
    else
      _ -> {:error, :network_executor_session_forbidden}
    end
  end

  defp declared_network_endpoint(
         %PluginBundle{manifest_json: %{"network" => %{"endpoints" => endpoints}}},
         endpoint_id
       )
       when is_list(endpoints) do
    case Enum.find(endpoints, &(is_map(&1) and Map.get(&1, "id") == endpoint_id)) do
      nil -> {:error, :network_endpoint_unknown}
      endpoint -> {:ok, endpoint}
    end
  end

  defp declared_network_endpoint(_bundle, _endpoint_id), do: {:error, :network_endpoint_unknown}

  defp validate_proxy_registration_policy(
         %{"route" => "proxy", "proxy_id" => proxy_id} = policy,
         workspace_id,
         user_id,
         endpoint
       )
       when is_binary(proxy_id) do
    with {:ok, proxy} <- effective_proxy_registration(workspace_id, user_id),
         true <- proxy["id"] == proxy_id,
         :ok <- validate_proxy_allowed_scope(proxy, workspace_id, user_id),
         {:ok, base_url, base_origin} <- canonical_target_url(proxy["base_url"]),
         true <- policy["target_url"] == base_url,
         true <- policy["target_origin"] == base_origin,
         :ok <- validate_proxy_execution_policy(proxy["policy"] || %{}, policy, endpoint) do
      :ok
    else
      _ -> {:error, :network_executor_proxy_forbidden}
    end
  end

  defp validate_proxy_registration_policy(
         %{"route" => "proxy"},
         _workspace_id,
         _user_id,
         _endpoint
       ),
       do: {:error, :network_executor_proxy_forbidden}

  defp validate_proxy_execution_policy(proxy_policy, policy, endpoint)
       when is_map(proxy_policy) do
    endpoint_id = policy["runtime"]["endpoint_id"]

    with :ok <- validate_proxy_endpoint_allowed(proxy_policy, endpoint_id),
         :ok <- validate_proxy_route_allowed(proxy_policy, policy["route"]),
         :ok <- validate_proxy_request_size(proxy_policy, policy["request_bytes"]) do
      validate_proxy_response_size(proxy_policy, policy["max_response_bytes"], endpoint)
    end
  end

  defp validate_proxy_execution_policy(_proxy_policy, _policy, _endpoint),
    do: {:error, :network_executor_proxy_forbidden}

  defp validate_proxy_endpoint_allowed(proxy_policy, endpoint_id) do
    denied = policy_string_list(proxy_policy, "denied_endpoint_ids")
    allowed = policy_string_list(proxy_policy, "allowed_endpoint_ids")

    cond do
      endpoint_id in denied -> {:error, :network_executor_proxy_forbidden}
      allowed != [] and endpoint_id not in allowed -> {:error, :network_executor_proxy_forbidden}
      true -> :ok
    end
  end

  defp validate_proxy_route_allowed(proxy_policy, route) do
    case policy_string_list(proxy_policy, "allowed_route_classes") do
      [] -> :ok
      routes -> if(route in routes, do: :ok, else: {:error, :network_executor_proxy_forbidden})
    end
  end

  defp validate_proxy_request_size(proxy_policy, request_bytes) do
    case Map.get(proxy_policy, "max_request_size") do
      limit when is_integer(limit) and limit > 0 and request_bytes <= limit -> :ok
      limit when is_integer(limit) and limit > 0 -> {:error, :network_executor_proxy_forbidden}
      _ -> :ok
    end
  end

  defp validate_proxy_response_size(proxy_policy, max_response_bytes, endpoint) do
    if max_response_bytes <= endpoint_max_response_bytes(endpoint) do
      validate_proxy_response_size_limit(proxy_policy, max_response_bytes)
    else
      {:error, :network_executor_proxy_forbidden}
    end
  end

  defp validate_proxy_response_size_limit(proxy_policy, max_response_bytes) do
    case Map.get(proxy_policy, "max_response_size") do
      limit when is_integer(limit) and limit > 0 and max_response_bytes <= limit -> :ok
      limit when is_integer(limit) and limit > 0 -> {:error, :network_executor_proxy_forbidden}
      _ -> :ok
    end
  end

  defp policy_string_list(policy, key) do
    case Map.get(policy, key) do
      values when is_list(values) -> Enum.filter(values, &is_binary/1)
      _ -> []
    end
  end

  defp effective_proxy_registration(workspace_id, user_id) do
    [workspace_proxy_registration(workspace_id), user_proxy_registration(user_id)]
    |> Enum.find(&is_map/1)
    |> case do
      nil -> {:error, :network_proxy_unconfigured}
      proxy -> {:ok, proxy}
    end
  end

  defp workspace_proxy_registration(workspace_id) do
    case Workspaces.get_workspace(workspace_id) do
      %{plugin_network_proxy: proxy} -> enabled_proxy_registration(proxy, "workspace")
      _ -> nil
    end
  end

  defp user_proxy_registration(user_id) do
    case Users.get_user_settings(user_id) do
      %{plugin_network_proxy: proxy} -> enabled_proxy_registration(proxy, "user")
      _ -> nil
    end
  end

  defp enabled_proxy_registration(nil, _scope), do: nil

  defp enabled_proxy_registration(proxy, scope) do
    with {:ok, %{} = normalized} <- NetworkProxyRegistration.normalize(proxy, scope),
         true <- normalized["enabled"] != false,
         true <- normalized["revoked"] != true do
      normalized
    else
      _ -> nil
    end
  end

  defp validate_proxy_allowed_scope(proxy, workspace_id, user_id) do
    with true <- allowed_scope?(proxy["allowed_workspace_ids"], workspace_id),
         true <- allowed_scope?(proxy["allowed_user_ids"], user_id) do
      :ok
    else
      _ -> {:error, :network_executor_proxy_forbidden}
    end
  end

  defp allowed_scope?([], _id), do: true
  defp allowed_scope?(ids, id) when is_list(ids), do: id in ids
  defp allowed_scope?(_, _), do: false

  defp validate_endpoint_policy(policy, endpoint, runtime) do
    with true <- Map.get(endpoint, "url") == policy["network_target_url"],
         true <- policy["route"] in endpoint_strings(endpoint, "routes"),
         true <- executor_target_valid?(policy),
         true <-
           policy["network_method"] in Enum.map(
             endpoint_strings(endpoint, "methods"),
             &String.upcase/1
           ),
         :ok <- validate_endpoint_headers(policy["network_header_names"], endpoint),
         true <- policy["network_body_schema"] == endpoint_body_schema(endpoint),
         true <- network_request_bytes_valid?(policy, policy["request_bytes"], endpoint),
         true <- runtime["credential_audience"] == Map.get(endpoint, "credentialAudience"),
         true <- credential_handle_flag_valid?(runtime["credential_handle_used"], endpoint) do
      :ok
    else
      _ -> {:error, :network_executor_endpoint_forbidden}
    end
  end

  defp executor_target_valid?(%{"route" => "proxy"} = policy),
    do: policy["target_url"] != policy["network_target_url"]

  defp executor_target_valid?(_policy), do: false

  defp network_request_bytes_valid?(%{"route" => "proxy"}, request_bytes, endpoint)
       when is_integer(request_bytes) and request_bytes >= 0,
       do: request_bytes <= endpoint_max_request_bytes(endpoint)

  defp network_request_bytes_valid?(_policy, _request_bytes, _endpoint), do: false

  defp endpoint_strings(endpoint, key) do
    case Map.get(endpoint, key) do
      values when is_list(values) -> Enum.filter(values, &is_binary/1)
      _ -> []
    end
  end

  defp validate_endpoint_headers(header_names, endpoint) when is_list(header_names) do
    allowed =
      endpoint
      |> endpoint_header_names()
      |> MapSet.new()

    if Enum.all?(header_names, &MapSet.member?(allowed, &1)) do
      :ok
    else
      {:error, :network_executor_header_forbidden}
    end
  end

  defp endpoint_header_names(endpoint) do
    (Map.get(endpoint, "headers") || Map.get(endpoint, "allowedHeaders") || [])
    |> Enum.filter(&is_binary/1)
    |> Enum.map(&String.downcase/1)
  end

  defp endpoint_body_schema(endpoint) do
    case Map.get(endpoint, "bodySchema") do
      schema when schema in ["json", "text"] -> schema
      _ -> "none"
    end
  end

  defp endpoint_max_request_bytes(endpoint) do
    case Map.get(endpoint, "maxRequestBytes") do
      value when is_integer(value) and value > 0 -> min(value, @max_executor_request_bytes)
      _ -> 64 * 1024
    end
  end

  defp endpoint_max_response_bytes(endpoint) do
    case Map.get(endpoint, "maxResponseBytes") do
      value when is_integer(value) and value > 0 -> value
      _ -> 512 * 1024
    end
  end

  defp credential_handle_flag_valid?(false, _endpoint), do: true

  defp credential_handle_flag_valid?(true, endpoint),
    do: is_binary(Map.get(endpoint, "credentialAudience"))

  defp validate_network_audit(application, policy, params, runtime, user_id, device_id) do
    target_uri = URI.parse(policy["network_target_url"])
    request_bytes = request_body_bytes(Map.get(params, "request_bytes"))

    query =
      from(a in AuditEvent,
        where: a.type == "plugin.network.requested",
        where: fragment("?->>'user_id' = ?", a.actor, ^user_id),
        where: fragment("?->>'device_id' = ?", a.actor, ^device_id),
        where: fragment("?->>'workspace_id' = ?", a.scope, ^application.workspace_id),
        where: fragment("?->>'id' = ?", a.resource, ^runtime["endpoint_id"]),
        where: fragment("?->>'request_id' = ?", a.correlation, ^runtime["request_id"]),
        where:
          fragment(
            "?->>'capability_grant_id' = ?",
            a.correlation,
            ^runtime["capability_grant_id"]
          ),
        where:
          fragment(
            "(?->>'frame_generation')::integer = ?",
            a.correlation,
            ^runtime["frame_generation"]
          ),
        where: fragment("?->>'endpoint_id' = ?", a.action, ^runtime["endpoint_id"]),
        where: fragment("?->>'route' = ?", a.action, ^policy["route"]),
        where: fragment("?->>'method' = ?", a.action, ^policy["network_method"]),
        where: fragment("?->>'target_origin' = ?", a.action, ^policy["network_target_origin"]),
        where: fragment("?->>'target_path' = ?", a.action, ^target_uri.path),
        where: fragment("(?->>'request_bytes')::integer = ?", a.action, ^request_bytes),
        where:
          fragment(
            "(?->>'credential_handle_used')::boolean = ?",
            a.action,
            ^runtime["credential_handle_used"]
          ),
        limit: 1
      )

    query = bind_proxy_audit(query, policy)

    if Repo.exists?(query), do: :ok, else: {:error, :network_executor_audit_required}
  end

  defp bind_proxy_audit(query, %{"route" => "proxy", "proxy_id" => proxy_id})
       when is_binary(proxy_id) do
    from(a in query, where: fragment("?->>'proxy_id' = ?", a.action, ^proxy_id))
  end

  defp bind_proxy_audit(query, _policy), do: query

  defp request_body_bytes(value) when is_integer(value) and value >= 0, do: value
  defp request_body_bytes(_value), do: 0

  defp canonical_request_bytes(value) when is_integer(value) and value >= 0, do: {:ok, value}
  defp canonical_request_bytes(_value), do: {:ok, 0}

  defp executor_csp(origin) do
    [
      "default-src 'none'",
      "script-src 'sha256-#{@script_hash}'",
      "connect-src #{origin}",
      "frame-ancestors 'self'",
      "base-uri 'none'",
      "form-action 'none'",
      "object-src 'none'"
    ]
    |> Enum.join("; ")
  end

  defp canonical_target_url(raw_url, extra_app_origins \\ [])

  defp canonical_target_url(raw_url, extra_app_origins) when is_binary(raw_url) do
    case URI.parse(raw_url) do
      %URI{scheme: "https", host: host, fragment: nil} = uri when is_binary(host) ->
        origin = RefMD.AppOrigin.uri_origin(uri)
        url = URI.to_string(uri)

        cond do
          forbidden_host?(host) -> {:error, :forbidden_target}
          RefMD.AppOrigin.app_origin?(origin, extra_app_origins) -> {:error, :forbidden_target}
          url != raw_url -> {:error, :noncanonical_url}
          true -> {:ok, url, origin}
        end

      _ ->
        {:error, :invalid_url}
    end
  end

  defp canonical_target_url(_raw_url, _extra_app_origins), do: {:error, :invalid_url}

  defp canonical_network_target_url(nil, fallback_url, extra_app_origins),
    do: canonical_target_url(fallback_url, extra_app_origins)

  defp canonical_network_target_url(raw_url, _fallback_url, extra_app_origins),
    do: canonical_target_url(raw_url, extra_app_origins)

  defp validate_target_origin(nil, _origin), do: :ok
  defp validate_target_origin(origin, origin), do: :ok
  defp validate_target_origin(_origin, _canonical_origin), do: {:error, :target_origin_mismatch}

  defp canonical_executor_token(token) when is_binary(token) do
    if String.match?(token, ~r/\A[A-Za-z0-9_-]{32,128}\z/) do
      {:ok, token}
    else
      {:error, :invalid_executor_token}
    end
  end

  defp canonical_executor_token(_token), do: {:error, :invalid_executor_token}

  defp canonical_route("proxy"), do: {:ok, "proxy"}
  defp canonical_route(_route), do: {:error, :invalid_route}

  defp canonical_method(method) when is_binary(method) do
    method = String.upcase(method)

    if String.match?(method, ~r/\A[A-Z]+(?:-[A-Z]+)?\z/) do
      {:ok, method}
    else
      {:error, :invalid_method}
    end
  end

  defp canonical_method(_method), do: {:error, :invalid_method}

  defp canonical_header_names(names) when is_list(names) do
    names
    |> Enum.reduce_while({:ok, MapSet.new()}, fn
      name, {:ok, acc} when is_binary(name) ->
        normalized = String.downcase(name)

        if header_name_allowed?(normalized) do
          {:cont, {:ok, MapSet.put(acc, normalized)}}
        else
          {:halt, {:error, :invalid_header_name}}
        end

      _name, _acc ->
        {:halt, {:error, :invalid_header_name}}
    end)
    |> case do
      {:ok, names} -> {:ok, names |> MapSet.to_list() |> Enum.sort()}
      error -> error
    end
  end

  defp canonical_header_names(_names), do: {:error, :invalid_header_names}

  defp canonical_body_schema(schema) when schema in ["none", "json", "text"], do: {:ok, schema}
  defp canonical_body_schema(_schema), do: {:error, :invalid_body_schema}

  defp canonical_max_request_bytes(bytes) when is_integer(bytes) and bytes >= 0 do
    if bytes <= @max_executor_request_bytes do
      {:ok, bytes}
    else
      {:error, :invalid_max_request_bytes}
    end
  end

  defp canonical_max_request_bytes(_bytes), do: {:error, :invalid_max_request_bytes}

  defp canonical_max_response_bytes(bytes) when is_integer(bytes) and bytes >= 0 do
    {:ok, bytes}
  end

  defp canonical_max_response_bytes(_bytes), do: {:error, :invalid_max_response_bytes}

  defp header_name_allowed?(name) do
    String.match?(name, ~r/\A[a-z0-9!#$%&'*+.^_`|~-]+\z/) and
      name not in @forbidden_request_headers
  end

  defp forbidden_host?(host) do
    normalized =
      host
      |> String.downcase()
      |> String.trim_leading("[")
      |> String.trim_trailing("]")
      |> String.trim_trailing(".")

    cond do
      normalized in [
        "localhost",
        "metadata",
        "metadata.google.internal",
        "169.254.169.254",
        "169.254.169.253",
        "100.100.100.200"
      ] ->
        true

      String.ends_with?(normalized, ".localhost") or String.ends_with?(normalized, ".local") ->
        true

      String.contains?(normalized, ":") ->
        true

      ipv4_literal?(normalized) ->
        true

      true ->
        false
    end
  end

  defp ipv4_literal?(host) do
    case String.split(host, ".") do
      [_a, _b, _c, _d] = octets -> Enum.all?(octets, &ipv4_octet?/1)
      _ -> false
    end
  end

  defp ipv4_octet?(octet) do
    case Integer.parse(octet) do
      {value, ""} when value >= 0 and value <= 255 -> true
      _ -> false
    end
  end
end
