defmodule RefMDWeb.ApiSpec do
  alias OpenApiSpex.{Components, Info, OpenApi, Parameter, Paths, Schema, SecurityScheme, Server}

  @behaviour OpenApi

  @impl OpenApi
  def spec do
    %OpenApi{
      info: %Info{
        title: "RefMD API",
        version: "1.0.0"
      },
      servers: [
        %Server{url: "/"}
      ],
      security: [],
      components: %Components{
        securitySchemes: %{
          "user_session" => %SecurityScheme{
            type: "apiKey",
            in: "cookie",
            name: "_refmd_session",
            description: "Authenticated user session cookie."
          },
          "share_session" => %SecurityScheme{
            type: "apiKey",
            in: "cookie",
            name: "_refmd_share_session",
            description: "Share participant session cookie."
          },
          "session_scope" => %SecurityScheme{
            type: "apiKey",
            in: "header",
            name: "x-refmd-session-scope",
            description: "Explicit user/share session scope selector."
          },
          "recovery_user_session" => %SecurityScheme{
            type: "apiKey",
            in: "cookie",
            name: "_refmd_session",
            description: "Authenticated user session cookie with is_recovery=true."
          },
          "proof_of_possession" => %SecurityScheme{
            type: "apiKey",
            in: "header",
            name: "x-pop-signature-transport",
            description: "Proof-of-possession transport signature."
          },
          "proof_of_possession_device" => %SecurityScheme{
            type: "apiKey",
            in: "header",
            name: "x-pop-device-id",
            description: "PoP signing device id."
          },
          "proof_of_possession_challenge" => %SecurityScheme{
            type: "apiKey",
            in: "header",
            name: "x-pop-challenge",
            description: "Strict base64url PoP challenge."
          },
          "proof_of_possession_actor_variant" => %SecurityScheme{
            type: "apiKey",
            in: "header",
            name: "x-pop-actor-variant",
            description: "PoP actor variant: user_device or share_participant_device.",
            extensions: %{
              "x-schema" => %Schema{
                type: :string,
                enum: ["user_device", "share_participant_device"]
              }
            }
          }
        }
      },
      paths: Paths.from_router(RefMDWeb.Router)
    }
    |> OpenApiSpex.resolve_schema_modules()
    |> close_object_schemas()
    |> require_declared_request_bodies()
    |> assign_route_security_overrides()
    |> sanitize_operation_ids()
  end

  @http_methods [:get, :put, :post, :delete, :options, :head, :patch, :trace]
  @public_route_security []
  @user_session_security [%{"user_session" => []}]
  @user_or_share_session_security [%{"user_session" => []}, %{"share_session" => []}]
  @session_scope_header_parameter %Parameter{
    name: :"x-refmd-session-scope",
    in: :header,
    description:
      "Set to share to select the share participant session cookie on dual-session routes.",
    required: false,
    schema: %Schema{type: :string, enum: ["share"]}
  }
  @user_pop_security [
    %{
      "user_session" => [],
      "proof_of_possession" => [],
      "proof_of_possession_device" => [],
      "proof_of_possession_challenge" => [],
      "proof_of_possession_actor_variant" => []
    }
  ]
  @user_or_share_pop_security [
    %{
      "user_session" => [],
      "proof_of_possession" => [],
      "proof_of_possession_device" => [],
      "proof_of_possession_challenge" => [],
      "proof_of_possession_actor_variant" => []
    },
    %{
      "share_session" => [],
      "proof_of_possession" => [],
      "proof_of_possession_device" => [],
      "proof_of_possession_challenge" => [],
      "proof_of_possession_actor_variant" => []
    }
  ]
  @recovery_or_user_pop_security [
    %{"recovery_user_session" => []},
    %{
      "user_session" => [],
      "proof_of_possession" => [],
      "proof_of_possession_device" => [],
      "proof_of_possession_challenge" => [],
      "proof_of_possession_actor_variant" => []
    }
  ]
  @recovery_session_security [%{"recovery_user_session" => []}]
  @pop_header_parameters [
    %Parameter{
      name: :"x-pop-device-id",
      in: :header,
      description: "PoP signing device id.",
      required: true,
      schema: %Schema{type: :string, format: :uuid}
    },
    %Parameter{
      name: :"x-pop-challenge",
      in: :header,
      description: "Strict base64url PoP challenge.",
      required: true,
      schema: %Schema{type: :string, pattern: "^[A-Za-z0-9_-]+$"}
    },
    %Parameter{
      name: :"x-pop-signature-transport",
      in: :header,
      description: "Base64url encoded canonical PoP signature transport.",
      required: true,
      schema: %Schema{type: :string, pattern: "^[A-Za-z0-9_-]+$"}
    },
    %Parameter{
      name: :"x-pop-actor-variant",
      in: :header,
      description: "PoP actor variant.",
      required: true,
      schema: %Schema{type: :string, enum: ["user_device", "share_participant_device"]}
    }
  ]

  @public_routes %{
    {"/api/auth/salt", :get} => @public_route_security,
    {"/api/auth/register", :post} => @public_route_security,
    {"/api/auth/login", :post} => @public_route_security,
    {"/api/auth/recovery/challenge", :post} => @public_route_security,
    {"/api/auth/recovery/session", :post} => @public_route_security,
    {"/api/auth/password-reset/request", :post} => @public_route_security,
    {"/api/auth/password-reset/verify", :post} => @public_route_security,
    {"/api/shares/{share_slug}", :get} => @public_route_security,
    {"/api/shares/{share_slug}/challenge", :get} => @public_route_security,
    {"/api/shares/d/{document_token}", :get} => @public_route_security,
    {"/api/shares/f/{folder_token}", :get} => @public_route_security,
    {"/api/shares/{share_slug}/bootstrap", :post} => @public_route_security,
    {"/api/shares/{share_slug}/challenge", :post} => @public_route_security,
    {"/api/shares/d/{document_token}/bootstrap", :post} => @public_route_security,
    {"/api/shares/f/{folder_token}/bootstrap", :post} => @public_route_security,
    {"/api/guest/redeem", :post} => @public_route_security,
    {"/api/invitations/lookup", :get} => @public_route_security,
    {"/api/public/authors/{author_slug}", :get} => @public_route_security,
    {"/api/public/authors/{author_slug}/documents/{document_slug}", :get} =>
      @public_route_security
  }

  @session_only_routes %{
    {"/api/auth/me", :get} => @user_session_security,
    {"/api/auth/key-restore", :get} => @user_session_security,
    {"/api/auth/verify-key", :post} => @user_session_security,
    {"/api/auth/kdf-migration", :post} => @user_session_security,
    {"/api/auth/recovery", :get} => @user_session_security,
    {"/api/auth/password-set", :post} => @recovery_session_security,
    {"/api/devices/bootstrap/challenge", :post} => @user_session_security,
    {"/api/devices/bootstrap", :post} => @user_session_security,
    {"/api/devices/registrations/challenge", :post} => @user_session_security,
    {"/api/devices/registrations", :post} => @user_session_security,
    {"/api/devices/registrations", :get} => @user_session_security,
    {"/api/devices/registrations/{device_id}/sas", :get} => @user_session_security,
    {"/api/devices/registrations/{device_id}", :delete} => @user_session_security,
    {"/api/encryption/setup-complete", :post} => @user_session_security,
    {"/api/workspaces/ids", :get} => @user_session_security,
    {"/api/workspaces", :post} => @user_session_security,
    {"/api/mounts", :post} => @user_session_security,
    {"/api/shares/{share_slug}/mounts", :get} => @user_session_security,
    {"/api/settings", :get} => @user_session_security,
    {"/api/auth/logout", :post} => @user_or_share_session_security,
    {"/api/auth/pop-challenge", :post} => @user_or_share_session_security,
    {"/api/auth/ws-token", :post} => @user_or_share_session_security
  }

  @user_or_share_pop_routes %{
    {"/api/users/{user_id}/key-directory/latest", :get} => @user_or_share_pop_security,
    {"/api/workspaces/{workspace_id}/key-directory/latest", :get} => @user_or_share_pop_security
  }

  @recovery_or_user_pop_routes %{
    {"/api/devices/registrations/{device_id}/approve", :post} => @recovery_or_user_pop_security
  }

  defp close_object_schemas(%Schema{} = schema) do
    %Schema{} =
      schema =
      schema
      |> Map.from_struct()
      |> Map.new(fn {key, value} -> {key, close_object_schemas(value)} end)
      |> then(&struct(schema, &1))

    if schema.type in [:object, "object"] and is_nil(schema.additionalProperties) do
      %Schema{schema | additionalProperties: false}
    else
      schema
    end
  end

  defp close_object_schemas(%module{} = struct) do
    struct
    |> Map.from_struct()
    |> Map.new(fn {key, value} -> {key, close_object_schemas(value)} end)
    |> then(&struct(module, &1))
  end

  defp close_object_schemas(values) when is_list(values),
    do: Enum.map(values, &close_object_schemas/1)

  defp close_object_schemas(map) when is_map(map) do
    map =
      Map.new(map, fn {key, value} ->
        {key, close_object_schemas(value)}
      end)

    if object_schema_map?(map) and missing_additional_properties?(map) do
      Map.put(map, :additionalProperties, false)
    else
      map
    end
  end

  defp close_object_schemas(value), do: value

  defp object_schema_map?(%{type: type}) when type in [:object, "object"], do: true
  defp object_schema_map?(%{"type" => type}) when type in [:object, "object"], do: true
  defp object_schema_map?(_), do: false

  defp missing_additional_properties?(map) do
    not Map.has_key?(map, :additionalProperties) and not Map.has_key?(map, "additionalProperties")
  end

  defp require_declared_request_bodies(%OpenApi{paths: paths} = spec) when is_map(paths) do
    paths =
      Map.new(paths, fn {path, item} ->
        {path,
         Enum.reduce(@http_methods, item, fn method, acc ->
           case Map.get(acc, method) do
             %{requestBody: %OpenApiSpex.RequestBody{} = body} = operation ->
               Map.put(acc, method, %{operation | requestBody: %{body | required: true}})

             %{requestBody: %{"content" => _} = body} = operation ->
               Map.put(acc, method, %{operation | requestBody: Map.put(body, "required", true)})

             _ ->
               acc
           end
         end)}
      end)

    %{spec | paths: paths}
  end

  defp assign_route_security_overrides(%OpenApi{paths: paths} = spec) when is_map(paths) do
    overrides =
      @public_routes
      |> Map.merge(@session_only_routes)
      |> Map.merge(@user_or_share_pop_routes)
      |> Map.merge(@recovery_or_user_pop_routes)

    paths =
      Map.new(paths, fn {path, item} ->
        {path,
         Enum.reduce(@http_methods, item, fn method, acc ->
           case Map.get(acc, method) do
             nil ->
               acc

             operation ->
               security = Map.get(overrides, {path, method}, @user_pop_security)

               operation =
                 operation
                 |> Map.put(:security, security)
                 |> maybe_add_session_scope_header_parameter()
                 |> maybe_require_pop_header_parameters()

               Map.put(acc, method, operation)
           end
         end)}
      end)

    %{spec | paths: paths}
  end

  defp maybe_require_pop_header_parameters(%{security: security} = operation) do
    if pop_security?(security) do
      required? = strict_pop_security?(security)

      pop_header_parameters = pop_header_parameters(security, required?)

      parameters =
        Enum.reduce(@pop_header_parameters, List.wrap(operation.parameters), fn parameter, acc ->
          reject_parameter(acc, Atom.to_string(parameter.name), :header)
        end)

      %{operation | parameters: pop_header_parameters ++ parameters}
    else
      operation
    end
  end

  defp maybe_add_session_scope_header_parameter(
         %{security: @user_or_share_session_security} = operation
       ) do
    parameters =
      operation.parameters
      |> List.wrap()
      |> reject_parameter("x-refmd-session-scope", :header)

    %{operation | parameters: [@session_scope_header_parameter | parameters]}
  end

  defp maybe_add_session_scope_header_parameter(operation), do: operation

  defp pop_header_parameters(security, required?) do
    actor_variants =
      if share_participant_pop_security?(security),
        do: ["user_device", "share_participant_device"],
        else: ["user_device"]

    Enum.map(@pop_header_parameters, fn
      %Parameter{name: :"x-pop-actor-variant"} = parameter ->
        %{
          parameter
          | required: required?,
            schema: %Schema{type: :string, enum: actor_variants}
        }

      parameter ->
        %{parameter | required: required?}
    end)
  end

  defp pop_security?(security) when is_list(security) and security != [] do
    Enum.any?(security, fn requirement ->
      is_map(requirement) and Map.has_key?(requirement, "proof_of_possession_actor_variant")
    end)
  end

  defp pop_security?(_), do: false

  defp share_participant_pop_security?(security) when is_list(security) do
    Enum.any?(security, fn
      %{"share_session" => [], "proof_of_possession_actor_variant" => []} -> true
      _requirement -> false
    end)
  end

  defp share_participant_pop_security?(_), do: false

  defp strict_pop_security?(security) when is_list(security) and security != [] do
    Enum.all?(security, fn requirement ->
      is_map(requirement) and Map.has_key?(requirement, "proof_of_possession_actor_variant")
    end)
  end

  defp strict_pop_security?(_), do: false

  defp reject_parameter(parameters, name, location) do
    atom_name = String.to_atom(name)

    Enum.reject(parameters, fn
      %Parameter{name: ^name, in: ^location} -> true
      %Parameter{name: ^atom_name, in: ^location} -> true
      %{name: ^name, in: ^location} -> true
      %{name: ^atom_name, in: ^location} -> true
      {^name, opts} when is_list(opts) -> Keyword.get(opts, :in) == location
      {^atom_name, opts} when is_list(opts) -> Keyword.get(opts, :in) == location
      _ -> false
    end)
  end

  defp sanitize_operation_ids(%OpenApi{paths: paths} = spec) when is_map(paths) do
    sanitized_paths =
      Map.new(paths, fn {path, item} ->
        {path,
         Enum.reduce(@http_methods, item, fn method, acc ->
           case Map.get(acc, method) do
             nil ->
               acc

             operation ->
               Map.put(acc, method, %{operation | operationId: operation_id(method, path)})
           end
         end)}
      end)

    %{spec | paths: sanitized_paths}
  end

  defp operation_id(method, path) do
    path_part =
      path
      |> String.trim_leading("/")
      |> String.replace(~r/\{([^}]+)\}/, "by_\\1")
      |> String.replace(~r/[^A-Za-z0-9]+/, "_")
      |> String.trim("_")

    "#{method}_#{path_part}"
  end
end
