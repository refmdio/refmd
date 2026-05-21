defmodule RefMDWeb.Plugs.OpenApiRequestValidation do
  @moduledoc false

  alias OpenApiSpex.Operation
  alias OpenApiSpex.Plug.PutApiSpec
  alias Plug.Conn
  alias RefMDWeb.Plugs.OpenApiRequestValidation.RenderError

  @cast_opts [replace_params: false]

  @spec init(keyword()) :: keyword()
  def init(opts), do: opts

  @spec call(Plug.Conn.t(), keyword()) :: Plug.Conn.t()
  def call(
        %{private: %{open_api_spex: _, phoenix_controller: controller, phoenix_action: action}} =
          conn,
        _opts
      ) do
    with true <- function_exported?(controller, :open_api_operation, 1),
         %Operation{} <- controller.open_api_operation(action),
         {route_path, method} <- route_key(conn),
         %Operation{} = operation <- spec_operation(conn, route_path, method) do
      cast_and_validate(conn, operation)
    else
      _ ->
        conn
    end
  end

  def call(conn, _opts), do: conn

  defp spec_operation(conn, route_path, method) do
    {spec, _operation_lookup} = PutApiSpec.get_spec_and_operation_lookup(conn)

    spec.paths
    |> Map.get(route_path)
    |> case do
      nil ->
        nil

      path_item ->
        Map.get(path_item, method)
    end
  end

  defp route_key(conn) do
    route_info =
      Phoenix.Router.route_info(
        RefMDWeb.Router,
        conn.method,
        conn.request_path,
        conn.host
      )

    route_path =
      route_info.route
      |> String.split("/")
      |> Enum.map_join("/", &route_segment/1)

    {route_path, method(conn)}
  end

  defp route_segment(":" <> param), do: "{#{param}}"
  defp route_segment(segment), do: segment

  defp method(%{method: method}) do
    method
    |> String.downcase()
    |> String.to_existing_atom()
  end

  defp cast_and_validate(conn, operation) do
    {spec, _operation_lookup} = PutApiSpec.get_spec_and_operation_lookup(conn)
    conn = put_operation_id(conn, operation)

    case OpenApiSpex.cast_and_validate(spec, operation, conn, "application/json", @cast_opts) do
      {:ok, conn} ->
        conn

      {:error, errors} ->
        errors = RenderError.init(errors)

        conn
        |> RenderError.call(errors)
        |> Conn.halt()
    end
  end

  defp put_operation_id(conn, operation) do
    private_data =
      conn
      |> Map.get(:private)
      |> Map.get(:open_api_spex, %{})
      |> Map.put(:operation_id, operation.operationId)

    Conn.put_private(conn, :open_api_spex, private_data)
  end
end
