defmodule RefMDWeb.PluginStorageController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Plugins
  alias RefMDWeb.Schemas

  @max_plugin_storage_payload_bytes 64 * 1024
  @plugin_storage_write_limit 60
  @plugin_storage_write_period_ms 60_000

  plug RefMDWeb.Plugs.RequireRBAC,
    permission: :membership

  @storage_parameters [
    workspace_id: [in: :path, type: :string, required: true],
    application_id: [in: :path, type: :string, required: true],
    surface: [in: :path, type: :string, required: true],
    plugin_id: [in: :query, type: :string, required: false],
    state_head_hash: [in: :query, type: :string, required: true],
    consent_head_hash: [in: :query, type: :string, required: true],
    capability_grant_id: [in: :query, type: :string, required: true],
    consent_epoch: [in: :query, type: :integer, required: true],
    frame_generation: [in: :query, type: :integer, required: true],
    key: [in: :query, type: :string, required: true],
    document_id: [in: :query, type: :string, required: false]
  ]
  @record_storage_parameters [
    workspace_id: [in: :path, type: :string, required: true],
    application_id: [in: :path, type: :string, required: true],
    surface: [in: :path, type: :string, required: true],
    plugin_id: [in: :query, type: :string, required: false],
    state_head_hash: [in: :query, type: :string, required: true],
    consent_head_hash: [in: :query, type: :string, required: true],
    capability_grant_id: [in: :query, type: :string, required: true],
    consent_epoch: [in: :query, type: :integer, required: true],
    frame_generation: [in: :query, type: :integer, required: true],
    document_id: [in: :query, type: :string, required: false]
  ]
  @record_entry_parameters [
    workspace_id: [in: :path, type: :string, required: true],
    application_id: [in: :path, type: :string, required: true],
    surface: [in: :path, type: :string, required: true],
    record_id: [in: :path, type: :string, required: true],
    plugin_id: [in: :query, type: :string, required: false],
    state_head_hash: [in: :query, type: :string, required: true],
    consent_head_hash: [in: :query, type: :string, required: true],
    capability_grant_id: [in: :query, type: :string, required: true],
    consent_epoch: [in: :query, type: :integer, required: true],
    frame_generation: [in: :query, type: :integer, required: true],
    document_id: [in: :query, type: :string, required: false]
  ]

  operation(:show,
    summary: "Get encrypted plugin storage",
    parameters: @storage_parameters,
    responses: [
      ok: {"Encrypted plugin storage", "application/json", Schemas.PluginStorageEntryResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def show(conn, params) do
    with {:ok, storage} <- storage_ref(params),
         {:ok, context} <- authorize_storage_request(conn, params, storage, "read"),
         entry when not is_nil(entry) <-
           Plugins.get_kv(
             context.application.id,
             storage.surface,
             storage.scope_id,
             storage.key
           ) do
      json(conn, format_entry(entry))
    else
      nil -> json(conn, nil)
      {:error, status, error} -> conn |> put_status(status) |> json(%{error: error})
    end
  end

  operation(:upsert,
    summary: "Save encrypted plugin storage",
    parameters: @storage_parameters,
    request_body:
      {"Encrypted plugin storage", "application/json", Schemas.PluginStorageWriteRequest},
    responses: [
      ok: {"Encrypted plugin storage", "application/json", Schemas.PluginStorageEntryResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def upsert(conn, params) do
    with {:ok, storage} <- storage_ref(params),
         {:ok, context} <- authorize_storage_request(conn, params, storage, "write"),
         {:ok, ciphertext} <- decode_binary(params["ciphertext"]),
         {:ok, nonce} <- decode_binary(params["nonce"]),
         :ok <- validate_storage_payload_size(byte_size(ciphertext)),
         :ok <-
           record_storage_mutation(conn, context, storage, "set", byte_size(ciphertext)),
         {:ok, entry} <-
           Plugins.put_kv(%{
             application_id: context.application.id,
             package_id: context.application.package_id,
             activation_id: context.consent.activation_id,
             workspace_id: storage.workspace_id,
             plugin_id: context.application.plugin_id,
             scope: storage.surface,
             scope_id: storage.scope_id,
             key: storage.key,
             ciphertext: ciphertext,
             nonce: nonce,
             key_version: params["key_version"]
           }) do
      json(conn, format_entry(entry))
    else
      {:error, :invalid_base64} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_storage_entry", details: format_errors(changeset)})

      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  end

  operation(:delete,
    summary: "Delete encrypted plugin storage",
    parameters: @storage_parameters,
    responses: [
      ok: {"Deleted", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def delete(conn, params) do
    with {:ok, storage} <- storage_ref(params),
         {:ok, context} <- authorize_storage_request(conn, params, storage, "write"),
         :ok <- record_storage_mutation(conn, context, storage, "delete", 0),
         {:ok, _entry} <-
           Plugins.delete_kv(
             context.application.id,
             storage.surface,
             storage.scope_id,
             storage.key
           ) do
      json(conn, %{ok: true})
    else
      {:error, :not_found} -> conn |> put_status(:not_found) |> json(%{error: "not_found"})
      {:error, status, error} -> conn |> put_status(status) |> json(%{error: error})
    end
  end

  operation(:create_record,
    summary: "Create encrypted plugin record storage",
    parameters: @record_storage_parameters,
    request_body:
      {"Encrypted plugin record storage", "application/json", Schemas.PluginRecordWriteRequest},
    responses: [
      ok: {"Encrypted plugin record storage", "application/json", Schemas.PluginRecordResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Validation error", "application/json", Schemas.ErrorResponse}
    ]
  )

  def create_record(conn, params) do
    with {:ok, storage} <- record_storage_ref(params),
         {:ok, context} <- authorize_storage_request(conn, params, storage, "write"),
         {:ok, record_id} <- record_id(params["id"]),
         {:ok, kind} <- non_empty(params["kind"], "invalid_kind"),
         {:ok, encrypted_data} <- decode_binary(params["encrypted_data"]),
         {:ok, nonce} <- decode_binary(params["nonce"]),
         :ok <- validate_storage_payload_size(byte_size(encrypted_data)),
         :ok <-
           record_storage_mutation(
             conn,
             context,
             Map.put(storage, :key, kind),
             "create_record",
             byte_size(encrypted_data)
           ),
         {:ok, record} <-
           Plugins.put_record(%{
             id: record_id,
             application_id: context.application.id,
             package_id: context.application.package_id,
             activation_id: context.consent.activation_id,
             workspace_id: storage.workspace_id,
             plugin_id: context.application.plugin_id,
             scope: storage.surface,
             scope_id: storage.scope_id,
             kind: kind,
             encrypted_data: encrypted_data,
             nonce: nonce,
             key_version: params["key_version"]
           }) do
      json(conn, format_record(record))
    else
      {:error, :invalid_base64} ->
        conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_base64_encoding"})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "invalid_storage_record", details: format_errors(changeset)})

      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  end

  operation(:show_record,
    summary: "Get encrypted plugin record storage",
    parameters: @record_entry_parameters,
    responses: [
      ok: {"Encrypted plugin record storage", "application/json", Schemas.PluginRecordResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def show_record(conn, params) do
    with {:ok, storage} <- record_storage_ref(params),
         {:ok, context} <- authorize_storage_request(conn, params, storage, "read"),
         record when not is_nil(record) <-
           Plugins.get_record(
             params["record_id"],
             context.application.id,
             storage.surface,
             storage.scope_id
           ) do
      json(conn, format_record(record))
    else
      nil -> json(conn, nil)
      {:error, status, error} -> conn |> put_status(status) |> json(%{error: error})
    end
  end

  operation(:delete_record,
    summary: "Delete encrypted plugin record storage",
    parameters: @record_entry_parameters,
    responses: [
      ok: {"Deleted", "application/json", Schemas.OkResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse}
    ]
  )

  def delete_record(conn, params) do
    with {:ok, storage} <- record_storage_ref(params),
         {:ok, context} <- authorize_storage_request(conn, params, storage, "write"),
         :ok <-
           record_storage_mutation(
             conn,
             context,
             Map.put(storage, :key, params["record_id"]),
             "delete_record",
             0
           ),
         {:ok, _record} <-
           Plugins.delete_record(
             params["record_id"],
             context.application.id,
             storage.surface,
             storage.scope_id
           ) do
      json(conn, %{ok: true})
    else
      {:error, :not_found} -> conn |> put_status(:not_found) |> json(%{error: "not_found"})
      {:error, status, error} -> conn |> put_status(status) |> json(%{error: error})
    end
  end

  defp storage_ref(params) do
    with {:ok, surface} <- parse_surface(params["surface"]),
         {:ok, key} <- non_empty(params["key"], "invalid_key"),
         {:ok, scope_id} <- scope_id(surface, params) do
      {:ok,
       %{
         workspace_id: params["workspace_id"],
         surface: surface,
         scope_id: scope_id,
         key: key
       }}
    end
  end

  defp record_storage_ref(params) do
    with {:ok, surface} <- parse_surface(params["surface"]),
         {:ok, scope_id} <- scope_id(surface, params) do
      {:ok,
       %{
         workspace_id: params["workspace_id"],
         surface: surface,
         scope_id: scope_id
       }}
    end
  end

  defp parse_surface(surface) when surface in ["workspace", "document"], do: {:ok, surface}
  defp parse_surface(_surface), do: {:error, :bad_request, "invalid_surface"}

  defp scope_id("workspace", %{"workspace_id" => workspace_id}), do: {:ok, workspace_id}
  defp scope_id("document", params), do: non_empty(params["document_id"], "invalid_document_id")

  defp non_empty(value, error) when is_binary(value) do
    if String.trim(value) == "", do: {:error, :bad_request, error}, else: {:ok, value}
  end

  defp non_empty(_value, error), do: {:error, :bad_request, error}

  defp record_id(value) when is_binary(value) do
    case Ecto.UUID.cast(value) do
      {:ok, record_id} -> {:ok, record_id}
      :error -> {:error, :bad_request, "invalid_record_id"}
    end
  end

  defp record_id(_value), do: {:error, :bad_request, "invalid_record_id"}

  defp authorize_storage_request(conn, params, storage, operation) do
    Plugins.authorize_storage_context(%{
      application_id: params["application_id"],
      plugin_id: params["plugin_id"],
      workspace_id: storage.workspace_id,
      surface: storage.surface,
      scope_id: storage.scope_id,
      operation: operation,
      user_id: conn.assigns.current_user_id,
      device_id: current_device_id(conn),
      state_head_hash: params["state_head_hash"],
      consent_head_hash: params["consent_head_hash"],
      capability_grant_id: params["capability_grant_id"],
      consent_epoch: params["consent_epoch"],
      frame_generation: params["frame_generation"]
    })
  end

  defp current_device_id(%{assigns: %{current_session: %{device_id: device_id}}})
       when is_binary(device_id),
       do: device_id

  defp current_device_id(_conn), do: nil

  defp record_storage_mutation(conn, context, storage, operation, storage_bytes) do
    with :ok <- enforce_storage_write_rate(conn, context, storage) do
      Plugins.record_storage_mutation_audit(%{
        application: context.application,
        bundle: context.bundle,
        consent: context.consent,
        storage: storage,
        operation: operation,
        storage_bytes: storage_bytes,
        consent_head_hash: context.consent_head_hash,
        activation: context.activation,
        capability_grant_id: context.capability_grant_id,
        consent_epoch: context.consent_epoch,
        frame_generation: context.frame_generation,
        user_id: conn.assigns.current_user_id,
        device_id: current_device_id(conn)
      })
    end
  end

  defp validate_storage_payload_size(bytes) when bytes <= @max_plugin_storage_payload_bytes,
    do: :ok

  defp validate_storage_payload_size(_bytes),
    do: {:error, 413, "plugin_storage_payload_too_large"}

  defp enforce_storage_write_rate(conn, context, storage) do
    now = System.system_time(:millisecond)
    window_start = div(now, @plugin_storage_write_period_ms)

    counter_key =
      {{:plugin_storage_write, context.application.id, context.consent.activation_id,
        storage.surface, storage.scope_id, conn.assigns.current_user_id}, window_start}

    count =
      :ets.update_counter(
        RefMDWeb.Plugs.RateLimit.Storage,
        counter_key,
        {2, 1},
        {counter_key, 0}
      )

    if count > @plugin_storage_write_limit do
      {:error, :too_many_requests, "plugin_storage_rate_limited"}
    else
      :ok
    end
  end

  defp format_entry(entry) do
    %{
      plugin_id: entry.plugin_id,
      application_id: entry.application_id,
      activation_id: entry.activation_id,
      workspace_id: entry.workspace_id,
      surface: entry.scope,
      scope_id: entry.scope_id,
      key: entry.key,
      ciphertext: encode_binary(entry.ciphertext),
      nonce: encode_binary(entry.nonce),
      key_version: entry.key_version
    }
  end

  defp format_record(record) do
    %{
      id: record.id,
      plugin_id: record.plugin_id,
      application_id: record.application_id,
      activation_id: record.activation_id,
      workspace_id: record.workspace_id,
      surface: record.scope,
      scope_id: record.scope_id,
      kind: record.kind,
      encrypted_data: encode_binary(record.encrypted_data),
      nonce: encode_binary(record.nonce),
      key_version: record.key_version
    }
  end
end
