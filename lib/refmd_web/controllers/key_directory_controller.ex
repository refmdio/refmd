defmodule RefMDWeb.KeyDirectoryController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Encryption
  alias RefMD.Sharing
  alias RefMD.Workspaces
  alias RefMDWeb.Schemas

  operation(:append,
    summary: "Append workspace device or identity key admission events",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true]
    ],
    request_body:
      {"Key-directory append", "application/json", Schemas.KeyDirectoryAppendRequest,
       required: true},
    responses: [
      ok: {"Appended", "application/json", Schemas.OkResponse},
      bad_request: {"Invalid request", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      unprocessable_entity: {"Invalid key directory", "application/json", Schemas.ErrorResponse}
    ]
  )

  def append(conn, %{"workspace_id" => workspace_id} = params) do
    user_id = conn.assigns.current_user_id
    pop_device_id = conn.assigns[:pop_device_id]

    with {:ok, role} <- fetch_workspace_role(workspace_id, user_id),
         :ok <- require_workspace_key_authority(role),
         :ok <- reject_wipe_required_device(workspace_id, pop_device_id),
         {:ok, events} <- require_append_events(params["events"]),
         {:ok, checkpoint} <- require_append_checkpoint(params["checkpoint"]),
         {:ok, checkpoint_signer_kind} <-
           Encryption.validate_workspace_key_directory_append(
             events,
             checkpoint,
             workspace_id,
             user_id,
             pop_device_id
           ) do
      case Encryption.append_workspace_key_directory(workspace_id, events, checkpoint,
             checkpoint_signer_kind: checkpoint_signer_kind
           ) do
        :ok ->
          json(conn, %{ok: true})

        {:error, :invalid_key_directory} ->
          conn |> put_status(:unprocessable_entity) |> json(%{error: "invalid_key_directory"})
      end
    else
      {:error, status, error} ->
        conn |> put_status(status) |> json(%{error: error})
    end
  end

  operation(:latest_user,
    summary: "Get the latest pinned user key-directory checkpoint and ancestry",
    parameters: [
      user_id: [in: :path, type: :string, required: true],
      checkpoint_sequence: [in: :query, type: :integer, required: true],
      event_head_sequence: [in: :query, type: :integer, required: true],
      checkpoint_hash: [in: :query, type: :string, required: true],
      event_head_hash: [in: :query, type: :string, required: true]
    ],
    responses: [
      ok: {"Latest key directory", "application/json", Schemas.LatestKeyDirectoryResponse},
      bad_request: {"Invalid pin", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Pin mismatch", "application/json", Schemas.ErrorResponse}
    ]
  )

  def latest_user(conn, %{"user_id" => user_id}) do
    if user_id == conn.assigns.current_user_id do
      send_latest(conn, "user", user_id, conn.params)
    else
      conn |> put_status(:forbidden) |> json(%{error: "key_directory_scope_forbidden"})
    end
  end

  operation(:latest_workspace,
    summary: "Get the latest pinned workspace key-directory checkpoint and ancestry",
    parameters: [
      workspace_id: [in: :path, type: :string, required: true],
      checkpoint_sequence: [in: :query, type: :integer, required: true],
      event_head_sequence: [in: :query, type: :integer, required: true],
      checkpoint_hash: [in: :query, type: :string, required: true],
      event_head_hash: [in: :query, type: :string, required: true]
    ],
    responses: [
      ok: {"Latest key directory", "application/json", Schemas.LatestKeyDirectoryResponse},
      bad_request: {"Invalid pin", "application/json", Schemas.ErrorResponse},
      forbidden: {"Forbidden", "application/json", Schemas.ErrorResponse},
      not_found: {"Not found", "application/json", Schemas.ErrorResponse},
      conflict: {"Pin mismatch", "application/json", Schemas.ErrorResponse}
    ]
  )

  def latest_workspace(conn, %{"workspace_id" => workspace_id}) do
    cond do
      Workspaces.get_workspace_member(workspace_id, conn.assigns.current_user_id) ->
        send_latest(conn, "workspace", workspace_id, conn.params)

      guest_workspace_access?(workspace_id, conn.assigns.current_user_id) ->
        send_latest(conn, "workspace", workspace_id, conn.params)

      Workspaces.share_links_enabled?(workspace_id) and
          share_participant_workspace_access?(conn, workspace_id) ->
        send_latest(conn, "workspace", workspace_id, conn.params)

      true ->
        conn |> put_status(:forbidden) |> json(%{error: "key_directory_scope_forbidden"})
    end
  end

  defp fetch_workspace_role(workspace_id, user_id) do
    case Workspaces.get_member_role(workspace_id, user_id) do
      nil -> {:error, :forbidden, "key_directory_scope_forbidden"}
      role -> {:ok, role}
    end
  end

  defp share_participant_workspace_access?(conn, workspace_id) do
    share_id = conn.assigns[:current_share_id]

    conn.assigns[:session_kind] == :share_participant and
      is_binary(share_id) and
      Sharing.share_session_workspace_access?(share_id, workspace_id)
  end

  defp guest_workspace_access?(workspace_id, user_id) do
    Workspaces.guest_user?(user_id) and
      Workspaces.authorize_guest_permission(workspace_id, user_id, "document:read", nil) == :ok
  end

  defp require_workspace_key_authority(role) when role in ~w(owner admin), do: :ok
  defp require_workspace_key_authority(_), do: {:error, :forbidden, "forbidden"}

  defp reject_wipe_required_device(_workspace_id, nil), do: :ok

  defp reject_wipe_required_device(workspace_id, device_id) do
    if Workspaces.workspace_device_wipe_required?(workspace_id, device_id),
      do: {:error, :forbidden, "device_wipe_required"},
      else: :ok
  end

  defp require_append_events(events) when is_list(events) and events != [], do: {:ok, events}
  defp require_append_events(_), do: {:error, :bad_request, "events_required"}

  defp require_append_checkpoint(checkpoint) when is_map(checkpoint), do: {:ok, checkpoint}
  defp require_append_checkpoint(_), do: {:error, :bad_request, "checkpoint_required"}

  defp send_latest(conn, scope_kind, scope_id, params) do
    with {:ok, client_checkpoint_sequence} <-
           parse_positive_integer(params["checkpoint_sequence"]),
         {:ok, client_event_head_sequence} <-
           parse_positive_integer(params["event_head_sequence"]),
         {:ok, client_checkpoint_hash} <- parse_required_hash(params["checkpoint_hash"]),
         {:ok, client_event_head_hash} <- parse_required_hash(params["event_head_hash"]) do
      client_anchor = %{
        checkpoint_sequence: client_checkpoint_sequence,
        checkpoint_hash: client_checkpoint_hash,
        event_head_sequence: client_event_head_sequence,
        event_head_hash: client_event_head_hash
      }

      case latest_delta(scope_kind, scope_id, client_anchor) do
        {:ok, %{checkpoint: checkpoint, checkpoints: checkpoints, events: events, pin: pin}} ->
          json(conn, %{
            checkpoint: %{
              payload: checkpoint.payload,
              signatures: checkpoint.signatures
            },
            checkpoint_ancestry: Enum.map(checkpoints, &serialize_checkpoint/1),
            event_ancestry: Enum.map(events, &serialize_event/1),
            events: Enum.map(events, &serialize_event/1),
            rotation_deletion_evidences: rotation_deletion_evidences(scope_kind, events),
            pin: serialize_pin(pin)
          })

        {:error, :not_found} ->
          conn |> put_status(:not_found) |> json(%{error: "key_directory_not_found"})

        {:error, :invalid_anchor} ->
          conn |> put_status(:conflict) |> json(%{error: "key_directory_pin_mismatch"})
      end
    else
      {:error, _reason} ->
        conn |> put_status(:bad_request) |> json(%{error: "invalid_key_directory_pin"})
    end
  end

  defp serialize_checkpoint(checkpoint) do
    %{
      payload: checkpoint.payload,
      signatures: checkpoint.signatures
    }
  end

  defp serialize_event(event) do
    %{
      payload: event.payload,
      signatures: event.signatures
    }
  end

  defp rotation_deletion_evidences("workspace", events) do
    event_hashes =
      events
      |> Enum.filter(&(&1.event_type == "old_key_deleted"))
      |> Enum.map(& &1.event_hash)

    records = Workspaces.rotation_deletion_evidences_by_event_hash(event_hashes)

    event_hashes
    |> Enum.map(&Map.get(records, &1))
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&serialize_rotation_deletion_evidence/1)
  end

  defp rotation_deletion_evidences(_scope_kind, _events), do: []

  defp latest_delta("user", user_id, client_anchor),
    do: Encryption.latest_user_key_directory_delta(user_id, client_anchor)

  defp latest_delta("workspace", workspace_id, client_anchor),
    do: Encryption.latest_workspace_key_directory_delta(workspace_id, client_anchor)

  defp serialize_rotation_deletion_evidence(evidence) do
    %{
      old_key_deleted_event_hash: evidence.old_key_deleted_event_hash,
      workspace_id: evidence.workspace_id,
      rotation_kind: evidence.rotation_kind,
      scope_kind: evidence.scope_kind,
      scope_id: evidence.scope_id,
      old_key_version: evidence.old_key_version,
      deletion_manifest: evidence.deletion_manifest,
      device_key_deletion_proofs: evidence.device_key_deletion_proofs
    }
  end

  defp serialize_pin(nil), do: nil

  defp serialize_pin(pin) when is_map(pin) do
    %{
      scope_kind: pin.scope_kind,
      scope_id: pin.scope_id,
      checkpoint_sequence: pin.checkpoint_sequence,
      checkpoint_hash: pin.checkpoint_hash,
      event_head_sequence: pin.event_head_sequence,
      event_head_hash: pin.event_head_hash,
      suite_policy_version: pin.suite_policy_version,
      min_suite_rank: pin.min_suite_rank,
      allowed_suite_ids_hash: pin.allowed_suite_ids_hash
    }
  end

  defp parse_positive_integer(value) do
    case Integer.parse(to_string(value || "")) do
      {parsed, ""} when parsed > 0 -> {:ok, parsed}
      _ -> {:error, :invalid_sequence}
    end
  end

  defp parse_required_hash(value) when is_binary(value) and byte_size(value) > 0,
    do: {:ok, value}

  defp parse_required_hash(_), do: {:error, :invalid_hash}
end
