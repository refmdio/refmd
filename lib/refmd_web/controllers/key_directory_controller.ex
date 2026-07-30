defmodule RefMDWeb.KeyDirectoryController do
  use RefMDWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias RefMD.Documents.DekRotation
  alias RefMD.Encryption
  alias RefMD.Sharing
  alias RefMD.Workspaces
  alias RefMDWeb.Schemas

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
    user_id = conn.assigns.current_user_id
    device_id = conn.assigns[:rrp_device_id]

    cond do
      Workspaces.guest_user?(user_id) and
          guest_workspace_access?(workspace_id, user_id, device_id) ->
        send_latest(conn, "workspace", workspace_id, conn.params)

      not Workspaces.guest_user?(user_id) and
          Workspaces.get_workspace_member(workspace_id, user_id) ->
        send_latest(conn, "workspace", workspace_id, conn.params)

      Workspaces.share_links_enabled?(workspace_id) and
          share_participant_workspace_access?(conn, workspace_id) ->
        send_latest(conn, "workspace", workspace_id, conn.params)

      true ->
        conn |> put_status(:forbidden) |> json(%{error: "key_directory_scope_forbidden"})
    end
  end

  defp share_participant_workspace_access?(conn, workspace_id) do
    share_id = conn.assigns[:current_share_id]

    conn.assigns[:session_kind] == :share_participant and
      is_binary(share_id) and
      Sharing.share_session_workspace_access?(share_id, workspace_id)
  end

  defp guest_workspace_access?(workspace_id, user_id, device_id) do
    Workspaces.guest_user?(user_id) and
      Workspaces.authorize_workspace_guest_access(workspace_id, user_id) == :ok and
      Encryption.active_workspace_scope_guest_device_admitted?(workspace_id, user_id, device_id)
  end

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
          authority_events =
            Encryption.key_directory_authority_events(
              scope_kind,
              scope_id,
              client_event_head_sequence,
              events,
              checkpoint
            )

          json(conn, %{
            checkpoint: %{
              payload: checkpoint.payload,
              signatures: checkpoint.signatures
            },
            checkpoint_ancestry: Enum.map(checkpoints, &serialize_checkpoint/1),
            event_ancestry: Enum.map(events, &serialize_event/1),
            authority_event_ancestry: Enum.map(authority_events, &serialize_event/1),
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

    records =
      Workspaces.rotation_deletion_evidences_by_event_hash(event_hashes)
      |> Map.merge(DekRotation.deletion_evidences_by_event_hash(event_hashes))

    event_hashes
    |> Enum.map(&Map.get(records, &1))
    |> Enum.reject(&is_nil/1)
    |> Enum.map(&serialize_rotation_deletion_evidence/1)
  end

  defp rotation_deletion_evidences("user", events) do
    event_hashes =
      events
      |> Enum.filter(&(&1.event_type == "old_key_deleted"))
      |> Enum.map(& &1.event_hash)

    records = Encryption.user_identity_rotation_deletion_evidences_by_event_hash(event_hashes)

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
      workspace_id: Map.get(evidence, :workspace_id),
      document_id: Map.get(evidence, :document_id),
      user_id: Map.get(evidence, :user_id),
      rotation_kind: evidence.rotation_kind,
      scope_kind: evidence.scope_kind,
      scope_id: evidence.scope_id,
      old_key_version: evidence.old_key_version,
      completion_manifest: Map.get(evidence, :completion_manifest),
      deletion_manifest: evidence.deletion_manifest,
      device_key_deletion_proofs: evidence.device_key_deletion_proofs,
      wipe_required_device_ids: Map.get(evidence, :wipe_required_device_ids)
    }
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Map.new()
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
