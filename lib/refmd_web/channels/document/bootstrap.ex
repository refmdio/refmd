defmodule RefMDWeb.Channels.Document.Bootstrap do
  @moduledoc false

  alias RefMD.Documents
  alias RefMD.Public
  alias RefMD.Sharing
  alias RefMD.Workspaces
  alias RefMDWeb.Channels.Document.Access
  alias RefMDWeb.Channels.Document.Envelope

  @spec load_for_join(map(), map(), Phoenix.Socket.t(), Ecto.UUID.t() | nil, Ecto.UUID.t()) ::
          {:ok, map()} | {:error, %{reason: String.t()}}
  def load_for_join(document, params, socket, mounted_share_id, user_id) do
    if socket.assigns[:session_kind] == :share_participant do
      load_share_initial_data(
        document,
        params,
        mounted_share_id || socket.assigns.current_share_id
      )
    else
      load_initial_data(document, params, document.workspace_id, user_id, socket)
    end
  end

  @spec validate_join_params(map()) :: :ok | {:error, %{reason: String.t()}}
  def validate_join_params(%{"mode" => "delta"} = params) do
    with :ok <- validate_exact_join_keys(params),
         :ok <- validate_optional_join_uuid(params, "knownSnapshotId") do
      case params["knownSnapshotUpdateClocks"] do
        clocks when is_map(clocks) -> validate_clock_values(clocks)
        _ -> {:error, %{reason: "knownSnapshotUpdateClocks required for delta mode"}}
      end
    end
  end

  def validate_join_params(%{"mode" => "complete"} = params),
    do:
      with(
        :ok <- validate_exact_join_keys(params),
        do: validate_optional_join_uuid(params, "knownSnapshotId")
      )

  def validate_join_params(%{"mode" => nil} = params),
    do:
      with(
        :ok <- validate_exact_join_keys(params),
        do: validate_optional_join_uuid(params, "knownSnapshotId")
      )

  def validate_join_params(%{"mode" => _}), do: {:error, %{reason: "invalid mode"}}

  def validate_join_params(params) do
    with :ok <- validate_exact_join_keys(params) do
      validate_optional_join_uuid(params, "knownSnapshotId")
    end
  end

  defp load_initial_data(document, params, workspace_id, user_id, socket) do
    mode = params["mode"] || "complete"

    case Documents.get_initial_document_data(document.id, workspace_id, user_id, params) do
      {:error, :unauthorized} ->
        {:error, %{reason: "permission_denied"}}

      {:error, :db_error} ->
        {:error, %{reason: "document_error"}}

      {:ok, {snapshot, all_updates}} ->
        initial_data =
          document.id
          |> build_initial_data(snapshot, all_updates, mode, params)
          |> Map.put(:archived, !is_nil(document.archived_at))
          |> Map.put(:readOnly, !Access.workspace_write_allowed?(document, user_id))
          |> Map.put(
            :authorityPermissionVersion,
            Workspaces.get_member_permission_version(document.workspace_id, user_id)
          )
          |> Map.put(
            :publicState,
            document.id
            |> Public.get_public_state()
            |> Map.put(
              :can_sync,
              Access.publication_sync_allowed?(document, user_id, socket, nil)
            )
          )

        {:ok, initial_data}
    end
  end

  @spec load_share_initial_data(map(), map(), Ecto.UUID.t()) ::
          {:ok, map()} | {:error, %{reason: String.t()}}
  def load_share_initial_data(document, params, share_id) do
    mode = params["mode"] || "complete"

    case Documents.get_initial_document_data_for_share(document.id, share_id, params) do
      {:ok, {snapshot, all_updates}} ->
        initial_data =
          document.id
          |> build_initial_data(snapshot, all_updates, mode, params)
          |> Map.put(:archived, !is_nil(document.archived_at))
          |> Map.put(:readOnly, !Sharing.can_write_document?(share_id, document.id))
          |> Map.put(:authorityPermissionVersion, Sharing.get_share_permission_version(share_id))

        {:ok, initial_data}

      {:error, :unauthorized} ->
        {:error, %{reason: "permission_denied"}}

      {:error, :db_error} ->
        {:error, %{reason: "document_error"}}
    end
  end

  defp build_initial_data(document_id, snapshot, all_updates, mode, params) do
    updates = filter_updates(snapshot, all_updates, mode, params)
    snapshot_id = if snapshot, do: snapshot.id
    delta_same = mode == "delta" && params["knownSnapshotId"] == snapshot_id
    latest_version = if snapshot, do: snapshot.latest_version, else: 0

    proof_chain =
      Documents.build_snapshot_proof_chain(
        document_id,
        params["knownSnapshotId"],
        snapshot_id
      )

    %{
      snapshot:
        if(delta_same, do: nil, else: Envelope.format_snapshot(snapshot, snapshot_opts(params))),
      updates: Envelope.format_initial_updates(updates, !delta_same and !is_nil(snapshot)),
      snapshotProofChain: proof_chain,
      proofChainHash: if(snapshot, do: snapshot.proof_chain_hash),
      ciphertextHash: if(snapshot, do: snapshot.ciphertext_hash),
      snapshotAdmissionEventHash: if(snapshot, do: snapshot.snapshot_admission_event_hash),
      latestVersion: latest_version
    }
  end

  defp filter_updates(_snapshot, updates, "complete", _params), do: updates

  defp filter_updates(snapshot, updates, "delta", params) do
    known_clocks = params["knownSnapshotUpdateClocks"]
    known_snapshot_id = params["knownSnapshotId"]
    same_snapshot = snapshot && known_snapshot_id == snapshot.id

    cond do
      is_nil(snapshot) -> []
      !same_snapshot -> updates
      true -> filter_by_clocks(updates, known_clocks)
    end
  end

  defp filter_updates(_snapshot, updates, _mode, _params), do: updates

  defp snapshot_opts(%{"authenticated_workspace_pin_bootstrap_hash" => hash})
       when is_binary(hash),
       do: [current_incremental: true]

  defp snapshot_opts(_params), do: []

  defp filter_by_clocks(updates, known_clocks) do
    Enum.filter(updates, fn u ->
      clock_key = "#{u.authority_context_key}:#{u.signing_key_id}"
      u.clock > Map.get(known_clocks, clock_key, -1)
    end)
  end

  defp validate_optional_join_uuid(params, key) do
    case params[key] do
      nil ->
        :ok

      v when is_binary(v) ->
        case Ecto.UUID.cast(v) do
          {:ok, _} -> :ok
          :error -> {:error, %{reason: "invalid_#{key}"}}
        end

      _ ->
        {:error, %{reason: "invalid_#{key}"}}
    end
  end

  defp validate_exact_join_keys(params) do
    allowed = [
      "knownSnapshotId",
      "knownSnapshotUpdateClocks",
      "mode",
      "mount_id",
      "authenticated_workspace_pin_bootstrap_hash",
      "pop_actor_variant",
      "pop_challenge",
      "pop_device_id",
      "pop_signature",
      "share_id",
      "silent"
    ]

    if Enum.all?(Map.keys(params), &(&1 in allowed)) do
      :ok
    else
      {:error, %{reason: "unexpected_join_keys"}}
    end
  end

  defp validate_clock_values(clocks) do
    if Enum.all?(clocks, fn {_k, v} -> is_integer(v) end) do
      :ok
    else
      {:error, %{reason: "knownSnapshotUpdateClocks values must be integers"}}
    end
  end
end
