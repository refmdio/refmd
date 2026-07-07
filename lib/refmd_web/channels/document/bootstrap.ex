defmodule RefMDWeb.Channels.Document.Bootstrap do
  @moduledoc false

  alias RefMD.Documents
  alias RefMD.Public
  alias RefMD.Sharing
  alias RefMD.Workspaces
  alias RefMDWeb.Channels.Document.Access
  alias RefMDWeb.Channels.Document.Envelope

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

  def validate_join_params(%{"mode" => "delta"} = params) do
    with :ok <- validate_exact_join_keys(params),
         :ok <- validate_optional_join_uuid(params, "knownSnapshotId"),
         :ok <- validate_required_workspace_pin_anchor(params) do
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
        :ok <- validate_optional_join_uuid(params, "knownSnapshotId"),
        do: validate_required_workspace_pin_anchor(params)
      )

  def validate_join_params(%{"mode" => nil} = params),
    do:
      with(
        :ok <- validate_exact_join_keys(params),
        :ok <- validate_optional_join_uuid(params, "knownSnapshotId"),
        do: validate_required_workspace_pin_anchor(params)
      )

  def validate_join_params(%{"mode" => _}), do: {:error, %{reason: "invalid mode"}}

  def validate_join_params(params) do
    with :ok <- validate_exact_join_keys(params),
         :ok <- validate_optional_join_uuid(params, "knownSnapshotId") do
      validate_required_workspace_pin_anchor(params)
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
        with {:ok, initial_data} <-
               safe_build_initial_data(document, snapshot, all_updates, mode, params) do
          initial_data =
            initial_data
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
  end

  def load_share_initial_data(document, params, share_id) do
    mode = params["mode"] || "complete"

    case Documents.get_initial_document_data_for_share(document.id, share_id, params) do
      {:ok, {snapshot, all_updates}} ->
        with {:ok, initial_data} <-
               safe_build_initial_data(document, snapshot, all_updates, mode, params) do
          initial_data =
            initial_data
            |> Map.put(:archived, !is_nil(document.archived_at))
            |> Map.put(:readOnly, !Sharing.can_write_document?(share_id, document.id))
            |> Map.put(
              :authorityPermissionVersion,
              Sharing.get_share_permission_version(share_id)
            )

          {:ok, initial_data}
        end

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
    admission_opts = admission_opts(params)
    sends_snapshot? = !delta_same and !is_nil(snapshot)

    proof_chain =
      Documents.build_snapshot_proof_chain(
        document_id,
        params["knownSnapshotId"],
        snapshot_id
      )

    %{
      snapshot: if(sends_snapshot?, do: Envelope.format_snapshot(snapshot, admission_opts)),
      updates:
        Envelope.format_initial_updates(
          updates,
          sends_snapshot?,
          admission_opts
        ),
      snapshotProofChain: proof_chain,
      proofChainHash: if(snapshot, do: snapshot.proof_chain_hash),
      ciphertextHash: if(snapshot, do: snapshot.ciphertext_hash),
      snapshotAdmissionEventHash: if(snapshot, do: snapshot.snapshot_admission_event_hash),
      latestVersion: latest_version
    }
  end

  defp safe_build_initial_data(document, snapshot, all_updates, mode, params) do
    {:ok, build_initial_data(document.id, snapshot, all_updates, mode, params)}
  rescue
    error in ArgumentError ->
      if key_directory_anchor_error?(error) do
        {:error, %{reason: "workspace_key_directory_refresh_required"}}
      else
        {:error, %{reason: "document_error"}}
      end
  end

  defp key_directory_anchor_error?(%ArgumentError{message: "document_admission_anchor_required"}),
    do: true

  defp key_directory_anchor_error?(_), do: false

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

  defp admission_opts(%{
         "workspaceKeyDirectoryPinSequence" => sequence,
         "workspaceKeyDirectoryPinHash" => hash
       })
       when is_integer(sequence) and sequence > 0 and is_binary(hash) do
    [from_checkpoint_sequence: sequence, from_checkpoint_hash: hash]
  end

  defp admission_opts(_params), do: []

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

  defp validate_required_workspace_pin_anchor(params) do
    sequence = params["workspaceKeyDirectoryPinSequence"]
    hash = params["workspaceKeyDirectoryPinHash"]

    cond do
      is_nil(sequence) and is_nil(hash) ->
        {:error, %{reason: "workspaceKeyDirectoryPin required"}}

      is_integer(sequence) and sequence > 0 and is_binary(hash) and
        byte_size(hash) == 43 and Regex.match?(~r/^[A-Za-z0-9\-_]+$/, hash) ->
        :ok

      true ->
        {:error, %{reason: "invalid_workspaceKeyDirectoryPin"}}
    end
  end

  defp validate_exact_join_keys(params) do
    allowed = [
      "knownSnapshotId",
      "knownSnapshotUpdateClocks",
      "mode",
      "mount_id",
      "authenticated_workspace_pin_bootstrap_hash",
      "workspaceKeyDirectoryPinHash",
      "workspaceKeyDirectoryPinSequence",
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
