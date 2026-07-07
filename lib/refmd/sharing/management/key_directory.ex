defmodule RefMD.Sharing.Management.KeyDirectory do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Documents.Document
  alias RefMD.Encryption
  alias RefMD.Repo
  alias RefMD.Sharing.Share

  def parse_append(attrs) do
    events = dual_key_get(attrs, :workspace_key_directory_events)
    checkpoint = dual_key_get(attrs, :workspace_key_directory_checkpoint)

    if is_list(events) and is_map(checkpoint),
      do: {:ok, %{events: events, checkpoint: checkpoint}},
      else: {:error, :invalid_key_directory}
  end

  defp dual_key_get(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> value
      :error -> Map.get(attrs, Atom.to_string(key))
    end
  end

  def append_management!(
        share,
        %{events: events, checkpoint: checkpoint},
        event_type,
        update_attrs \\ nil
      ) do
    workspace_id = share_workspace_id!(share)
    body = validate_management_append!(share, events, event_type, update_attrs)

    Encryption.append_workspace_key_directory!(
      workspace_id,
      events,
      checkpoint,
      checkpoint_signer_kind: "device"
    )

    body
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  def append_scope!(share, %{events: events, checkpoint: checkpoint}, update_attrs) do
    workspace_id = share_workspace_id!(share)
    :ok = validate_scope_append!(share, events, update_attrs)

    Encryption.append_workspace_key_directory!(
      workspace_id,
      events,
      checkpoint,
      checkpoint_signer_kind: "device"
    )

    :ok
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  def latest_event_hash!(%{events: events}, event_type) when is_list(events) do
    %{"payload" => %{"event_type" => ^event_type} = payload} =
      Enum.find(events, &(get_in(&1, ["payload", "event_type"]) == event_type))

    Hash.blake3_base64url(JCS.canonical_bytes!(payload))
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  def signed_share_settings_update_attrs!(body, client_update_attrs) do
    signed_update_attrs = %{
      expires_event_sequence:
        expires_event_sequence_from_event_sequence!(body["expires_event_sequence"]),
      max_views: max_views_from_max_views!(body["max_views"])
    }

    if client_share_settings_match_signed?(client_update_attrs, signed_update_attrs) do
      signed_update_attrs
    else
      Repo.rollback(:invalid_key_directory)
    end
  end

  defp validate_management_append!(
         share,
         [
           %{"payload" => %{"event_type" => "share_exclusion_changed", "body" => body} = payload}
           | removed_events
         ],
         "share_exclusion_changed",
         update_attrs
       ) do
    workspace_id = share_workspace_id!(share)

    if management_event_base_matches?(share, body, workspace_id) and
         share_management_sequence_matches?(
           body,
           "share_exclusion_changed",
           payload["sequence"]
         ) and
         share_management_body_matches_update?(
           body,
           "share_exclusion_changed",
           workspace_id,
           update_attrs
         ) and
         share_scope_removed_events_match_update?(
           share,
           removed_events,
           update_attrs,
           workspace_id
         ) do
      body
    else
      Repo.rollback(:invalid_key_directory)
    end
  end

  defp validate_management_append!(
         share,
         [%{"payload" => %{"event_type" => event_type, "body" => body} = payload}],
         event_type,
         update_attrs
       ) do
    workspace_id = share_workspace_id!(share)

    if management_event_base_matches?(share, body, workspace_id) and
         share_management_sequence_matches?(body, event_type, payload["sequence"]) and
         share_management_body_matches_update?(body, event_type, workspace_id, update_attrs) do
      body
    else
      Repo.rollback(:invalid_key_directory)
    end
  end

  defp validate_management_append!(_share, _events, _event_type, _update_attrs),
    do: Repo.rollback(:invalid_key_directory)

  defp management_event_base_matches?(share, body, workspace_id) do
    body["workspace_id"] == workspace_id and body["share_id"] == share.id
  end

  defp share_scope_removed_events_match_update?(_share, [], %{add: []}, _workspace_id), do: true

  defp share_scope_removed_events_match_update?(
         share,
         removed_events,
         %{add: added_scope_ids},
         workspace_id
       ) do
    removed_by_scope_id =
      Map.new(removed_events, fn
        %{"payload" => %{"event_type" => "share_key_scope_removed", "body" => body} = payload} ->
          {body["scope_id"], {body, payload["sequence"]}}

        _ ->
          Repo.rollback(:invalid_key_directory)
      end)

    length(removed_events) == length(added_scope_ids) and
      Enum.all?(added_scope_ids, fn scope_id ->
        case Map.get(removed_by_scope_id, scope_id) do
          {body, sequence} ->
            share_scope_removed_body_matches?(share, body, workspace_id, scope_id, sequence)

          nil ->
            false
        end
      end)
  end

  defp share_scope_removed_body_matches?(share, body, workspace_id, scope_id, sequence) do
    document = Repo.get(Document, scope_id)

    body["workspace_id"] == workspace_id and
      body["share_id"] == share.id and
      body["share_key_version"] == 1 and
      body["scope_kind"] == document_scope_kind(document) and
      body["scope_id"] == scope_id and
      body["document_scope_hash"] == document_scope_hash(workspace_id, scope_id) and
      body["removed_reason"] == "share_exclusion_added" and
      body["removed_at_event_sequence"] == sequence
  end

  defp share_management_body_matches_update?(_body, _event_type, _workspace_id, nil), do: true

  defp share_management_body_matches_update?(
         body,
         "share_exclusion_changed",
         workspace_id,
         %{add: add, remove: remove}
       ) do
    body["added_scope_hashes"] == Enum.map(add, &document_scope_hash(workspace_id, &1)) and
      body["removed_scope_hashes"] == Enum.map(remove, &document_scope_hash(workspace_id, &1))
  end

  defp share_management_body_matches_update?(_body, _event_type, _workspace_id, _update_attrs),
    do: true

  defp share_management_sequence_matches?(body, "share_revoked", sequence),
    do: body["revoked_at_event_sequence"] == sequence

  defp share_management_sequence_matches?(body, "share_exclusion_changed", sequence),
    do: body["changed_at_event_sequence"] == sequence

  defp share_management_sequence_matches?(body, "share_metadata_updated", sequence),
    do: body["updated_at_event_sequence"] == sequence

  defp max_views_from_max_views!(max_views) when is_integer(max_views) and max_views > 0,
    do: max_views

  defp max_views_from_max_views!(_), do: Repo.rollback(:invalid_key_directory)

  defp expires_event_sequence_from_event_sequence!(sequence)
       when is_integer(sequence) and sequence > 0,
       do: sequence

  defp expires_event_sequence_from_event_sequence!(_), do: Repo.rollback(:invalid_key_directory)

  defp client_share_settings_match_signed?(client_attrs, signed_attrs) do
    Enum.all?(client_attrs, fn
      {:max_views, value} ->
        value == signed_attrs.max_views

      {:expires_event_sequence, value} ->
        value == signed_attrs.expires_event_sequence

      _ ->
        false
    end)
  rescue
    MatchError -> false
  end

  defp validate_scope_append!(share, events, update_attrs) do
    expected_add = length(update_attrs.add_keys)
    expected_replace = length(update_attrs.replace_keys)
    add_by_share_id = Map.new(update_attrs.add_keys, &{&1.share_id, &1})
    replace_by_share_id = Map.new(update_attrs.replace_keys, &{&1.share_id, &1})

    actual =
      Enum.reduce(events, %{add: 0, replace: 0}, fn
        %{"payload" => %{"event_type" => "share_key_scope_added", "body" => body} = payload},
        acc ->
          validate_share_scope_event_body!(
            share,
            body,
            add_by_share_id,
            "share_key_scope_added",
            payload["sequence"]
          )

          %{acc | add: acc.add + 1}

        %{"payload" => %{"event_type" => "share_key_scope_replaced", "body" => body} = payload},
        acc ->
          validate_share_scope_event_body!(
            share,
            body,
            replace_by_share_id,
            "share_key_scope_replaced",
            payload["sequence"]
          )

          %{acc | replace: acc.replace + 1}

        _event, _acc ->
          Repo.rollback(:invalid_key_directory)
      end)

    if actual.add == expected_add and actual.replace == expected_replace do
      :ok
    else
      Repo.rollback(:invalid_key_directory)
    end
  end

  defp validate_share_scope_event_body!(share, body, entries_by_share_id, event_type, sequence) do
    workspace_id = share_workspace_id!(share)
    entry = Map.get(entries_by_share_id, body["share_id"])

    if entry != nil and
         share_scope_event_body_matches_entry?(
           share,
           workspace_id,
           body,
           entry,
           event_type,
           sequence
         ) do
      :ok
    else
      Repo.rollback(:invalid_key_directory)
    end
  end

  defp share_scope_event_body_matches_entry?(
         share,
         workspace_id,
         body,
         entry,
         event_type,
         sequence
       ) do
    document = Repo.get(Document, entry.document_id)

    body["workspace_id"] == workspace_id and
      body["share_id"] == entry.share_id and
      body["scope_id"] == entry.document_id and
      body["scope_kind"] == document_scope_kind(document) and
      body["document_scope_hash"] == document_scope_hash(workspace_id, entry.document_id) and
      body["share_metadata_hash"] == share_scope_metadata_hash(entry) and
      share_scope_sequence_matches?(body, event_type, sequence) and
      share_scope_version_matches?(body, event_type) and
      share_scope_parent_matches?(share, body, event_type)
  end

  defp share_scope_sequence_matches?(body, "share_key_scope_added", sequence),
    do: body["added_at_event_sequence"] == sequence

  defp share_scope_sequence_matches?(body, "share_key_scope_replaced", sequence),
    do: body["replaced_at_event_sequence"] == sequence

  defp document_scope_kind(%Document{doc_type: doc_type}), do: doc_type
  defp document_scope_kind(_), do: nil

  defp share_scope_version_matches?(body, "share_key_scope_added"),
    do: body["share_key_version"] == 1 and not Map.has_key?(body, "previous_share_key_version")

  defp share_scope_version_matches?(body, "share_key_scope_replaced"),
    do: body["share_key_version"] == 1 and body["previous_share_key_version"] == 1

  defp share_scope_parent_matches?(share, body, "share_key_scope_added"),
    do: body["parent_share_id"] == share.id

  defp share_scope_parent_matches?(_share, body, "share_key_scope_replaced"),
    do: not Map.has_key?(body, "parent_share_id")

  defp document_scope_hash(workspace_id, document_id) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "workspace_id" => workspace_id,
        "document_id" => document_id || "unknown"
      })
    )
  end

  defp share_scope_metadata_hash(entry) do
    Hash.blake3_base64url(
      JCS.canonical_bytes!(%{
        "share_id" => entry.share_id,
        "encrypted_dek_hash" => Hash.blake3_base64url(entry.encrypted_dek),
        "nonce_hash" => Hash.blake3_base64url(entry.nonce)
      })
    )
  end

  defp share_workspace_id!(%Share{document_id: document_id}) do
    case Repo.get(Document, document_id) do
      %Document{workspace_id: workspace_id} -> workspace_id
      nil -> Repo.rollback(:not_found)
    end
  end
end
