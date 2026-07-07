defmodule RefMD.Documents.WriteStateAdmission do
  @moduledoc false

  alias RefMD.Documents.Document
  alias RefMD.Encryption
  alias RefMD.Encryption.KeyDirectory.Envelope
  alias RefMD.Repo

  @event_type "document_write_state_changed"

  def parse_append(attrs) do
    events = dual_key_get(attrs, :workspace_key_directory_events)
    checkpoint = dual_key_get(attrs, :workspace_key_directory_checkpoint)

    if is_list(events) and is_map(checkpoint),
      do: {:ok, %{events: events, checkpoint: checkpoint}},
      else: {:error, :invalid_key_directory}
  end

  def append!(%Document{} = document, %{events: events, checkpoint: checkpoint}, affected, reason)
      when is_list(events) and is_list(affected) and is_binary(reason) do
    validate_events!(document, events, affected, reason)

    Encryption.append_workspace_key_directory!(
      document.workspace_id,
      events,
      checkpoint,
      checkpoint_signer_kind: "device"
    )

    :ok
  rescue
    _ -> Repo.rollback(:invalid_key_directory)
  end

  defp dual_key_get(attrs, key) do
    case Map.fetch(attrs, key) do
      {:ok, value} -> value
      :error -> Map.get(attrs, Atom.to_string(key))
    end
  end

  defp validate_events!(document, events, affected, reason) do
    expected =
      Map.new(affected, fn entry ->
        {entry.id,
         %{
           "previous_write_state" => entry.previous_write_state,
           "write_state" => entry.write_state
         }}
      end)

    bodies =
      Enum.map(events, fn envelope ->
        payload = Envelope.payload!(envelope, :event)
        body = payload["body"]

        true = payload["scope_kind"] == "workspace"
        true = payload["scope_id"] == document.workspace_id
        true = payload["event_type"] == @event_type
        true = body["event_type"] == @event_type
        true = body["workspace_id"] == document.workspace_id
        true = body["reason"] == reason
        true = body["previous_workspace_event_sequence"] == payload["sequence"] - 1
        true = body["previous_workspace_event_hash"] == payload["previous_event_hash"]

        {body["document_id"], body}
      end)

    document_ids = Enum.map(bodies, fn {document_id, _body} -> document_id end)
    true = MapSet.new(Map.keys(expected)) == MapSet.new(document_ids)
    true = MapSet.size(MapSet.new(document_ids)) == length(document_ids)

    Enum.each(bodies, fn {document_id, body} ->
      expected_body = Map.fetch!(expected, document_id)
      true = body["previous_write_state"] == expected_body["previous_write_state"]
      true = body["write_state"] == expected_body["write_state"]
    end)
  end
end
