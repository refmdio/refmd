defmodule RefMDWeb.Channels.StrictJSONSerializer do
  @moduledoc false
  @behaviour Phoenix.Socket.Serializer

  alias Phoenix.Socket.Message
  alias RefMD.Crypto.JCS

  @max_update_payload_raw_bytes 1_048_576
  @oversized_update_payload %{
    "_refmd_strict_json_error" => "document_update_payload_too_large"
  }

  @impl true
  defdelegate fastlane!(message), to: Phoenix.Socket.V2.JSONSerializer

  @impl true
  defdelegate encode!(message), to: Phoenix.Socket.V2.JSONSerializer

  @impl true
  def decode!(raw_message, opts) do
    case Keyword.fetch(opts, :opcode) do
      {:ok, :text} -> decode_text(IO.iodata_to_binary(raw_message))
      {:ok, :binary} -> raise ArgumentError, "phoenix_binary_frame_forbidden"
    end
  end

  defp decode_text(raw_message) do
    [join_ref_raw, ref_raw, topic_raw, event_raw, payload_raw] = split_v2_message!(raw_message)
    event = decode_string!(event_raw)
    payload = decode_payload(event, payload_raw)

    %Message{
      join_ref: decode_optional_string!(join_ref_raw),
      ref: decode_optional_string!(ref_raw),
      topic: decode_string!(topic_raw),
      event: event,
      payload: payload
    }
  end

  defp decode_payload("update", payload_raw)
       when byte_size(payload_raw) > @max_update_payload_raw_bytes do
    @oversized_update_payload
  end

  defp decode_payload(_event, payload_raw), do: JCS.parse_json_strict!(payload_raw)

  defp decode_optional_string!(raw) do
    case Jason.decode!(raw) do
      nil -> nil
      value when is_binary(value) -> value
      _ -> raise ArgumentError, "phoenix_protocol_field_invalid"
    end
  end

  defp decode_string!(raw) do
    case Jason.decode!(raw) do
      value when is_binary(value) -> value
      _ -> raise ArgumentError, "phoenix_protocol_field_invalid"
    end
  end

  defp split_v2_message!(raw_message) do
    length = byte_size(raw_message)
    index = skip_ws(raw_message, 0, length)
    require_byte!(raw_message, index, ?[, "phoenix_message_array_invalid")

    {join_ref_raw, index} = take_delimited_value(raw_message, index + 1, length)
    {ref_raw, index} = take_delimited_value(raw_message, index, length)
    {topic_raw, index} = take_delimited_value(raw_message, index, length)
    {event_raw, index} = take_delimited_value(raw_message, index, length)
    {payload_raw, index} = take_final_payload(raw_message, index, length)

    if skip_ws(raw_message, index, length) != length,
      do: raise(ArgumentError, "phoenix_message_array_invalid")

    [join_ref_raw, ref_raw, topic_raw, event_raw, payload_raw]
  end

  defp take_delimited_value(raw, index, length) do
    index = skip_ws(raw, index, length)
    {value, delimiter, index} = take_value(raw, index, length)
    if delimiter != ?,, do: raise(ArgumentError, "phoenix_message_array_invalid")
    {value, index + 1}
  end

  defp take_final_payload(raw, index, length) do
    start_index = skip_ws(raw, index, length)
    close_index = find_array_end(raw, length - 1)
    end_index = trim_value_end(raw, close_index)
    if start_index >= end_index, do: raise(ArgumentError, "phoenix_message_array_invalid")
    {binary_part(raw, start_index, end_index - start_index), close_index + 1}
  end

  defp take_value(raw, index, length) do
    {delimiter, end_index} = scan_value(raw, index, length, 0)

    if end_index == index do
      raise ArgumentError, "phoenix_message_array_invalid"
    end

    {binary_part(raw, index, end_index - index), delimiter, end_index}
  end

  defp scan_value(raw, index, length, depth) when index < length do
    byte = :binary.at(raw, index)

    cond do
      byte == ?" ->
        scan_string(raw, index + 1, length, depth)

      byte in [?{, ?[] ->
        scan_value(raw, index + 1, length, depth + 1)

      byte in [?}, ?]] and depth > 0 ->
        scan_value(raw, index + 1, length, depth - 1)

      byte in [?,, ?]] and depth == 0 ->
        {byte, trim_value_end(raw, index)}

      true ->
        scan_value(raw, index + 1, length, depth)
    end
  end

  defp scan_value(_raw, _index, _length, _depth),
    do: raise(ArgumentError, "phoenix_message_array_invalid")

  defp scan_string(raw, index, length, depth) when index < length do
    case :binary.at(raw, index) do
      ?\\ -> scan_string_escaped(raw, index + 1, length, depth)
      ?" -> scan_value(raw, index + 1, length, depth)
      _ -> scan_string(raw, index + 1, length, depth)
    end
  end

  defp scan_string(_raw, _index, _length, _depth),
    do: raise(ArgumentError, "phoenix_message_array_invalid")

  defp scan_string_escaped(raw, index, length, depth) when index < length,
    do: scan_string(raw, index + 1, length, depth)

  defp scan_string_escaped(_raw, _index, _length, _depth),
    do: raise(ArgumentError, "phoenix_message_array_invalid")

  defp trim_value_end(raw, index) when index > 0 do
    previous_index = index - 1

    if whitespace?(:binary.at(raw, previous_index)) do
      trim_value_end(raw, previous_index)
    else
      index
    end
  end

  defp trim_value_end(_raw, index), do: index

  defp find_array_end(raw, index) when index >= 0 do
    cond do
      whitespace?(:binary.at(raw, index)) ->
        find_array_end(raw, index - 1)

      :binary.at(raw, index) == ?] ->
        index

      true ->
        raise ArgumentError, "phoenix_message_array_invalid"
    end
  end

  defp find_array_end(_raw, _index), do: raise(ArgumentError, "phoenix_message_array_invalid")

  defp skip_ws(raw, index, length) when index < length do
    if whitespace?(:binary.at(raw, index)),
      do: skip_ws(raw, index + 1, length),
      else: index
  end

  defp skip_ws(_raw, index, _length), do: index

  defp require_byte!(raw, index, byte, message) do
    if index < byte_size(raw) and :binary.at(raw, index) == byte do
      :ok
    else
      raise ArgumentError, message
    end
  end

  defp whitespace?(byte), do: byte in [?\s, ?\n, ?\r, ?\t]
end
