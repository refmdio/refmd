defmodule RefMD.Crypto.JCS do
  @moduledoc false

  @max_safe_json_integer 9_007_199_254_740_991

  def canonicalize!(value) when is_map(value) do
    value
    |> encode_value(true)
    |> IO.iodata_to_binary()
  end

  def canonicalize!(_), do: raise(ArgumentError, "jcs_root_must_be_object")

  def canonical_bytes!(value), do: canonicalize!(value)

  def canonical_value_bytes!(value) do
    value
    |> encode_value(false)
    |> IO.iodata_to_binary()
  end

  def parse_json_strict!(raw) when is_binary(raw) do
    reject_negative_number_tokens!(raw, 0, byte_size(raw))

    raw
    |> Jason.decode!(objects: :ordered_objects)
    |> strict_decoded_root!()
  rescue
    _ in Jason.DecodeError ->
      reraise ArgumentError, [message: "json_unexpected_token"], __STACKTRACE__
  end

  defp encode_value(value, root?) when is_map(value) do
    if !root? && not plain_string_key_map?(value) do
      raise ArgumentError, "jcs_object_key_must_be_string"
    end

    members =
      value
      |> Enum.map(fn
        {key, item} when is_binary(key) -> {key, item}
        _ -> raise ArgumentError, "jcs_object_key_must_be_string"
      end)
      |> Enum.sort_by(fn {key, _} -> key end, &utf8_lte?/2)
      |> Enum.map(fn {key, item} ->
        [quote_string!(key), ?:, encode_value(item, false)]
      end)

    [?{, Enum.intersperse(members, ?,), ?}]
  end

  defp encode_value(value, _root?) when is_list(value) do
    [?[, value |> Enum.map(&encode_value(&1, false)) |> Enum.intersperse(?,), ?]]
  end

  defp encode_value(value, _root?) when is_binary(value), do: quote_string!(value)
  defp encode_value(true, _root?), do: "true"
  defp encode_value(false, _root?), do: "false"

  defp encode_value(value, _root?) when is_integer(value) do
    if value < 0 or value > @max_safe_json_integer do
      raise ArgumentError, "jcs_invalid_integer"
    end

    Integer.to_string(value)
  end

  defp encode_value(nil, _root?), do: raise(ArgumentError, "jcs_null_rejected")

  defp encode_value(value, _root?) when is_float(value),
    do: raise(ArgumentError, "jcs_invalid_integer")

  defp encode_value(_, _root?), do: raise(ArgumentError, "jcs_unsupported_value")

  defp plain_string_key_map?(map), do: Enum.all?(map, fn {key, _} -> is_binary(key) end)

  defp utf8_lte?(left, right), do: left <= right

  defp quote_string!(value) do
    assert_valid_string!(value)

    if escape_required?(value) do
      IO.iodata_to_binary([?", escape_string(value), ?"])
    else
      <<?", value::binary, ?">>
    end
  end

  defp assert_valid_string!(value) do
    if String.valid?(value), do: :ok, else: raise(ArgumentError, "jcs_invalid_unicode")
  end

  defp escape_required?(<<>>), do: false
  defp escape_required?(<<?", _::binary>>), do: true
  defp escape_required?(<<?\\, _::binary>>), do: true
  defp escape_required?(<<code, _::binary>>) when code <= 0x1F, do: true
  defp escape_required?(<<_code, rest::binary>>), do: escape_required?(rest)

  defp escape_string(<<>>), do: []
  defp escape_string(<<?", rest::binary>>), do: ["\\\"" | escape_string(rest)]
  defp escape_string(<<?\\, rest::binary>>), do: ["\\\\" | escape_string(rest)]
  defp escape_string(<<?\b, rest::binary>>), do: ["\\b" | escape_string(rest)]
  defp escape_string(<<?\f, rest::binary>>), do: ["\\f" | escape_string(rest)]
  defp escape_string(<<?\n, rest::binary>>), do: ["\\n" | escape_string(rest)]
  defp escape_string(<<?\r, rest::binary>>), do: ["\\r" | escape_string(rest)]
  defp escape_string(<<?\t, rest::binary>>), do: ["\\t" | escape_string(rest)]

  defp escape_string(<<code, rest::binary>>) when code <= 0x1F do
    [
      "\\u",
      code |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(4, "0")
      | escape_string(rest)
    ]
  end

  defp escape_string(<<code, rest::binary>>), do: [code | escape_string(rest)]

  defp strict_decoded_root!(%Jason.OrderedObject{} = value), do: strict_decoded_object!(value)
  defp strict_decoded_root!(_), do: raise(ArgumentError, "jcs_root_must_be_object")

  defp strict_decoded_value!(%Jason.OrderedObject{} = value), do: strict_decoded_object!(value)

  defp strict_decoded_value!(value) when is_list(value),
    do: Enum.map(value, &strict_decoded_value!/1)

  defp strict_decoded_value!(value) when is_binary(value), do: value

  defp strict_decoded_value!(value) when is_boolean(value), do: value

  defp strict_decoded_value!(value) when is_integer(value) do
    if value < 0 or value > @max_safe_json_integer do
      raise ArgumentError, "jcs_invalid_integer"
    end

    value
  end

  defp strict_decoded_value!(nil), do: raise(ArgumentError, "jcs_null_rejected")

  defp strict_decoded_value!(value) when is_float(value),
    do: raise(ArgumentError, "json_invalid_number_form")

  defp strict_decoded_value!(_), do: raise(ArgumentError, "jcs_unsupported_value")

  defp strict_decoded_object!(%Jason.OrderedObject{values: values}) do
    {object, _seen} =
      Enum.reduce(values, {%{}, MapSet.new()}, fn
        {key, value}, {object, seen} when is_binary(key) ->
          if MapSet.member?(seen, key), do: raise(ArgumentError, "json_duplicate_key")
          {Map.put(object, key, strict_decoded_value!(value)), MapSet.put(seen, key)}

        _entry, _acc ->
          raise ArgumentError, "jcs_object_key_must_be_string"
      end)

    object
  end

  defp reject_negative_number_tokens!(raw, index, length) when index < length do
    case :binary.match(raw, "\"", scope: {index, length - index}) do
      {quote_index, 1} ->
        reject_negative_number_segment!(raw, index, quote_index)

        reject_negative_number_tokens!(
          raw,
          skip_json_string_token!(raw, quote_index + 1, length),
          length
        )

      :nomatch ->
        reject_negative_number_segment!(raw, index, length)
    end
  end

  defp reject_negative_number_tokens!(_raw, _index, _length), do: :ok

  defp reject_negative_number_segment!(raw, start_index, end_index) do
    if :binary.match(raw, "-", scope: {start_index, end_index - start_index}) != :nomatch do
      raise ArgumentError, "jcs_negative_integer_rejected"
    end
  end

  defp skip_json_string_token!(raw, index, length) do
    case :binary.match(raw, "\"", scope: {index, length - index}) do
      {quote_index, 1} ->
        if escaped_quote?(raw, quote_index) do
          skip_json_string_token!(raw, quote_index + 1, length)
        else
          quote_index + 1
        end

      :nomatch ->
        raise ArgumentError, "json_unterminated_string"
    end
  end

  defp escaped_quote?(raw, quote_index), do: odd_backslash_count_before?(raw, quote_index - 1, 0)

  defp odd_backslash_count_before?(_raw, index, count) when index < 0, do: rem(count, 2) == 1

  defp odd_backslash_count_before?(raw, index, count) do
    if :binary.at(raw, index) == ?\\ do
      odd_backslash_count_before?(raw, index - 1, count + 1)
    else
      rem(count, 2) == 1
    end
  end
end
