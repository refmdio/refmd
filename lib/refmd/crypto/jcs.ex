defmodule RefMD.Crypto.JCS do
  @moduledoc false

  @max_safe_json_integer 9_007_199_254_740_991

  @spec canonicalize!(map()) :: binary()
  def canonicalize!(value) when is_map(value), do: encode_value(value, true)
  def canonicalize!(_), do: raise(ArgumentError, "jcs_root_must_be_object")

  @spec canonical_bytes!(map()) :: binary()
  def canonical_bytes!(value), do: canonicalize!(value)

  @spec canonical_value_bytes!(term()) :: binary()
  def canonical_value_bytes!(value), do: encode_value(value, false)

  @spec parse_json_strict!(binary()) :: map()
  def parse_json_strict!(raw) when is_binary(raw) do
    {value, rest} = parse_value(raw)
    rest = skip_ws(rest)
    if rest != "", do: raise(ArgumentError, "json_trailing_data")
    if not is_map(value), do: raise(ArgumentError, "jcs_root_must_be_object")
    value
  end

  defp encode_value(value, root?) when is_map(value) do
    if !root? && not plain_string_key_map?(value) do
      raise ArgumentError, "jcs_object_key_must_be_string"
    end

    value
    |> Enum.map(fn
      {key, item} when is_binary(key) -> {key, item}
      _ -> raise ArgumentError, "jcs_object_key_must_be_string"
    end)
    |> Enum.sort_by(fn {key, _} -> key end, &utf8_lte?/2)
    |> Enum.map_join(",", fn {key, item} ->
      quote_string!(key) <> ":" <> encode_value(item, false)
    end)
    |> then(&("{" <> &1 <> "}"))
  end

  defp encode_value(value, _root?) when is_list(value) do
    "[" <> Enum.map_join(value, ",", &encode_value(&1, false)) <> "]"
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

    value
    |> String.to_charlist()
    |> Enum.map(fn
      ?" ->
        "\\\""

      ?\\ ->
        "\\\\"

      ?\b ->
        "\\b"

      ?\f ->
        "\\f"

      ?\n ->
        "\\n"

      ?\r ->
        "\\r"

      ?\t ->
        "\\t"

      code when code <= 0x1F ->
        "\\u" <> String.pad_leading(Integer.to_string(code, 16) |> String.downcase(), 4, "0")

      code ->
        <<code::utf8>>
    end)
    |> IO.iodata_to_binary()
    |> then(&("\"" <> &1 <> "\""))
  end

  defp assert_valid_string!(value) do
    if String.valid?(value), do: :ok, else: raise(ArgumentError, "jcs_invalid_unicode")
  end

  defp parse_value(raw) do
    raw = skip_ws(raw)

    case raw do
      <<"{" <> rest>> -> parse_object(rest)
      <<"[" <> rest>> -> parse_array(rest)
      <<"\"" <> rest>> -> parse_string(rest, "")
      _ -> parse_scalar_value(raw)
    end
  end

  defp parse_scalar_value(raw) do
    case raw do
      <<"true", rest::binary>> -> {true, rest}
      <<"false", rest::binary>> -> {false, rest}
      <<"null", _::binary>> -> raise ArgumentError, "jcs_null_rejected"
      <<"-", _::binary>> -> raise ArgumentError, "jcs_negative_integer_rejected"
      <<char, _::binary>> when char in ?0..?9 -> parse_integer(raw)
      _ -> raise ArgumentError, "json_unexpected_token"
    end
  end

  defp parse_object(raw) do
    raw = skip_ws(raw)

    if String.starts_with?(raw, "}"),
      do: {%{}, binary_part(raw, 1, byte_size(raw) - 1)},
      else: parse_object_pairs(raw, %{}, %{})
  end

  @spec parse_object_pairs(binary(), map(), map()) :: {map(), binary()}
  defp parse_object_pairs(raw, acc, seen) do
    raw = skip_ws(raw)
    unless String.starts_with?(raw, "\""), do: raise(ArgumentError, "json_unexpected_token")
    {key, raw} = parse_string(binary_part(raw, 1, byte_size(raw) - 1), "")
    if Map.has_key?(seen, key), do: raise(ArgumentError, "json_duplicate_key")
    raw = skip_ws(raw)
    unless String.starts_with?(raw, ":"), do: raise(ArgumentError, "json_unexpected_token")
    {value, raw} = parse_value(binary_part(raw, 1, byte_size(raw) - 1))
    raw = skip_ws(raw)
    acc = Map.put(acc, key, value)
    seen = Map.put(seen, key, true)

    cond do
      String.starts_with?(raw, "}") ->
        {acc, binary_part(raw, 1, byte_size(raw) - 1)}

      String.starts_with?(raw, ",") ->
        parse_object_pairs(binary_part(raw, 1, byte_size(raw) - 1), acc, seen)

      true ->
        raise ArgumentError, "json_unexpected_token"
    end
  end

  defp parse_array(raw) do
    raw = skip_ws(raw)

    if String.starts_with?(raw, "]"),
      do: {[], binary_part(raw, 1, byte_size(raw) - 1)},
      else: parse_array_items(raw, [])
  end

  defp parse_array_items(raw, acc) do
    {value, raw} = parse_value(raw)
    raw = skip_ws(raw)

    cond do
      String.starts_with?(raw, "]") ->
        {Enum.reverse([value | acc]), binary_part(raw, 1, byte_size(raw) - 1)}

      String.starts_with?(raw, ",") ->
        parse_array_items(binary_part(raw, 1, byte_size(raw) - 1), [value | acc])

      true ->
        raise ArgumentError, "json_unexpected_token"
    end
  end

  defp parse_string(<<"\"" <> rest>>, acc), do: finish_string(acc, rest)

  defp parse_string(<<"\\" <> rest>>, acc) do
    {escaped, rest} = parse_escape(rest)
    parse_string(rest, acc <> escaped)
  end

  defp parse_string(<<char::utf8, rest::binary>>, acc) when char > 0x1F do
    parse_string(rest, acc <> <<char::utf8>>)
  end

  defp parse_string(<<_char, _rest::binary>>, _acc),
    do: raise(ArgumentError, "json_unescaped_control")

  defp parse_string(<<>>, _acc), do: raise(ArgumentError, "json_unterminated_string")

  defp finish_string(acc, rest) do
    assert_valid_string!(acc)
    {acc, rest}
  end

  defp parse_escape(<<"\"", rest::binary>>), do: {"\"", rest}
  defp parse_escape(<<"\\", rest::binary>>), do: {"\\", rest}
  defp parse_escape(<<"/", rest::binary>>), do: {"/", rest}
  defp parse_escape(<<"b", rest::binary>>), do: {"\b", rest}
  defp parse_escape(<<"f", rest::binary>>), do: {"\f", rest}
  defp parse_escape(<<"n", rest::binary>>), do: {"\n", rest}
  defp parse_escape(<<"r", rest::binary>>), do: {"\r", rest}
  defp parse_escape(<<"t", rest::binary>>), do: {"\t", rest}

  defp parse_escape(<<"u", hex::binary-size(4), rest::binary>>) do
    code = parse_hex4!(hex)

    cond do
      code in 0xD800..0xDBFF ->
        parse_low_surrogate!(code, rest)

      code in 0xDC00..0xDFFF ->
        raise ArgumentError, "jcs_invalid_unicode"

      true ->
        {<<code::utf8>>, rest}
    end
  end

  defp parse_escape(_), do: raise(ArgumentError, "json_invalid_escape")

  defp parse_low_surrogate!(high, <<"\\u", low_hex::binary-size(4), rest::binary>>) do
    low = parse_hex4!(low_hex)
    if low not in 0xDC00..0xDFFF, do: raise(ArgumentError, "jcs_invalid_unicode")
    scalar = 0x10000 + (high - 0xD800) * 0x400 + (low - 0xDC00)
    {<<scalar::utf8>>, rest}
  end

  defp parse_low_surrogate!(_, _), do: raise(ArgumentError, "jcs_invalid_unicode")

  defp parse_hex4!(hex) do
    if Regex.match?(~r/^[0-9a-fA-F]{4}$/, hex) do
      String.to_integer(hex, 16)
    else
      raise ArgumentError, "json_invalid_unicode_escape"
    end
  end

  defp parse_integer(<<"0", rest::binary>>) do
    case rest do
      <<char, _::binary>> when char in ?0..?9 -> raise ArgumentError, "json_invalid_integer"
      <<"." <> _::binary>> -> raise ArgumentError, "json_invalid_number_form"
      <<"e" <> _::binary>> -> raise ArgumentError, "json_invalid_number_form"
      <<"E" <> _::binary>> -> raise ArgumentError, "json_invalid_number_form"
      _ -> {0, rest}
    end
  end

  defp parse_integer(raw) do
    {digits, rest} = take_digits(raw, "")

    case rest do
      <<"." <> _::binary>> -> raise ArgumentError, "json_invalid_number_form"
      <<"e" <> _::binary>> -> raise ArgumentError, "json_invalid_number_form"
      <<"E" <> _::binary>> -> raise ArgumentError, "json_invalid_number_form"
      _ -> :ok
    end

    value = String.to_integer(digits)
    if value > @max_safe_json_integer, do: raise(ArgumentError, "jcs_invalid_integer")
    {value, rest}
  end

  defp take_digits(<<char, rest::binary>>, acc) when char in ?0..?9 do
    take_digits(rest, acc <> <<char>>)
  end

  defp take_digits(rest, acc), do: {acc, rest}

  defp skip_ws(<<char, rest::binary>>) when char in [?\s, ?\t, ?\n, ?\r], do: skip_ws(rest)
  defp skip_ws(rest), do: rest
end
