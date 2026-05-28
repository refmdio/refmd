defmodule RefMD.Plugins.JavaScriptSource do
  @moduledoc false

  @script_breakout_error :plugin_script_inline_forbidden
  @code_tokens ["/", "\"", "'", "`", "<", "-"]
  @line_comment_end "\n"
  @block_comment_end "*/"
  @double_quote_string_tokens ["\\", "\""]
  @single_quote_string_tokens ["\\", "'"]
  @template_tokens ["\\", "`", "$"]
  @template_expr_tokens ["/", "\"", "'", "`", "<", "-", "{", "}"]
  @regex_tokens ["\\", "[", "]", "/"]
  @non_code_escape_tokens ["<", "-"]

  @spec unsafe_control_character?(String.t()) :: boolean()
  def unsafe_control_character?(source) do
    unsafe_control_character_binary?(source)
  end

  @spec mask_non_code(String.t()) :: String.t()
  def mask_non_code(source) when is_binary(source) do
    source
    |> scan(:mask)
    |> elem(1)
  end

  @spec escape_inline_script(String.t()) :: {:ok, String.t()} | {:error, atom()}
  def escape_inline_script(source) when is_binary(source) do
    scan(source, :escape)
  end

  @spec escape_inline_script(String.t(), String.t()) :: {:ok, String.t()} | {:error, atom()}
  def escape_inline_script(source, normalized_source)
      when is_binary(source) and is_binary(normalized_source) do
    if executable_parser_breakout?(normalized_source) do
      {:error, @script_breakout_error}
    else
      {:ok, escape_parser_breakout_tokens(source)}
    end
  end

  defp scan(source, mode), do: source |> scan_code(mode, [], []) |> finish_scan()

  defp finish_scan({:error, _reason} = error), do: error
  defp finish_scan({output, _sig}), do: {:ok, output |> Enum.reverse() |> IO.iodata_to_binary()}

  defp scan_code("", _mode, output, sig), do: {output, sig}

  defp scan_code("//" <> rest, mode, output, sig) do
    scan_line_comment(rest, mode, emit_non_code("//", mode, output), sig)
  end

  defp scan_code("/*" <> rest, mode, output, sig) do
    scan_block_comment(rest, mode, emit_non_code("/*", mode, output), sig)
  end

  defp scan_code("/" <> rest, mode, output, sig) do
    scan_slash(rest, mode, output, sig)
  end

  defp scan_code("\"" <> rest, mode, output, sig),
    do: scan_string(rest, "\"", mode, emit_non_code("\"", mode, output), sig)

  defp scan_code("'" <> rest, mode, output, sig),
    do: scan_string(rest, "'", mode, emit_non_code("'", mode, output), sig)

  defp scan_code("`" <> rest, mode, output, sig),
    do: scan_template(rest, mode, emit_non_code("`", mode, output), sig)

  defp scan_code("<" <> rest, :escape, output, sig) do
    if script_breakout_after_lt?(rest) do
      {:error, @script_breakout_error}
    else
      scan_code(rest, :escape, emit_code("<", :escape, output), push_sig(?<, sig))
    end
  end

  defp scan_code("<" <> rest, mode, output, sig),
    do: scan_code(rest, mode, emit_code("<", mode, output), push_sig(?<, sig))

  defp scan_code("-" <> rest, :escape, output, sig) do
    if String.starts_with?(rest, "->") do
      {:error, @script_breakout_error}
    else
      scan_code(rest, :escape, emit_code("-", :escape, output), push_sig(?-, sig))
    end
  end

  defp scan_code("-" <> rest, mode, output, sig),
    do: scan_code(rest, mode, emit_code("-", mode, output), push_sig(?-, sig))

  defp scan_code(source, mode, output, sig) do
    case :binary.match(source, code_tokens()) do
      {0, _length} ->
        <<char::utf8, rest::binary>> = source
        scan_code(rest, mode, emit_code(<<char::utf8>>, mode, output), push_codepoint(char, sig))

      {index, _length} ->
        chunk = binary_part(source, 0, index)
        rest = binary_part(source, index, byte_size(source) - index)
        scan_code(rest, mode, emit_code(chunk, mode, output), push_significant(chunk, sig))

      :nomatch ->
        {emit_code(source, mode, output), push_significant(source, sig)}
    end
  end

  defp scan_line_comment(source, mode, output, sig) do
    case :binary.match(source, @line_comment_end) do
      {index, 1} ->
        comment = binary_part(source, 0, index)
        rest = binary_part(source, index + 1, byte_size(source) - index - 1)

        scan_code(rest, mode, emit_code("\n", mode, emit_non_code(comment, mode, output)), sig)

      :nomatch ->
        {emit_non_code(source, mode, output), sig}
    end
  end

  defp scan_block_comment(source, mode, output, sig) do
    case :binary.match(source, @block_comment_end) do
      {index, 2} ->
        comment = binary_part(source, 0, index)
        rest = binary_part(source, index + 2, byte_size(source) - index - 2)

        scan_code(
          rest,
          mode,
          emit_non_code("*/", mode, emit_non_code(comment, mode, output)),
          sig
        )

      :nomatch ->
        {emit_non_code(source, mode, output), sig}
    end
  end

  defp scan_string(source, quote, mode, output, sig) do
    case next_scanner_token(source, string_tokens(quote)) do
      {chunk, token, rest} ->
        scan_string_token(token, rest, quote, mode, emit_non_code(chunk, mode, output), sig)

      :nomatch ->
        {emit_non_code(source, mode, output), sig}
    end
  end

  defp scan_string_token("\\", rest, quote, mode, output, sig),
    do: scan_string_escape(rest, quote, mode, output, sig)

  defp scan_string_token(quote, rest, quote, mode, output, sig),
    do: scan_code(rest, mode, emit_non_code(quote, mode, output), sig)

  defp scan_string_escape("", _quote, mode, output, sig),
    do: {emit_non_code("\\", mode, output), sig}

  defp scan_string_escape(<<escaped::utf8, tail::binary>>, quote, mode, output, sig) do
    scan_string(tail, quote, mode, emit_non_code(<<?\\, escaped::utf8>>, mode, output), sig)
  end

  defp scan_regex(source, mode, output, sig, class?) do
    case next_scanner_token(source, regex_tokens()) do
      {chunk, token, rest} ->
        scan_regex_token(token, rest, mode, emit_non_code(chunk, mode, output), sig, class?)

      :nomatch ->
        {emit_non_code(source, mode, output), sig}
    end
  end

  defp scan_regex_token("\\", rest, mode, output, sig, class?),
    do: scan_regex_escape(rest, mode, output, sig, class?)

  defp scan_regex_token("[", rest, mode, output, sig, false),
    do: scan_regex(rest, mode, emit_non_code("[", mode, output), sig, true)

  defp scan_regex_token("]", rest, mode, output, sig, true),
    do: scan_regex(rest, mode, emit_non_code("]", mode, output), sig, false)

  defp scan_regex_token("/", rest, mode, output, sig, false) do
    {flags, tail} = take_regex_flags(rest, "")
    scan_code(tail, mode, emit_non_code("/" <> flags, mode, output), push_sig(?/, sig))
  end

  defp scan_regex_token(token, rest, mode, output, sig, class?),
    do: scan_regex(rest, mode, emit_non_code(token, mode, output), sig, class?)

  defp scan_regex_escape("", mode, output, sig, _class?),
    do: {emit_non_code("\\", mode, output), sig}

  defp scan_regex_escape(<<escaped::utf8, tail::binary>>, mode, output, sig, class?) do
    scan_regex(tail, mode, emit_non_code(<<?\\, escaped::utf8>>, mode, output), sig, class?)
  end

  defp scan_template(source, mode, output, sig) do
    case next_scanner_token(source, template_tokens()) do
      {chunk, token, rest} ->
        scan_template_token(token, rest, mode, emit_non_code(chunk, mode, output), sig)

      :nomatch ->
        {emit_non_code(source, mode, output), sig}
    end
  end

  defp scan_template_token("\\", rest, mode, output, sig),
    do: scan_template_escape(rest, mode, output, sig)

  defp scan_template_token("`", rest, mode, output, sig),
    do: scan_code(rest, mode, emit_non_code("`", mode, output), sig)

  defp scan_template_token("$", rest, mode, output, sig),
    do: scan_template_dollar(rest, mode, output, sig)

  defp scan_template_escape("", mode, output, sig),
    do: {emit_non_code("\\", mode, output), sig}

  defp scan_template_escape(<<escaped::utf8, tail::binary>>, mode, output, sig) do
    scan_template(tail, mode, emit_non_code(<<?\\, escaped::utf8>>, mode, output), sig)
  end

  defp scan_template_dollar("{" <> tail, mode, output, sig) do
    tail
    |> scan_template_expr(mode, emit_code("${", mode, output), push_sig(?{, sig), 1)
    |> continue_template_scan(mode)
  end

  defp scan_template_dollar(rest, mode, output, sig),
    do: scan_template(rest, mode, emit_non_code("$", mode, output), sig)

  defp continue_template_scan({:error, _reason} = error, _mode), do: error

  defp continue_template_scan({tail, output, sig}, mode),
    do: scan_template(tail, mode, output, sig)

  defp scan_template_expr("", _mode, output, sig, _depth), do: {"", output, sig}

  defp scan_template_expr("}" <> rest, mode, output, sig, 1) do
    {rest, emit_code("}", mode, output), pop_sig(sig)}
  end

  defp scan_template_expr("}" <> rest, mode, output, sig, depth) when depth > 1 do
    scan_template_expr(rest, mode, emit_code("}", mode, output), pop_sig(sig), depth - 1)
  end

  defp scan_template_expr("{" <> rest, mode, output, sig, depth) do
    scan_template_expr(rest, mode, emit_code("{", mode, output), push_sig(?{, sig), depth + 1)
  end

  defp scan_template_expr(source, mode, output, sig, depth) do
    case scan_code_one(source, mode, output, sig) do
      {:error, _reason} = error ->
        error

      {tail, next_output, next_sig} ->
        scan_template_expr(tail, mode, next_output, next_sig, depth)
    end
  end

  defp scan_code_one("//" <> rest, mode, output, sig),
    do: scan_line_comment_one(rest, mode, emit_non_code("//", mode, output), sig)

  defp scan_code_one("/*" <> rest, mode, output, sig),
    do: scan_block_comment_one(rest, mode, emit_non_code("/*", mode, output), sig)

  defp scan_code_one("/" <> rest, mode, output, sig),
    do: scan_code_one_slash(rest, mode, output, sig)

  defp scan_code_one("\"" <> rest, mode, output, sig) do
    case scan_string(rest, "\"", mode, emit_non_code("\"", mode, output), sig) do
      {:error, _reason} = error -> error
      {next_output, next_sig} -> {"", next_output, next_sig}
    end
  end

  defp scan_code_one("'" <> rest, mode, output, sig) do
    case scan_string(rest, "'", mode, emit_non_code("'", mode, output), sig) do
      {:error, _reason} = error -> error
      {next_output, next_sig} -> {"", next_output, next_sig}
    end
  end

  defp scan_code_one("`" <> rest, mode, output, sig) do
    case scan_template(rest, mode, emit_non_code("`", mode, output), sig) do
      {:error, _reason} = error -> error
      {next_output, next_sig} -> {"", next_output, next_sig}
    end
  end

  defp scan_code_one("<" <> rest, :escape, output, sig) do
    if script_breakout_after_lt?(rest) do
      {:error, @script_breakout_error}
    else
      {rest, emit_code("<", :escape, output), push_sig(?<, sig)}
    end
  end

  defp scan_code_one("-" <> rest, :escape, output, sig) do
    if String.starts_with?(rest, "->") do
      {:error, @script_breakout_error}
    else
      {rest, emit_code("-", :escape, output), push_sig(?-, sig)}
    end
  end

  defp scan_code_one("<" <> rest, mode, output, sig),
    do: {rest, emit_code("<", mode, output), push_sig(?<, sig)}

  defp scan_code_one("-" <> rest, mode, output, sig),
    do: {rest, emit_code("-", mode, output), push_sig(?-, sig)}

  defp scan_code_one(source, mode, output, sig) do
    case :binary.match(source, template_expr_tokens()) do
      {0, _length} ->
        <<char::utf8, rest::binary>> = source
        {rest, emit_code(<<char::utf8>>, mode, output), push_codepoint(char, sig)}

      {index, _length} ->
        chunk = binary_part(source, 0, index)
        rest = binary_part(source, index, byte_size(source) - index)
        {rest, emit_code(chunk, mode, output), push_significant(chunk, sig)}

      :nomatch ->
        {"", emit_code(source, mode, output), push_significant(source, sig)}
    end
  end

  defp next_scanner_token(source, tokens) do
    case :binary.match(source, tokens) do
      {index, 1} ->
        token_offset = index + 1

        {
          binary_part(source, 0, index),
          binary_part(source, index, 1),
          binary_part(source, token_offset, byte_size(source) - token_offset)
        }

      :nomatch ->
        :nomatch
    end
  end

  defp scan_code_one_slash(rest, mode, output, sig) do
    if regex_context?(sig) do
      scan_code_one_regex(rest, mode, output, sig)
    else
      {rest, emit_code("/", mode, output), push_sig(?/, sig)}
    end
  end

  defp scan_code_one_regex(rest, mode, output, sig) do
    case scan_regex(rest, mode, emit_non_code("/", mode, output), sig, false) do
      {:error, _reason} = error -> error
      {next_output, next_sig} -> {"", next_output, next_sig}
    end
  end

  defp scan_slash(rest, mode, output, sig) do
    if regex_context?(sig) do
      scan_regex(rest, mode, emit_non_code("/", mode, output), sig, false)
    else
      scan_code(rest, mode, emit_code("/", mode, output), push_sig(?/, sig))
    end
  end

  defp scan_line_comment_one(source, mode, output, sig) do
    case :binary.match(source, @line_comment_end) do
      {index, 1} ->
        comment = binary_part(source, 0, index)
        rest = binary_part(source, index + 1, byte_size(source) - index - 1)
        {rest, emit_code("\n", mode, emit_non_code(comment, mode, output)), sig}

      :nomatch ->
        {"", emit_non_code(source, mode, output), sig}
    end
  end

  defp scan_block_comment_one(source, mode, output, sig) do
    case :binary.match(source, @block_comment_end) do
      {index, 2} ->
        comment = binary_part(source, 0, index)
        rest = binary_part(source, index + 2, byte_size(source) - index - 2)
        {rest, emit_non_code("*/", mode, emit_non_code(comment, mode, output)), sig}

      :nomatch ->
        {"", emit_non_code(source, mode, output), sig}
    end
  end

  defp take_regex_flags(<<char::utf8, rest::binary>>, acc)
       when char in ?a..?z or char in ?A..?Z do
    take_regex_flags(rest, acc <> <<char::utf8>>)
  end

  defp take_regex_flags(rest, acc), do: {acc, rest}

  defp emit_non_code(text, mode, output), do: [non_code_text(text, mode) | output]

  defp emit_code(text, :escape, output), do: [text | output]
  defp emit_code(text, :mask, output), do: [text | output]

  defp non_code_text(text, :escape), do: escape_non_code(text)
  defp non_code_text(text, :mask), do: mask_text(text)

  defp executable_parser_breakout?(source) do
    Regex.match?(~r/<\/(?:script|style)|<!--|-->/iu, source)
  end

  defp escape_parser_breakout_tokens(source) do
    ~r/<(\/(?:script|style))/iu
    |> Regex.replace(source, fn _match, tail -> "\\x3c" <> tail end)
    |> String.replace("<!--", "\\x3c!--")
    |> String.replace("-->", "\\x2d->")
  end

  defp escape_non_code(""), do: ""

  defp escape_non_code(text) do
    case :binary.match(text, non_code_escape_tokens()) do
      {index, 1} ->
        before = binary_part(text, 0, index)
        token_offset = index + 1
        token = binary_part(text, index, 1)
        rest = binary_part(text, token_offset, byte_size(text) - token_offset)

        [before, escaped_non_code_token(token, rest), escape_non_code(rest)]

      :nomatch ->
        text
    end
  end

  defp escaped_non_code_token("<", rest),
    do: if(script_breakout_after_lt?(rest), do: "\\x3c", else: "<")

  defp escaped_non_code_token("-", rest),
    do: if(String.starts_with?(rest, "->"), do: "\\x2d", else: "-")

  defp mask_text(""), do: ""

  defp mask_text(text) do
    mask_text(text, [])
  end

  defp string_tokens("\""), do: double_quote_string_tokens()
  defp string_tokens("'"), do: single_quote_string_tokens()

  defp code_tokens, do: compiled_pattern(:code_tokens, @code_tokens)

  defp double_quote_string_tokens,
    do: compiled_pattern(:double_quote_string_tokens, @double_quote_string_tokens)

  defp single_quote_string_tokens,
    do: compiled_pattern(:single_quote_string_tokens, @single_quote_string_tokens)

  defp template_tokens, do: compiled_pattern(:template_tokens, @template_tokens)
  defp template_expr_tokens, do: compiled_pattern(:template_expr_tokens, @template_expr_tokens)
  defp regex_tokens, do: compiled_pattern(:regex_tokens, @regex_tokens)

  defp non_code_escape_tokens,
    do: compiled_pattern(:non_code_escape_tokens, @non_code_escape_tokens)

  defp compiled_pattern(name, source) do
    key = {__MODULE__, name}

    case :persistent_term.get(key, :undefined) do
      :undefined ->
        compiled = :binary.compile_pattern(source)
        :persistent_term.put(key, compiled)
        compiled

      compiled ->
        compiled
    end
  end

  defp script_breakout_after_lt?(rest) do
    starts_with_ci?(rest, "/script") or starts_with_ci?(rest, "/style") or
      String.starts_with?(rest, "!--")
  end

  defp starts_with_ci?(text, prefix) when byte_size(text) >= byte_size(prefix) do
    text
    |> binary_part(0, byte_size(prefix))
    |> String.downcase()
    |> Kernel.==(prefix)
  end

  defp starts_with_ci?(_text, _prefix), do: false

  defp push_significant("", sig), do: sig

  defp push_significant(chunk, sig) do
    case last_significant(chunk) do
      nil -> sig
      char -> push_sig(char, sig)
    end
  end

  defp push_codepoint(char, sig) do
    if whitespace?(char), do: sig, else: push_sig(char, sig)
  end

  defp push_sig(char, sig), do: [char | sig]
  defp pop_sig([_token | sig]), do: sig
  defp pop_sig([]), do: []

  defp mask_text("", output), do: output |> Enum.reverse() |> IO.iodata_to_binary()

  defp mask_text(text, output) do
    case :binary.match(text, @line_comment_end) do
      {index, 1} ->
        before = binary_part(text, 0, index)
        rest = binary_part(text, index + 1, byte_size(text) - index - 1)
        mask_text(rest, ["\n", spaces(byte_size(before)) | output])

      :nomatch ->
        [spaces(byte_size(text)) | output] |> Enum.reverse() |> IO.iodata_to_binary()
    end
  end

  defp spaces(0), do: ""
  defp spaces(count), do: :binary.copy(" ", count)

  defp last_significant(""), do: nil

  defp last_significant(chunk), do: last_significant_byte(chunk, byte_size(chunk) - 1)

  defp last_significant_byte(_chunk, index) when index < 0, do: nil

  defp last_significant_byte(chunk, index) do
    byte = :binary.at(chunk, index)
    if ascii_whitespace?(byte), do: last_significant_byte(chunk, index - 1), else: byte
  end

  defp ascii_whitespace?(char), do: char in [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20]

  defp whitespace?(char),
    do:
      char in [
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x20,
        0x85,
        0xA0,
        0x1680,
        0x2000,
        0x2001,
        0x2002,
        0x2003,
        0x2004,
        0x2005,
        0x2006,
        0x2007,
        0x2008,
        0x2009,
        0x200A,
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000
      ]

  defp regex_context?([]), do: true

  defp regex_context?([token | _rest]) do
    token in [?(, ?{, ?[, ?=, ?:, ?,, ?;, ?!, ??, ?&, ?|, ?+, ?-, ?*, ?%, ?^, ?~]
  end

  defp unsafe_control_character_binary?(<<>>), do: false

  defp unsafe_control_character_binary?(<<char::utf8, rest::binary>>) do
    char == 0x00 or (char > 0x00 and char <= 0x08) or char in [0x0B, 0x0C] or
      (char >= 0x0E and char <= 0x1F) or char == 0x7F or
      unsafe_control_character_binary?(rest)
  end
end
