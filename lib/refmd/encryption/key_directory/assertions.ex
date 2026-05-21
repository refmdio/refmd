defmodule RefMD.Encryption.KeyDirectory.Assertions do
  @moduledoc false

  alias RefMD.Crypto.Hash

  @max_safe_integer 9_007_199_254_740_991

  @spec assert_non_empty_string!(term(), String.t()) :: :ok
  def assert_non_empty_string!(value, _error) when is_binary(value) and value != "", do: :ok
  def assert_non_empty_string!(_, error), do: raise(ArgumentError, error)

  @spec normalize_event_head!(term()) :: map()
  def normalize_event_head!(head) when is_map(head) do
    assert_exact_keys!(head, Enum.sort(["head_hash", "head_sequence"]))
    assert_positive_integer!(head["head_sequence"], "event_head_sequence_invalid")
    Hash.assert_blake3_base64url!(head["head_hash"])
    head
  end

  def normalize_event_head!(_), do: raise(ArgumentError, "event_head_invalid")

  @spec assert_positive_integer!(term(), String.t()) :: :ok
  def assert_positive_integer!(value, _error)
      when is_integer(value) and value > 0 and value <= @max_safe_integer,
      do: :ok

  def assert_positive_integer!(_, error), do: raise(ArgumentError, error)

  @spec assert_literal!(term(), term(), String.t()) :: :ok
  def assert_literal!(value, value, _error), do: :ok
  def assert_literal!(_, _, error), do: raise(ArgumentError, error)

  @spec assert_exact_keys!(map(), [String.t()]) :: :ok
  def assert_exact_keys!(map, expected_keys) when is_map(map) do
    if Enum.sort(Map.keys(map)) == expected_keys do
      :ok
    else
      raise ArgumentError, "keys_invalid"
    end
  end

  @spec maybe_put(map(), term(), term()) :: map()
  def maybe_put(map, _key, nil), do: map
  def maybe_put(map, key, value), do: Map.put(map, key, value)
end
