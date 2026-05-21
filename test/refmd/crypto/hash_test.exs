defmodule RefMD.Crypto.HashTest do
  use ExUnit.Case, async: true

  alias RefMD.Crypto.Hash

  describe "BLAKE3 base64url hashes" do
    test "matches golden hashes for canonical strings" do
      cases = [
        {
          ~s({"a":1,"b":[true,"x"],"c":{"d":2}}),
          "gEZ-CC60-ZGXR-zjeJshsxng5NNlZsfjuV75BsoG2lU"
        },
        {
          "{\"\\\"\":\"quote\",\"\\\\\":\"slash\",\"control\":\"line\\nbreak\",\"emoji\":\"😀\",\"é\":\"e-acute\"}",
          "4r6J_8lqRQAPRGJJYYNn3XTgzp-UX-TvHjyIqOu2t_s"
        },
        {
          "{\"A\":1,\"z\":2,\"é\":3,\"€\":4}",
          "DLCESylEclZ2AZGAFcQSJBB8x1QPeP9P1qdcaJToyT8"
        },
        {
          ~s({"n":9007199254740991}),
          "bzrcA2FCBeTvfTeMUdWEppHGC6oqvN_qUyUBgmGij7Y"
        },
        {
          ~s({"control":"\\u000b\\u001f"}),
          "pn3t2AxZu1EGyi26Jx1utL15v4TkEbKkhcdtTBfFjnE"
        }
      ]

      for {canonical, hash} <- cases do
        assert Hash.blake3_base64url(canonical) == hash
      end
    end

    test "validates BLAKE3 base64url hashes and sentinels" do
      hash = Hash.blake3_base64url("protocol")
      assert byte_size(hash) == 43
      assert :ok = Hash.assert_blake3_base64url!(hash)
      assert_raise ArgumentError, fn -> Hash.assert_blake3_base64url!("GENESIS") end
      assert :ok = Hash.assert_blake3_base64url!("GENESIS", MapSet.new(["GENESIS"]))

      assert_raise ArgumentError, fn ->
        Hash.assert_blake3_base64url!(String.duplicate("A", 42) <> "_")
      end

      assert_raise ArgumentError, fn ->
        Hash.assert_blake3_base64url!(
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
      end
    end
  end
end
