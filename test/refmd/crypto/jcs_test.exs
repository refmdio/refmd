defmodule RefMD.Crypto.JCSTest do
  use ExUnit.Case, async: true

  alias RefMD.Crypto.JCS

  describe "strict JCS" do
    test "matches golden canonical bytes" do
      cases = [
        {
          %{"c" => %{"d" => 2}, "b" => [true, "x"], "a" => 1},
          ~s({"a":1,"b":[true,"x"],"c":{"d":2}})
        },
        {
          %{
            "\"" => "quote",
            "\\" => "slash",
            "control" => "line\nbreak",
            "emoji" => "😀",
            "é" => "e-acute"
          },
          "{\"\\\"\":\"quote\",\"\\\\\":\"slash\",\"control\":\"line\\nbreak\",\"emoji\":\"😀\",\"é\":\"e-acute\"}"
        },
        {
          %{"€" => 4, "z" => 2, "é" => 3, "A" => 1},
          "{\"A\":1,\"z\":2,\"é\":3,\"€\":4}"
        },
        {
          %{"n" => 9_007_199_254_740_991},
          ~s({"n":9007199254740991})
        },
        {
          %{"control" => "\v\u001F"},
          ~s({"control":"\\u000b\\u001f"})
        }
      ]

      for {value, canonical} <- cases do
        assert JCS.canonicalize!(value) == canonical
        assert JCS.canonical_bytes!(value) == canonical
      end
    end

    test "rejects non-strict values and raw JSON syntax" do
      assert_raise ArgumentError, fn -> JCS.canonicalize!(%{"a" => nil}) end
      assert_raise ArgumentError, fn -> JCS.canonicalize!(%{"a" => -1}) end
      assert_raise ArgumentError, fn -> JCS.canonicalize!(%{"a" => 9_007_199_254_740_992}) end
      assert_raise ArgumentError, fn -> JCS.canonicalize!(%{"a" => 1.5}) end
      assert_raise ArgumentError, fn -> JCS.canonicalize!(%{a: 1}) end
      assert_raise ArgumentError, fn -> JCS.parse_json_strict!(~s({"a":1,"a":2})) end
      assert_raise ArgumentError, fn -> JCS.parse_json_strict!(~s({"a":1e0})) end
      assert_raise ArgumentError, fn -> JCS.parse_json_strict!(~s({"a":-0})) end
      assert_raise ArgumentError, fn -> JCS.parse_json_strict!(~s({"a":"\\uD800"})) end
      assert_raise ArgumentError, fn -> JCS.parse_json_strict!(~s({"a":null})) end
    end
  end
end
