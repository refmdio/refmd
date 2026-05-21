defmodule RefMD.Crypto.EncodingTest do
  use ExUnit.Case, async: true

  alias RefMD.Crypto.Encoding

  describe "strict base64url encoding" do
    test "accepts only canonical unpadded base64url" do
      encoded = Encoding.encode_base64url("foo")
      assert encoded == "Zm9v"
      assert Encoding.decode_base64url!(encoded, 3) == "foo"
      assert_raise ArgumentError, fn -> Encoding.decode_base64url!("Zg==") end
      assert_raise ArgumentError, fn -> Encoding.decode_base64url!("Zm8/") end
      assert_raise ArgumentError, fn -> Encoding.decode_base64url!("A") end
    end
  end
end
