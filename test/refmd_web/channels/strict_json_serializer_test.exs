defmodule RefMDWeb.Channels.StrictJSONSerializerTest do
  use ExUnit.Case, async: true

  alias Phoenix.Socket.Message
  alias RefMDWeb.Channels.StrictJSONSerializer

  test "decodes canonical Phoenix V2 text payloads" do
    raw = ~s(["1","2","document:doc","update",{"payload":{"a":1},"signature":{"b":"c"}}])

    assert %Message{
             join_ref: "1",
             ref: "2",
             topic: "document:doc",
             event: "update",
             payload: %{"payload" => %{"a" => 1}, "signature" => %{"b" => "c"}}
           } = StrictJSONSerializer.decode!(raw, opcode: :text)
  end

  test "rejects duplicate keys in channel payload before channel handlers run" do
    raw = ~s(["1","2","document:doc","update",{"signature":{"a":1,"a":2}}])

    assert_raise ArgumentError, "json_duplicate_key", fn ->
      StrictJSONSerializer.decode!(raw, opcode: :text)
    end
  end

  test "rejects non-canonical numeric token forms in channel payload" do
    raw = ~s(["1","2","document:doc","update",{"clock":1e0}])

    assert_raise ArgumentError, "json_invalid_number_form", fn ->
      StrictJSONSerializer.decode!(raw, opcode: :text)
    end
  end

  test "rejects binary Phoenix frames at the strict JSON boundary" do
    raw = ~s(["1","2","document:doc","update",{"payload":{"a":1}}])

    assert_raise ArgumentError, "phoenix_binary_frame_forbidden", fn ->
      StrictJSONSerializer.decode!(raw, opcode: :binary)
    end
  end
end
