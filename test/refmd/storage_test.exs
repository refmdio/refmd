defmodule RefMD.StorageTest do
  use ExUnit.Case, async: false

  alias RefMD.Storage

  setup do
    previous = Application.get_env(:refmd, :storage)

    on_exit(fn ->
      restore_env(:storage, previous)
    end)

    :ok
  end

  test "local backend reads the documented shared storage config" do
    base_path = Path.join(System.tmp_dir!(), "refmd-storage-test-#{System.unique_integer()}")
    Application.put_env(:refmd, :storage, mode: "local", local: [base_path: base_path])

    assert :ok = Storage.put("plugin-packages/local-entry", "package bytes")
    assert {:ok, "package bytes"} = Storage.get("plugin-packages/local-entry")
    assert File.read!(Path.join(base_path, "plugin-packages/local-entry")) == "package bytes"

    File.rm_rf!(base_path)
  end

  test "S3 backend stores through the shared storage contract" do
    agent = start_supervised!({Agent, fn -> [] end})

    Application.put_env(:refmd, :storage,
      mode: "s3",
      s3: [
        bucket: "refmd-test",
        region: "us-east-1",
        access_key_id: "access",
        secret_access_key: "secret",
        now_fun: fn -> {{2026, 5, 25}, {1, 2, 3}} end,
        request_fun: request_recorder(agent)
      ]
    )

    assert :ok = Storage.put("plugin-packages/entry-id", "package bytes")
    assert {:ok, "package bytes"} = Storage.get("plugin-packages/entry-id")
    assert {:ok, true} = Storage.exists?("plugin-packages/entry-id")
    assert :ok = Storage.delete("plugin-packages/entry-id")

    requests = Agent.get(agent, &Enum.reverse/1)

    assert [
             {:put, put_url, put_headers, "package bytes"},
             {:get, get_url, get_headers, ""},
             {:head, head_url, head_headers, ""},
             {:delete, delete_url, _delete_headers, ""}
           ] = requests

    assert put_url == "https://refmd-test.s3.us-east-1.amazonaws.com/plugin-packages/entry-id"
    assert get_url == put_url
    assert head_url == put_url
    assert delete_url == put_url

    assert header(put_headers, "if-none-match") == "*"
    assert header(put_headers, "x-amz-content-sha256") == sha256_hex("package bytes")
    assert header(get_headers, "x-amz-content-sha256") == Storage.S3.empty_payload_hash()
    assert header(head_headers, "x-amz-date") == "20260525T010203Z"

    assert String.starts_with?(
             header(put_headers, "authorization"),
             "AWS4-HMAC-SHA256 Credential=access/20260525/us-east-1/s3/aws4_request"
           )
  end

  test "S3 backend lists only the plugin package namespace" do
    agent = start_supervised!({Agent, fn -> [] end})

    Application.put_env(:refmd, :storage,
      mode: "s3",
      s3: [
        bucket: "refmd-test",
        region: "us-west-2",
        access_key_id: "access",
        secret_access_key: "secret",
        now_fun: fn -> {{2026, 5, 25}, {1, 2, 3}} end,
        request_fun: request_recorder(agent)
      ]
    )

    assert {:ok, %{entries: ["plugin-packages/a", "plugin-packages/b"], cursor: "next-token"}} =
             Storage.list("plugin-packages/", nil)

    assert {:error, :invalid_prefix} = Storage.list("documents/", nil)

    [{:get, url, headers, ""}] = Agent.get(agent, &Enum.reverse/1)

    assert url ==
             "https://refmd-test.s3.us-west-2.amazonaws.com/?list-type=2&max-keys=100&prefix=plugin-packages%2F"

    assert header(headers, "x-amz-content-sha256") == Storage.S3.empty_payload_hash()
  end

  test "S3 backend maps storage errors and rejects invalid paths" do
    agent = start_supervised!({Agent, fn -> [] end})

    Application.put_env(:refmd, :storage,
      mode: "s3",
      s3: [
        bucket: "refmd-test",
        region: "us-east-1",
        access_key_id: "access",
        secret_access_key: "secret",
        request_fun: fn method, url, headers, body ->
          Agent.update(agent, &[{method, url, headers, body} | &1])
          {:ok, 404, [], ""}
        end
      ]
    )

    assert {:error, :not_found} = Storage.get("plugin-packages/missing")
    assert {:ok, false} = Storage.exists?("plugin-packages/missing")
    assert :ok = Storage.delete("plugin-packages/missing")
    assert {:error, :invalid_path} = Storage.put("../escape", "bytes")

    assert [
             {:get, _, _, ""},
             {:head, _, _, ""},
             {:delete, _, _, ""}
           ] = Agent.get(agent, &Enum.reverse/1)
  end

  defp request_recorder(agent) do
    fn
      :get, url, headers, "" ->
        Agent.update(agent, &[{:get, url, headers, ""} | &1])

        if String.contains?(url, "list-type=2") do
          {:ok, 200, [], list_response()}
        else
          {:ok, 200, [], "package bytes"}
        end

      :head, url, headers, "" ->
        Agent.update(agent, &[{:head, url, headers, ""} | &1])
        {:ok, 200, [], ""}

      :put, url, headers, body ->
        Agent.update(agent, &[{:put, url, headers, body} | &1])
        {:ok, 200, [], ""}

      :delete, url, headers, "" ->
        Agent.update(agent, &[{:delete, url, headers, ""} | &1])
        {:ok, 204, [], ""}
    end
  end

  defp list_response do
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <ListBucketResult>
      <Contents><Key>plugin-packages/a</Key></Contents>
      <Contents><Key>plugin-packages/b</Key></Contents>
      <NextContinuationToken>next-token</NextContinuationToken>
    </ListBucketResult>
    """
  end

  defp header(headers, name) do
    Enum.find_value(headers, fn {header_name, value} ->
      if header_name == name, do: value
    end)
  end

  defp sha256_hex(value), do: :crypto.hash(:sha256, value) |> Base.encode16(case: :lower)

  defp restore_env(key, nil), do: Application.delete_env(:refmd, key)
  defp restore_env(key, value), do: Application.put_env(:refmd, key, value)
end
