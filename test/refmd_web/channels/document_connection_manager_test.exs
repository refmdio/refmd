defmodule RefMDWeb.DocumentConnectionManagerTest do
  use ExUnit.Case, async: false

  alias RefMDWeb.Channels.Document.ConnectionManager, as: DocumentConnectionManager

  setup do
    :ets.delete_all_objects(:refmd_presence_pids)
    on_exit(fn -> :ets.delete_all_objects(:refmd_presence_pids) end)
    :ok
  end

  test "share connection cap rejects the 51st live connection" do
    document_id = "doc-connection-cap"
    share_id = "share-connection-cap"

    tracked =
      for index <- 1..50 do
        principal_id = "principal-#{index}"
        signing_pub_key = "signing-#{index}"

        {pid, result} =
          start_share_connection(document_id, share_id, principal_id, signing_pub_key)

        assert {:ok, _join_ref} = result
        pid
      end

    {overflow_pid, overflow_result} =
      start_share_connection(document_id, share_id, "principal-overflow", "signing-overflow")

    assert {:error, %{reason: "share_connection_limit_exceeded"}} = overflow_result

    stop_share_connection(overflow_pid)
    Enum.each(tracked, &stop_share_connection/1)
  end

  defp start_share_connection(document_id, share_id, principal_id, signing_pub_key) do
    parent = self()

    pid =
      spawn_link(fn ->
        result =
          DocumentConnectionManager.track_share_connection(
            document_id,
            share_id,
            principal_id,
            signing_pub_key
          )

        send(parent, {:share_connection_tracked, self(), result})

        receive do
          :stop -> :ok
        end
      end)

    receive do
      {:share_connection_tracked, ^pid, result} -> {pid, result}
    after
      1_000 -> flunk("timed out waiting for share connection tracking")
    end
  end

  defp stop_share_connection(pid) do
    send(pid, :stop)
    ref = Process.monitor(pid)

    receive do
      {:DOWN, ^ref, :process, ^pid, _reason} -> :ok
    after
      1_000 -> flunk("timed out stopping tracked share connection")
    end
  end
end
