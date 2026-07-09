defmodule RefMDWeb.Channels.Document.ConnectionManagerTest do
  use ExUnit.Case, async: false

  alias RefMDWeb.Channels.Document.ConnectionManager, as: DocumentConnectionManager
  alias RefMDWeb.Channels.Document.Presence

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

  test "user connection eviction broadcasts when the oldest connection is remote" do
    document_id = "doc-remote-eviction"
    user_id = "user-remote-eviction"
    topic = "document:#{document_id}"

    Phoenix.PubSub.subscribe(RefMD.PubSub, DocumentConnectionManager.evict_topic(topic, user_id))

    tracked =
      for index <- 1..3 do
        start_user_connection(document_id, user_id, "signing-#{index}")
      end

    wait_for_presence_count(topic, user_id, 3)

    refs = Enum.map(tracked, fn {_pid, join_ref} -> join_ref end)

    :ets.match_delete(:refmd_presence_pids, {{topic, user_id, :_}, :_})
    DocumentConnectionManager.evict_excess(document_id, user_id)

    assert_receive {:evict_connection, evicted_ref}, 1_000
    assert evicted_ref in refs

    Enum.each(tracked, fn {pid, _join_ref} -> stop_share_connection(pid) end)
  end

  defp start_user_connection(document_id, user_id, signing_key_id) do
    parent = self()

    pid =
      spawn_link(fn ->
        {:ok, join_ref} =
          DocumentConnectionManager.track_and_subscribe(document_id, user_id, signing_key_id)

        send(parent, {:user_connection_tracked, self(), join_ref})

        receive do
          :stop -> :ok
        end
      end)

    receive do
      {:user_connection_tracked, ^pid, join_ref} -> {pid, join_ref}
    after
      1_000 -> flunk("timed out waiting for user connection tracking")
    end
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

  defp wait_for_presence_count(topic, user_id, expected_count, attempts \\ 20)

  defp wait_for_presence_count(_topic, _user_id, _expected_count, 0),
    do: flunk("timed out waiting for presence count")

  defp wait_for_presence_count(topic, user_id, expected_count, attempts) do
    presences = Presence.list(topic)
    user_metas = get_in(presences, [user_id, :metas]) || []

    if length(user_metas) >= expected_count do
      :ok
    else
      Process.sleep(25)
      wait_for_presence_count(topic, user_id, expected_count, attempts - 1)
    end
  end
end
