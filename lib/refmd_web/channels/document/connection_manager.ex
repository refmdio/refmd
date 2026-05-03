defmodule RefMDWeb.Channels.Document.ConnectionManager do
  @moduledoc """
  Manages document channel connection tracking, eviction, and peer-left broadcasting.
  Uses Phoenix Presence (cluster-aware) for counting and node-local ETS for PID resolution.
  """

  alias RefMDWeb.Channels.Document.Presence

  @max_connections_per_user 3
  @max_connections_per_share 50
  @max_silent_per_user 50

  # ── Silent join management ──────────────────────────

  @spec check_and_increment_silent(String.t()) :: :ok | {:error, map()}
  def check_and_increment_silent(user_id) do
    silent_topic = "silent:#{user_id}"
    presences = Presence.list(silent_topic)
    user_metas = get_in(presences, [user_id, :metas]) || []

    if length(user_metas) >= @max_silent_per_user do
      {:error, %{reason: "silent_limit_exceeded"}}
    else
      {:ok, _} =
        Presence.track(self(), silent_topic, user_id, %{
          joined_at: System.monotonic_time(:millisecond)
        })

      :ok
    end
  end

  # ── Connection tracking ─────────────────────────────

  @spec track_and_subscribe(String.t(), String.t(), String.t()) :: {:ok, String.t()}
  def track_and_subscribe(document_id, user_id, signing_pub_key) do
    topic = "document:#{document_id}"
    join_ref = inspect(make_ref())

    Phoenix.PubSub.subscribe(RefMD.PubSub, evict_topic(topic, user_id))

    {:ok, _} =
      Presence.track(self(), topic, user_id, %{
        join_ref: join_ref,
        signing_pub_key: signing_pub_key
      })

    :ets.insert(:refmd_presence_pids, {{topic, user_id, join_ref}, {self(), signing_pub_key}})
    {:ok, join_ref}
  end

  @spec track_share_connection(String.t(), String.t(), String.t(), String.t()) ::
          {:ok, String.t()} | {:error, map()}
  def track_share_connection(document_id, share_id, principal_id, signing_pub_key) do
    lock_id = {{__MODULE__, :share_connection_cap, share_id}, :share_connection_cap}

    case :global.set_lock(lock_id) do
      true ->
        try do
          share_topic = share_topic(share_id)

          if total_connections(share_topic) >= @max_connections_per_share do
            {:error, %{reason: "share_connection_limit_exceeded"}}
          else
            topic = "document:#{document_id}"
            join_ref = inspect(make_ref())

            {:ok, _} = track_share_presence(share_topic, principal_id, join_ref)

            {:ok, _} =
              Presence.track(self(), topic, principal_id, %{
                join_ref: join_ref,
                signing_pub_key: signing_pub_key
              })

            :ets.insert(
              :refmd_presence_pids,
              {{topic, principal_id, join_ref}, {self(), signing_pub_key}}
            )

            {:ok, join_ref}
          end
        after
          :global.del_lock(lock_id)
        end

      false ->
        {:error, %{reason: "share_connection_limit_exceeded"}}
    end
  end

  @spec cleanup_connection(String.t()) :: :ok
  def cleanup_connection(document_id) do
    :ets.match_delete(:refmd_presence_pids, {{"document:#{document_id}", :_, :_}, {self(), :_}})
    :ok
  end

  @spec cleanup_connection_on_join_failure(String.t()) :: :ok
  def cleanup_connection_on_join_failure(document_id) do
    topic = "document:#{document_id}"
    :ets.match_delete(:refmd_presence_pids, {{topic, :_, :_}, {self(), :_}})
    :ok
  end

  # ── Eviction ────────────────────────────────────────

  @spec evict_excess(String.t(), String.t()) :: :ok
  def evict_excess(document_id, user_id) do
    topic = "document:#{document_id}"
    presences = Presence.list(topic)
    user_metas = get_in(presences, [user_id, :metas]) || []

    if length(user_metas) >= @max_connections_per_user do
      try_evict_by_ref(topic, user_id, user_metas)
    end

    :ok
  end

  defp try_evict_by_ref(topic, user_id, user_metas) do
    oldest = hd(user_metas)
    oldest_ref = oldest[:join_ref]
    oldest_key = {topic, user_id, oldest_ref}

    case :ets.lookup(:refmd_presence_pids, oldest_key) do
      [{^oldest_key, {pid, _spk}}] ->
        send(pid, :connection_cap_evict)
        :ets.delete(:refmd_presence_pids, oldest_key)
        true

      [] ->
        # Connection is on another node — broadcast eviction via PubSub.
        # The target channel subscribes to this topic on join.
        Phoenix.PubSub.broadcast(
          RefMD.PubSub,
          evict_topic(topic, user_id),
          {:evict_connection, oldest_ref}
        )

        true
    end
  end

  @spec evict_topic(String.t(), String.t()) :: String.t()
  def evict_topic(topic, user_id), do: "connection_evict:#{topic}:#{user_id}"

  defp share_topic(share_id), do: "share_connection:#{share_id}"

  defp track_share_presence(share_topic, principal_id, join_ref) do
    Presence.track(self(), share_topic, principal_id, %{
      join_ref: join_ref,
      joined_at: System.monotonic_time(:millisecond)
    })
  end

  defp total_connections(topic) do
    topic
    |> Presence.list()
    |> Map.values()
    |> Enum.reduce(0, fn presence, acc -> acc + length(presence.metas || []) end)
  end

  # ── Peer-left broadcast ─────────────────────────────

  @spec broadcast_peer_left(String.t(), String.t() | nil, String.t(), String.t() | nil) :: :ok
  def broadcast_peer_left(_document_id, nil, _user_id, _connection_id), do: :ok

  def broadcast_peer_left(document_id, signing_pub_key, user_id, connection_id) do
    # Always use delayed check to let Presence converge across nodes.
    # Avoids false peer-left when a same-device tab on another node hasn't
    # propagated yet. handlePeerLeft on clients is idempotent.
    schedule_delayed_peer_left_check(
      "document:#{document_id}",
      signing_pub_key,
      user_id,
      connection_id
    )
  end

  @peer_left_delays_ms [500, 2_000]
  defp schedule_delayed_peer_left_check(topic, signing_pub_key, user_id, connection_id) do
    Task.start(fn ->
      poll_peer_left(@peer_left_delays_ms, topic, signing_pub_key, user_id, connection_id)
    end)
  end

  defp poll_peer_left([], _topic, _signing_pub_key, _user_id, _connection_id), do: :ok

  defp poll_peer_left([delay | rest], topic, signing_pub_key, user_id, connection_id) do
    Process.sleep(delay)

    case check_device_presence(topic, user_id, signing_pub_key) do
      :gone -> do_broadcast_peer_left(topic, signing_pub_key, connection_id)
      :present when rest == [] -> :ok
      :present -> poll_peer_left(rest, topic, signing_pub_key, user_id, connection_id)
    end
  end

  defp check_device_presence(topic, user_id, signing_pub_key) do
    presences = Presence.list(topic)
    user_metas = get_in(presences, [user_id, :metas]) || []
    count = Enum.count(user_metas, fn meta -> meta[:signing_pub_key] == signing_pub_key end)
    if count == 0, do: :gone, else: :present
  end

  defp do_broadcast_peer_left(topic, signing_pub_key, connection_id) do
    RefMDWeb.Endpoint.broadcast(topic, "peer-left", %{
      signingPubKey: signing_pub_key,
      connectionId: connection_id
    })
  end
end
