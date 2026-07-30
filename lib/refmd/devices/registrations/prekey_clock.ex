defmodule RefMD.Devices.PrekeyClock do
  @moduledoc false

  import Ecto.Query

  alias RefMD.Repo

  @lifetime_ms 300_000
  @purposes ["device_approval_kek_initial", "trust_transfer", "umk_distribution"]

  def lifetime_ms, do: @lifetime_ms

  def issue!(now_ms \\ System.system_time(:millisecond))
      when is_integer(now_ms) and now_ms >= 0 do
    lock_namespaces!(@purposes, now_ms)
    %{issued_at_ms: now_ms, expires_at_ms: now_ms + @lifetime_ms}
  end

  def consume!(prekeys, now_ms \\ System.system_time(:millisecond))
      when is_list(prekeys) and is_integer(now_ms) and now_ms >= 0 do
    purposes = prekeys |> Enum.map(& &1.purpose) |> Enum.uniq() |> Enum.sort()
    lock_namespaces!(purposes, now_ms)

    if Enum.any?(prekeys, &expired?(&1, now_ms)) do
      {:error, :initial_ake_prekey_expired}
    else
      :ok
    end
  end

  defp expired?(%{expires_at_ms: expires_at_ms}, now_ms) when is_integer(expires_at_ms),
    do: now_ms >= expires_at_ms

  defp expired?(_, _), do: true

  defp lock_namespaces!(purposes, now_ms) do
    Enum.each(purposes, &ensure_namespace!/1)

    watermarks =
      from(w in "initial_ake_prekey_clock_watermarks",
        where: w.purpose in ^purposes,
        order_by: w.purpose,
        lock: "FOR UPDATE",
        select: {w.purpose, w.watermark_ms}
      )
      |> Repo.all()

    if length(watermarks) != length(purposes) do
      Repo.rollback(:initial_ake_prekey_clock_unavailable)
    end

    if Enum.any?(watermarks, fn {_purpose, watermark_ms} -> now_ms < watermark_ms end) do
      Repo.rollback(:server_clock_regression)
    end

    from(w in "initial_ake_prekey_clock_watermarks", where: w.purpose in ^purposes)
    |> Repo.update_all(set: [watermark_ms: now_ms, updated_at: DateTime.utc_now()])

    :ok
  end

  defp ensure_namespace!(purpose) when purpose in @purposes do
    now = DateTime.utc_now()

    Repo.insert_all(
      "initial_ake_prekey_clock_watermarks",
      [%{purpose: purpose, watermark_ms: 0, inserted_at: now, updated_at: now}],
      on_conflict: :nothing
    )
  end
end
