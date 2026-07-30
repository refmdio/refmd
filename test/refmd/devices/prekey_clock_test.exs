defmodule RefMD.Devices.PrekeyClockTest do
  use RefMD.DataCase, async: false

  alias RefMD.Devices.PrekeyClock
  alias RefMD.Repo

  setup do
    Repo.delete_all("initial_ake_prekey_clock_watermarks")
    :ok
  end

  test "issues an exact five-minute server lifetime and advances every namespace watermark" do
    assert {:ok, %{issued_at_ms: 1_700_000_000_000, expires_at_ms: 1_700_000_300_000}} =
             Repo.transaction(fn -> PrekeyClock.issue!(1_700_000_000_000) end,
               isolation: :serializable
             )

    assert Repo.all(
             from(w in "initial_ake_prekey_clock_watermarks",
               order_by: w.purpose,
               select: {w.purpose, w.watermark_ms}
             )
           ) == [
             {"device_approval_kek_initial", 1_700_000_000_000},
             {"trust_transfer", 1_700_000_000_000},
             {"umk_distribution", 1_700_000_000_000}
           ]
  end

  test "rejects clock rollback without lowering the durable watermark" do
    assert {:ok, _} =
             Repo.transaction(fn -> PrekeyClock.issue!(1_700_000_000_000) end,
               isolation: :serializable
             )

    assert {:error, :server_clock_regression} =
             Repo.transaction(fn -> PrekeyClock.issue!(1_699_999_999_999) end,
               isolation: :serializable
             )

    assert Repo.all(from(w in "initial_ake_prekey_clock_watermarks", select: w.watermark_ms)) ==
             List.duplicate(1_700_000_000_000, 3)
  end

  test "accepts immediately before expiry and rejects at the exact expiry boundary" do
    prekey = %{purpose: "umk_distribution", expires_at_ms: 1_700_000_300_000}

    assert {:ok, :ok} =
             Repo.transaction(fn -> PrekeyClock.consume!([prekey], 1_700_000_299_999) end,
               isolation: :serializable
             )

    assert {:ok, {:error, :initial_ake_prekey_expired}} =
             Repo.transaction(fn -> PrekeyClock.consume!([prekey], 1_700_000_300_000) end,
               isolation: :serializable
             )

    assert Repo.one(
             from(w in "initial_ake_prekey_clock_watermarks",
               where: w.purpose == "umk_distribution",
               select: w.watermark_ms
             )
           ) == 1_700_000_300_000
  end
end
