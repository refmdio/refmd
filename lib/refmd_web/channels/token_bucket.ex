defmodule RefMDWeb.Channels.TokenBucket do
  @moduledoc """
  Per-connection token bucket rate limiter for ephemeral messages.
  State is stored in socket assigns and updated on each check.
  """

  @type t :: %{tokens: float(), last_time: integer()}

  @spec new(float()) :: t()
  def new(burst) do
    %{tokens: burst, last_time: System.monotonic_time(:millisecond)}
  end

  @spec check(t(), float(), float()) :: {:ok, t()} | {:drop, t()}
  def check(bucket, rate_per_sec, burst) do
    now = System.monotonic_time(:millisecond)
    elapsed_sec = (now - bucket.last_time) / 1000.0
    new_tokens = min(bucket.tokens + elapsed_sec * rate_per_sec, burst)

    if new_tokens >= 1.0 do
      {:ok, %{tokens: new_tokens - 1.0, last_time: now}}
    else
      {:drop, %{tokens: new_tokens, last_time: now}}
    end
  end
end
