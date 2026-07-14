defmodule RefMD.Encryption.RotationPolicy do
  @moduledoc false

  @default_rotation_seconds 90 * 24 * 60 * 60

  def next_kek_due_at(now \\ DateTime.utc_now()), do: next_due_at(:kek, now)
  def next_dek_due_at(now \\ DateTime.utc_now()), do: next_due_at(:dek, now)
  def next_identity_due_at(now \\ DateTime.utc_now()), do: next_due_at(:identity, now)

  def kek_overdue?(workspace, now \\ DateTime.utc_now()) do
    workspace.needs_kek_rotation ||
      due?(workspace.kek_rotation_due_at, now)
  end

  def dek_overdue?(document, now \\ DateTime.utc_now()) do
    document.needs_dek_rotation ||
      due?(document.dek_rotation_due_at, now)
  end

  def identity_overdue?(identity_key, now \\ DateTime.utc_now()) do
    identity_key.needs_rotation ||
      due?(identity_key.rotation_due_at, now)
  end

  defp next_due_at(kind, value) do
    value
    |> as_utc_datetime()
    |> DateTime.add(rotation_seconds(kind), :second)
  end

  defp rotation_seconds(kind) do
    :refmd
    |> Application.get_env(__MODULE__, [])
    |> Keyword.get(:"#{kind}_rotation_seconds", @default_rotation_seconds)
  end

  defp due?(nil, _now), do: true

  defp due?(due_at, now) do
    DateTime.compare(as_utc_datetime(due_at), as_utc_datetime(now)) != :gt
  end

  defp as_utc_datetime(%DateTime{} = value), do: value
  defp as_utc_datetime(%NaiveDateTime{} = value), do: DateTime.from_naive!(value, "Etc/UTC")
end
