defmodule RefMD.Devices.Revocations do
  @moduledoc false

  alias RefMD.Devices.Revocations.{Commit, Intent}

  def prepare(user_id, actor_device_id, device_id, command),
    do: Intent.issue(user_id, actor_device_id, device_id, command)

  def commit(user_id, actor_device_id, device_id, authorization),
    do: Commit.commit(user_id, actor_device_id, device_id, authorization)
end
