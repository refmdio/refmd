defmodule RefMD.Workspaces.AuthorityMutations do
  @moduledoc false

  alias RefMD.Workspaces.AuthorityMutations.{Commit, Intent}

  def issue_intent(actor_user_id, actor_device_id, event_type, command, candidate),
    do: Intent.issue(actor_user_id, actor_device_id, event_type, command, candidate)

  def commit(actor_user_id, actor_device_id, authorization),
    do: Commit.commit(actor_user_id, actor_device_id, authorization)

  def commit(actor_user_id, actor_device_id, authorization, expected_command_binding),
    do: Commit.commit(actor_user_id, actor_device_id, authorization, expected_command_binding)
end
