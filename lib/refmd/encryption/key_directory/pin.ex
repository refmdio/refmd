defmodule RefMD.Encryption.KeyDirectory.Pin do
  @moduledoc false

  defstruct [
    :scope_kind,
    :scope_id,
    :checkpoint_sequence,
    :checkpoint_hash,
    :event_head_sequence,
    :event_head_hash,
    :suite_policy_version,
    :min_suite_rank,
    :allowed_suite_ids_hash
  ]
end
