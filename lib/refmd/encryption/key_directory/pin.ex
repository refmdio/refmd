defmodule RefMD.Encryption.KeyDirectory.Pin do
  @moduledoc false

  @type t :: %__MODULE__{
          scope_kind: binary(),
          scope_id: Ecto.UUID.t(),
          checkpoint_sequence: pos_integer(),
          checkpoint_hash: binary(),
          event_head_sequence: pos_integer(),
          event_head_hash: binary(),
          suite_policy_version: pos_integer(),
          min_suite_rank: pos_integer(),
          allowed_suite_ids_hash: binary()
        }

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
