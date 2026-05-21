defmodule RefMD.Encryption.KeyDirectory.Protocol do
  @moduledoc false

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Encryption.KeyDirectory.Payload

  @spec event_hash(map()) :: binary()
  def event_hash(payload) when is_map(payload) do
    assert_event_payload!(payload)
    Hash.blake3_base64url(JCS.canonical_bytes!(payload))
  end

  @spec event_body_hash(map()) :: binary()
  def event_body_hash(body) when is_map(body),
    do: Hash.blake3_base64url(JCS.canonical_bytes!(body))

  @spec checkpoint_hash(map()) :: binary()
  def checkpoint_hash(payload) when is_map(payload) do
    assert_checkpoint_payload!(payload)
    Hash.blake3_base64url(JCS.canonical_bytes!(payload))
  end

  @spec key_id!(map()) :: binary()
  def key_id!(material), do: Payload.key_id!(material)

  @spec key_entry!(map(), map(), map() | nil) :: map()
  def key_entry!(key_material, valid_from, revoked_at \\ nil),
    do: Payload.key_entry!(key_material, valid_from, revoked_at)

  @spec assert_event_payload!(map()) :: :ok
  def assert_event_payload!(payload), do: Payload.assert_event_payload!(payload)

  @spec assert_checkpoint_payload!(map()) :: :ok
  def assert_checkpoint_payload!(payload), do: Payload.assert_checkpoint_payload!(payload)
end
