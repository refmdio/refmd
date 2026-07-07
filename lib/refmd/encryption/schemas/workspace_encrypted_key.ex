defmodule RefMD.Encryption.WorkspaceEncryptedKey do
  use Ecto.Schema
  import Ecto.Changeset

  @hpke_enc_bytes 1120

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_encrypted_keys" do
    belongs_to :workspace, RefMD.Workspaces.Workspace, primary_key: true
    belongs_to :user, RefMD.Users.User, primary_key: true
    belongs_to :device, RefMD.Devices.Device, primary_key: true
    field :key_version, :integer, primary_key: true
    field :sender_device_id, :binary_id
    field :wrap_protocol, :string
    field :wrap_version, :integer
    field :suite_id, :string
    field :suite_rank, :integer
    field :purpose, :string
    field :resource, :map
    field :sender, :map
    field :recipient, :map
    field :event_scope, :map
    field :wrap_event_sequence, :integer
    field :wrap_event_hash, :binary
    field :wrap_event_body_hash, :binary
    field :operation_checkpoint_sequence, :integer
    field :operation_checkpoint_hash, :binary
    field :operation_checkpoint_covered_head_sequence, :integer
    field :operation_checkpoint_covered_head_hash, :binary
    field :wrap_body_hash, :binary
    field :recipient_key_id, :binary
    field :sender_signing_key_id, :binary
    field :hpke_enc, :binary
    field :hpke_ciphertext, :binary
    field :signature_protocol, :string
    field :signature_version, :integer
    field :signature_suite_id, :string
    field :signature_suite_rank, :integer
    field :transcript_hash, :binary
    field :ed25519_signature, :binary
    field :mldsa65_signature, :binary
    field :is_active, :boolean
    field :created_at, :utc_datetime_usec
  end

  @signed_wrap_fields [
    :wrap_protocol,
    :wrap_version,
    :suite_id,
    :suite_rank,
    :purpose,
    :resource,
    :sender,
    :recipient,
    :event_scope,
    :wrap_event_sequence,
    :wrap_event_hash,
    :wrap_event_body_hash,
    :operation_checkpoint_sequence,
    :operation_checkpoint_hash,
    :operation_checkpoint_covered_head_sequence,
    :operation_checkpoint_covered_head_hash,
    :wrap_body_hash,
    :recipient_key_id,
    :sender_signing_key_id,
    :hpke_enc,
    :hpke_ciphertext,
    :signature_protocol,
    :signature_version,
    :signature_suite_id,
    :signature_suite_rank,
    :transcript_hash,
    :ed25519_signature,
    :mldsa65_signature
  ]

  def changeset(key, attrs) do
    key
    |> cast(attrs, [
      :workspace_id,
      :user_id,
      :device_id,
      :key_version,
      :sender_device_id,
      :wrap_protocol,
      :wrap_version,
      :suite_id,
      :suite_rank,
      :purpose,
      :resource,
      :sender,
      :recipient,
      :event_scope,
      :wrap_event_sequence,
      :wrap_event_hash,
      :wrap_event_body_hash,
      :operation_checkpoint_sequence,
      :operation_checkpoint_hash,
      :operation_checkpoint_covered_head_sequence,
      :operation_checkpoint_covered_head_hash,
      :wrap_body_hash,
      :recipient_key_id,
      :sender_signing_key_id,
      :hpke_enc,
      :hpke_ciphertext,
      :signature_protocol,
      :signature_version,
      :signature_suite_id,
      :signature_suite_rank,
      :transcript_hash,
      :ed25519_signature,
      :mldsa65_signature,
      :is_active
    ])
    |> validate_required([
      :workspace_id,
      :user_id,
      :device_id,
      :key_version,
      :sender_device_id,
      :is_active
      | @signed_wrap_fields
    ])
    |> validate_byte_size(:hpke_enc, @hpke_enc_bytes)
    |> unique_constraint([:workspace_id, :user_id, :device_id, :key_version],
      name: :workspace_encrypted_keys_pkey,
      message: "key version already exists for this device"
    )
  end

  defp validate_byte_size(changeset, field, expected) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and byte_size(value) == expected,
        do: [],
        else: [{field, "must be #{expected} bytes"}]
    end)
  end
end
