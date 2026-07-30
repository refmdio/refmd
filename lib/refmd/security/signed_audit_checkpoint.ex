defmodule RefMD.Security.SignedAuditCheckpoint do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.Signature.Audit

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "security_signed_audit_checkpoints" do
    field :chain_scope_kind, :string
    field :chain_scope_id, :binary_id
    field :sequence, :integer
    field :event_hash, :string
    field :previous_signed_checkpoint_sequence, :integer
    field :previous_signed_checkpoint_hash, :string
    field :signer_user_id, :binary_id
    field :signer_device_id, :binary_id
    field :signing_key_id, :string
    field :authorization_checkpoint_scope_kind, :string
    field :authorization_checkpoint_scope_id, :binary_id
    field :authorization_checkpoint_sequence, :integer
    field :authorization_checkpoint_hash, :string
    field :covered_event_class, :string
    field :covered_event_type, :string
    field :variant, :string
    field :checkpoint_hash, :string
    field :payload, :map
    field :signature, :map

    timestamps(type: :utc_datetime_usec)
  end

  def changeset(checkpoint, attrs) do
    checkpoint
    |> cast(attrs, [
      :chain_scope_kind,
      :chain_scope_id,
      :sequence,
      :event_hash,
      :previous_signed_checkpoint_sequence,
      :previous_signed_checkpoint_hash,
      :signer_user_id,
      :signer_device_id,
      :signing_key_id,
      :authorization_checkpoint_scope_kind,
      :authorization_checkpoint_scope_id,
      :authorization_checkpoint_sequence,
      :authorization_checkpoint_hash,
      :covered_event_class,
      :covered_event_type,
      :variant,
      :checkpoint_hash,
      :payload,
      :signature
    ])
    |> validate_required([
      :chain_scope_kind,
      :chain_scope_id,
      :sequence,
      :event_hash,
      :signer_user_id,
      :signing_key_id,
      :authorization_checkpoint_scope_kind,
      :authorization_checkpoint_scope_id,
      :authorization_checkpoint_sequence,
      :authorization_checkpoint_hash,
      :covered_event_class,
      :covered_event_type,
      :variant,
      :checkpoint_hash,
      :payload,
      :signature
    ])
    |> validate_inclusion(:chain_scope_kind, ["user", "workspace"])
    |> validate_inclusion(:authorization_checkpoint_scope_kind, ["user", "workspace"])
    |> validate_inclusion(:variant, [
      "user_identity",
      "user_device",
      "workspace_device",
      "workspace_guest_device"
    ])
    |> validate_number(:sequence, greater_than: 0)
    |> validate_number(:authorization_checkpoint_sequence, greater_than_or_equal_to: 0)
    |> validate_integrity()
    |> unique_constraint([:chain_scope_kind, :chain_scope_id, :sequence])
    |> unique_constraint([:chain_scope_kind, :chain_scope_id, :checkpoint_hash])
  end

  def envelope(%__MODULE__{} = checkpoint) do
    %{
      "payload" => checkpoint.payload,
      "signature" => checkpoint.signature,
      "checkpoint_hash" => checkpoint.checkpoint_hash
    }
  end

  defp validate_integrity(changeset) do
    payload = get_field(changeset, :payload)
    variant = get_field(changeset, :variant)

    if is_map(payload) and is_binary(variant) do
      try do
        Audit.assert_payload!(variant, payload)

        changeset
        |> validate_literal(:chain_scope_kind, payload["chain_scope_kind"])
        |> validate_literal(:chain_scope_id, payload["chain_scope_id"])
        |> validate_literal(:sequence, payload["sequence"])
        |> validate_literal(:event_hash, payload["event_hash"])
        |> validate_literal(
          :previous_signed_checkpoint_sequence,
          payload["previous_signed_checkpoint_sequence"]
        )
        |> validate_literal(
          :previous_signed_checkpoint_hash,
          payload["previous_signed_checkpoint_hash"]
        )
        |> validate_literal(:signer_user_id, payload["signer_user_id"])
        |> validate_literal(:signer_device_id, payload["signer_device_id"])
        |> validate_literal(:signing_key_id, payload["signing_key_id"])
        |> validate_literal(
          :authorization_checkpoint_scope_kind,
          payload["authorization_checkpoint_scope_kind"]
        )
        |> validate_literal(
          :authorization_checkpoint_scope_id,
          payload["authorization_checkpoint_scope_id"]
        )
        |> validate_literal(
          :authorization_checkpoint_sequence,
          payload["authorization_checkpoint_sequence"]
        )
        |> validate_literal(
          :authorization_checkpoint_hash,
          payload["authorization_checkpoint_hash"]
        )
        |> validate_literal(:covered_event_class, payload["covered_event_class"])
        |> validate_literal(:covered_event_type, payload["covered_event_type"])
        |> validate_literal(:checkpoint_hash, Audit.checkpoint_hash!(variant, payload))
      rescue
        ArgumentError -> add_error(changeset, :payload, "is invalid")
      end
    else
      changeset
    end
  end

  defp validate_literal(changeset, field, expected) do
    if get_field(changeset, field) == expected,
      do: changeset,
      else: add_error(changeset, field, "does not match payload")
  end
end
