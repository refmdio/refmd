defmodule RefMD.Workspaces.InvitationDeliveryAttempt do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  @context_kinds ~w(workspace_invitation guest_invitation)
  @statuses ~w(pending approved consumed expired)

  schema "invitation_delivery_attempts" do
    belongs_to :workspace, RefMD.Workspaces.Workspace
    field :context_kind, :string
    field :context_id, :binary_id
    belongs_to :recipient_user, RefMD.Users.User
    belongs_to :recipient_device, RefMD.Devices.Device
    field :target_user_id, :binary_id
    field :target_device_id, :binary_id
    field :target_encryption_key_id, :string
    field :target_key_checkpoint_sequence, :integer
    field :target_key_checkpoint_hash, :string
    field :target_registration, :map
    field :target_registration_proof, :map
    field :recipient_redeem_nonce, :string
    field :live_redeem_challenge_hash, :string
    field :recipient_nonce_state_hash, :string
    field :request_binding_hash, :string
    field :resource_hash, :string
    field :context_snapshot, :map
    field :status, :string, default: "pending"
    field :authorization_id, :binary_id
    field :approved_artifacts, :map
    field :expires_at, :utc_datetime_usec
    field :approved_at, :utc_datetime_usec
    field :consumed_at, :utc_datetime_usec
    timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: :updated_at)
  end

  def create_changeset(attempt, attrs) do
    attempt
    |> cast(attrs, [
      :id,
      :workspace_id,
      :context_kind,
      :context_id,
      :recipient_user_id,
      :recipient_device_id,
      :target_user_id,
      :target_device_id,
      :target_encryption_key_id,
      :target_key_checkpoint_sequence,
      :target_key_checkpoint_hash,
      :target_registration,
      :target_registration_proof,
      :recipient_redeem_nonce,
      :live_redeem_challenge_hash,
      :recipient_nonce_state_hash,
      :request_binding_hash,
      :resource_hash,
      :context_snapshot,
      :status,
      :expires_at
    ])
    |> validate_required([
      :id,
      :workspace_id,
      :context_kind,
      :context_id,
      :recipient_user_id,
      :recipient_device_id,
      :target_user_id,
      :target_device_id,
      :target_encryption_key_id,
      :target_registration,
      :recipient_redeem_nonce,
      :live_redeem_challenge_hash,
      :recipient_nonce_state_hash,
      :request_binding_hash,
      :resource_hash,
      :context_snapshot,
      :status,
      :expires_at
    ])
    |> validate_inclusion(:context_kind, @context_kinds)
    |> validate_inclusion(:status, ["pending"])
    |> validate_hash(:target_encryption_key_id)
    |> validate_optional_target_checkpoint()
    |> validate_registration_proof()
    |> validate_hash(:live_redeem_challenge_hash)
    |> validate_hash(:recipient_nonce_state_hash)
    |> validate_hash(:request_binding_hash)
    |> validate_hash(:resource_hash)
    |> validate_length(:recipient_redeem_nonce, is: 43)
    |> validate_format(:recipient_redeem_nonce, ~r/^[A-Za-z0-9_-]{43}$/)
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:recipient_user_id)
    |> foreign_key_constraint(:recipient_device_id)
  end

  def approve_changeset(attempt, attrs) do
    attempt
    |> cast(attrs, [:authorization_id, :approved_artifacts, :approved_at, :status])
    |> validate_required([:authorization_id, :approved_artifacts, :approved_at, :status])
    |> validate_inclusion(:status, ["approved"])
    |> unique_constraint(:authorization_id)
  end

  def consume_changeset(attempt, consumed_at) do
    attempt
    |> change(status: "consumed", consumed_at: consumed_at)
    |> validate_inclusion(:status, @statuses)
  end

  def expire_changeset(attempt, expired_at) do
    attempt
    |> change(status: "expired", consumed_at: expired_at)
    |> validate_inclusion(:status, @statuses)
  end

  defp validate_hash(changeset, field) do
    changeset
    |> validate_length(field, is: 43)
    |> validate_format(field, ~r/^[A-Za-z0-9_-]{43}$/)
  end

  defp validate_optional_target_checkpoint(changeset) do
    case {
      get_field(changeset, :target_key_checkpoint_sequence),
      get_field(changeset, :target_key_checkpoint_hash)
    } do
      {nil, nil} ->
        changeset

      {sequence, hash} when is_integer(sequence) and sequence > 0 and is_binary(hash) ->
        validate_hash(changeset, :target_key_checkpoint_hash)

      _ ->
        add_error(changeset, :target_key_checkpoint_hash, "does not match checkpoint sequence")
    end
  end

  defp validate_registration_proof(changeset) do
    case {get_field(changeset, :context_kind), get_field(changeset, :target_registration_proof)} do
      {"workspace_invitation", nil} -> changeset
      {"guest_invitation", proof} when is_map(proof) -> changeset
      _ -> add_error(changeset, :target_registration_proof, "does not match invitation context")
    end
  end
end
