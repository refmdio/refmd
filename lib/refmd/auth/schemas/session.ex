defmodule RefMD.Auth.Session do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "sessions" do
    belongs_to :user, RefMD.Users.User
    belongs_to :device, RefMD.Devices.Device
    field :token_hash, :string
    field :remember_me, :boolean
    field :is_recovery, :boolean, default: false
    field :identity_recovery_required, :boolean, default: false
    belongs_to :device_registration, RefMD.Devices.DeviceRegistration
    field :recovery_session_transcript_hash, :string
    field :recovery_capability_hash, :string
    field :pending_registration_binding_hash, :string
    field :pending_registration_challenge_hash, :string
    field :pending_registration_challenge_expires_at, :utc_datetime_usec
    field :pending_registration_challenge_consumed_at, :utc_datetime_usec
    field :target_key_checkpoint_sequence, :integer
    field :target_key_checkpoint_hash, :string
    field :candidate_user_checkpoint_sequence, :integer
    field :candidate_user_checkpoint_hash, :string
    field :candidate_user_event_head_sequence, :integer
    field :candidate_user_event_head_hash, :string
    field :candidate_user_audit_sequence, :integer
    field :candidate_user_audit_hash, :string
    field :recovered_identity_signing_key_id, :string
    field :ip_address, :string
    field :user_agent, :string
    field :expires_at, :utc_datetime_usec
    field :last_seen_at, :utc_datetime_usec
    field :last_verified_at, :utc_datetime_usec
    field :created_at, :utc_datetime_usec
  end

  def changeset(session, attrs) do
    session
    |> cast(attrs, [
      :id,
      :user_id,
      :device_id,
      :token_hash,
      :remember_me,
      :is_recovery,
      :identity_recovery_required,
      :device_registration_id,
      :recovery_session_transcript_hash,
      :recovery_capability_hash,
      :pending_registration_binding_hash,
      :pending_registration_challenge_hash,
      :pending_registration_challenge_expires_at,
      :pending_registration_challenge_consumed_at,
      :target_key_checkpoint_sequence,
      :target_key_checkpoint_hash,
      :candidate_user_checkpoint_sequence,
      :candidate_user_checkpoint_hash,
      :candidate_user_event_head_sequence,
      :candidate_user_event_head_hash,
      :candidate_user_audit_sequence,
      :candidate_user_audit_hash,
      :recovered_identity_signing_key_id,
      :ip_address,
      :user_agent,
      :expires_at,
      :last_seen_at
    ])
    |> validate_required([:user_id, :token_hash, :remember_me, :expires_at, :last_seen_at])
    |> unique_constraint(:token_hash)
  end
end
