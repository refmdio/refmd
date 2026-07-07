defmodule RefMD.Plugins.PluginConsentEvent do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.Hash

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @decisions ~w(allow deny revoke)

  schema "plugin_consent_events" do
    belongs_to :package, RefMD.Plugins.PluginPackage
    belongs_to :application, RefMD.Plugins.PluginApplication
    belongs_to :activation, RefMD.Plugins.PluginActivation
    belongs_to :workspace, RefMD.Workspaces.Workspace
    belongs_to :signer_device, RefMD.Devices.Device
    belongs_to :signer_user, RefMD.Users.User
    belongs_to :user, RefMD.Users.User
    belongs_to :device, RefMD.Devices.Device

    field :plugin_id, :string
    field :version, :string
    field :owner_scope_kind, :string
    field :application_scope_kind, :string
    field :bundle_hash, :string
    field :manifest_hash, :string
    field :resource_manifest_hash, :string
    field :permissions_hash, :string
    field :endpoint_hash, :string
    field :document_scope_hash, :string
    field :decision, :string
    field :consent_epoch, :integer
    field :previous_event_hash, :string
    field :event_hash, :string
    field :hybrid_signature, :map

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
  end

  @required_fields [
    :plugin_id,
    :package_id,
    :application_id,
    :activation_id,
    :owner_scope_kind,
    :application_scope_kind,
    :version,
    :bundle_hash,
    :manifest_hash,
    :resource_manifest_hash,
    :permissions_hash,
    :endpoint_hash,
    :document_scope_hash,
    :signer_device_id,
    :signer_user_id,
    :user_id,
    :device_id,
    :workspace_id,
    :decision,
    :consent_epoch,
    :previous_event_hash,
    :event_hash,
    :hybrid_signature
  ]
  @hash_fields [
    :bundle_hash,
    :manifest_hash,
    :resource_manifest_hash,
    :permissions_hash,
    :endpoint_hash,
    :document_scope_hash,
    :event_hash
  ]

  def changeset(event, attrs) do
    event
    |> cast(attrs, @required_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:decision, @decisions)
    |> validate_number(:consent_epoch, greater_than: 0)
    |> validate_non_empty_fields(@required_fields -- [:consent_epoch, :hybrid_signature])
    |> validate_hash_fields(@hash_fields)
    |> validate_previous_event_hash()
    |> validate_signature()
    |> unique_constraint([:application_id, :user_id, :device_id, :consent_epoch],
      name: :plugin_consent_events_actor_epoch_index
    )
    |> unique_constraint([:application_id, :event_hash])
    |> foreign_key_constraint(:package_id)
    |> foreign_key_constraint(:application_id)
    |> foreign_key_constraint(:activation_id)
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:signer_device_id)
    |> foreign_key_constraint(:signer_user_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:device_id)
  end

  defp validate_non_empty_fields(changeset, fields) do
    Enum.reduce(fields, changeset, &validate_non_empty(&2, &1))
  end

  defp validate_non_empty(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value) and String.trim(value) != "" do
        []
      else
        [{field, "must not be empty"}]
      end
    end)
  end

  defp validate_signature(changeset) do
    validate_change(changeset, :hybrid_signature, fn :hybrid_signature, value ->
      if is_map(value) and map_size(value) > 0 do
        []
      else
        [hybrid_signature: "must not be empty"]
      end
    end)
  end

  defp validate_hash_fields(changeset, fields) do
    Enum.reduce(fields, changeset, &validate_hash_field(&2, &1))
  end

  defp validate_hash_field(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      try do
        Hash.assert_blake3_base64url!(value)
        []
      rescue
        ArgumentError -> [{field, "must be a BLAKE3 base64url hash"}]
      end
    end)
  end

  defp validate_previous_event_hash(changeset) do
    validate_change(changeset, :previous_event_hash, fn :previous_event_hash, value ->
      if value == "GENESIS" do
        []
      else
        try do
          Hash.assert_blake3_base64url!(value)
          []
        rescue
          ArgumentError -> [previous_event_hash: "must be GENESIS or a BLAKE3 base64url hash"]
        end
      end
    end)
  end
end
