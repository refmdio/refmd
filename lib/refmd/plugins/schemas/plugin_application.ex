defmodule RefMD.Plugins.PluginApplication do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @application_scope_kinds ~w(workspace)
  @application_modes ~w(workspace_shared user_applied)
  @workspace_policy_results ~w(allowed denied needs_admin_review)

  schema "plugin_applications" do
    belongs_to :package, RefMD.Plugins.PluginPackage
    belongs_to :workspace, RefMD.Workspaces.Workspace
    belongs_to :created_by_user, RefMD.Users.User
    belongs_to :current_bundle, RefMD.Plugins.PluginBundle

    field :plugin_id, :string
    field :application_scope_kind, :string, default: "workspace"
    field :application_mode, :string, default: "workspace_shared"
    field :workspace_policy_result, :string, default: "allowed"
    field :config, :map
    field :enabled, :boolean, default: true
    field :consent_epoch, :integer, default: 0
    field :state_head_hash, :string
    field :deleted_at, :utc_datetime_usec

    has_many :bundles, RefMD.Plugins.PluginBundle, foreign_key: :application_id

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  def changeset(application, attrs) do
    application
    |> cast(attrs, [
      :workspace_id,
      :package_id,
      :plugin_id,
      :created_by_user_id,
      :application_scope_kind,
      :application_mode,
      :workspace_policy_result,
      :config,
      :current_bundle_id,
      :enabled,
      :consent_epoch,
      :state_head_hash,
      :deleted_at
    ])
    |> validate_required([
      :workspace_id,
      :package_id,
      :plugin_id,
      :created_by_user_id,
      :application_scope_kind,
      :application_mode,
      :workspace_policy_result,
      :enabled,
      :consent_epoch,
      :state_head_hash
    ])
    |> validate_inclusion(:application_scope_kind, @application_scope_kinds)
    |> validate_inclusion(:application_mode, @application_modes)
    |> validate_inclusion(:workspace_policy_result, @workspace_policy_results)
    |> validate_number(:consent_epoch, greater_than_or_equal_to: 0)
    |> validate_non_empty(:plugin_id)
    |> validate_non_empty(:state_head_hash)
    |> unique_constraint([:workspace_id, :package_id])
    |> foreign_key_constraint(:package_id)
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:created_by_user_id)
    |> foreign_key_constraint(:current_bundle_id)
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
end
