defmodule RefMD.Workspaces.WorkspaceDeviceWipeRequirement do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_device_wipe_requirements" do
    belongs_to :workspace, RefMD.Workspaces.Workspace, primary_key: true
    belongs_to :device, RefMD.Devices.Device, primary_key: true
    field :required_kek_version, :integer, primary_key: true
    field :reason, :string
    field :required_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(requirement, attrs) do
    requirement
    |> cast(attrs, [
      :workspace_id,
      :device_id,
      :required_kek_version,
      :reason,
      :required_at
    ])
    |> validate_required([
      :workspace_id,
      :device_id,
      :required_kek_version,
      :reason,
      :required_at
    ])
    |> validate_number(:required_kek_version, greater_than: 0)
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:device_id)
    |> unique_constraint([:workspace_id, :device_id, :required_kek_version],
      name: :workspace_device_wipe_requirements_pkey
    )
  end
end
