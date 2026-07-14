defmodule RefMD.Documents.DocumentDeviceWipeRequirement do
  @moduledoc false

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "document_device_wipe_requirements" do
    belongs_to :document, RefMD.Documents.Document, primary_key: true
    belongs_to :device, RefMD.Devices.Device, primary_key: true
    field :required_dek_version, :integer, primary_key: true
    field :reason, :string
    field :required_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec, updated_at: false)
  end

  def changeset(requirement, attrs) do
    requirement
    |> cast(attrs, [
      :document_id,
      :device_id,
      :required_dek_version,
      :reason,
      :required_at
    ])
    |> validate_required([
      :document_id,
      :device_id,
      :required_dek_version,
      :reason,
      :required_at
    ])
    |> validate_number(:required_dek_version, greater_than: 0)
    |> foreign_key_constraint(:document_id)
    |> foreign_key_constraint(:device_id)
    |> unique_constraint([:document_id, :device_id, :required_dek_version],
      name: :document_device_wipe_requirements_pkey
    )
  end
end
