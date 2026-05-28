defmodule RefMD.Plugins.PluginActivation do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @activation_scope_kinds ~w(user device)

  schema "plugin_activations" do
    belongs_to :application, RefMD.Plugins.PluginApplication
    belongs_to :user, RefMD.Users.User
    belongs_to :device, RefMD.Devices.Device

    field :activation_scope_kind, :string
    field :enabled, :boolean, default: true
    field :deleted_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(activation, attrs) do
    activation
    |> cast(attrs, [
      :application_id,
      :user_id,
      :device_id,
      :activation_scope_kind,
      :enabled,
      :deleted_at
    ])
    |> validate_required([:application_id, :user_id, :activation_scope_kind, :enabled])
    |> validate_inclusion(:activation_scope_kind, @activation_scope_kinds)
    |> validate_device_scope()
    |> unique_constraint([:application_id, :user_id],
      name: :plugin_activations_application_user_actor_index
    )
    |> unique_constraint([:application_id, :user_id, :device_id],
      name: :plugin_activations_application_device_actor_index
    )
    |> foreign_key_constraint(:application_id)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:device_id)
  end

  defp validate_device_scope(changeset) do
    case {get_field(changeset, :activation_scope_kind), get_field(changeset, :device_id)} do
      {"device", device_id} when is_binary(device_id) -> changeset
      {"user", nil} -> changeset
      _ -> add_error(changeset, :activation_scope_kind, "must match device id presence")
    end
  end
end
