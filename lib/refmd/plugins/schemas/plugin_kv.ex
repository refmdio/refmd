defmodule RefMD.Plugins.PluginKV do
  use Ecto.Schema

  alias RefMD.Plugins.PluginStorageEntry

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "plugin_kv" do
    belongs_to :application, RefMD.Plugins.PluginApplication
    belongs_to :package, RefMD.Plugins.PluginPackage
    belongs_to :activation, RefMD.Plugins.PluginActivation
    belongs_to :workspace, RefMD.Workspaces.Workspace

    field :plugin_id, :string
    field :scope, :string
    field :scope_id, :string
    field :key, :string
    field :ciphertext, :binary
    field :nonce, :binary
    field :key_version, :integer

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(entry, attrs), do: PluginStorageEntry.changeset(entry, attrs)
end
