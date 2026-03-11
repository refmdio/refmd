defmodule RefMD.Encryption.WorkspaceTagIndexKey do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "workspace_tag_index_keys" do
    belongs_to :workspace, RefMD.Workspaces.Workspace, primary_key: true
    field :encrypted_key, :binary
    field :nonce, :binary
    field :kek_version, :integer
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(key, attrs) do
    key
    |> cast(attrs, [:workspace_id, :encrypted_key, :nonce, :kek_version])
    |> validate_required([:workspace_id, :encrypted_key, :nonce, :kek_version])
  end
end
