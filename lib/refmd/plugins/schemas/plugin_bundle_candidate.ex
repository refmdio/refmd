defmodule RefMD.Plugins.PluginBundleCandidate do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.{Hash, JCS}

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @source_kinds ~w(remote_https_url local_upload)
  @validation_statuses ~w(valid invalid)
  @source_url_hash_sentinels MapSet.new(["NO_SOURCE_URL"])

  schema "plugin_bundle_candidates" do
    belongs_to :workspace, RefMD.Workspaces.Workspace
    belongs_to :application, RefMD.Plugins.PluginApplication
    belongs_to :owner_workspace, RefMD.Workspaces.Workspace
    belongs_to :owner_user, RefMD.Users.User
    belongs_to :created_by_user, RefMD.Users.User
    belongs_to :created_by_device, RefMD.Devices.Device

    field :package_id, :binary_id
    field :plugin_id, :string
    field :version, :string
    field :owner_scope_kind, :string
    field :source_kind, :string
    field :source_url, :string
    field :source_url_hash, :string
    field :archive_hash, :string
    field :manifest_json, :map
    field :manifest_json_bytes, :binary, virtual: true
    field :main_js, :binary, virtual: true
    field :styles_css, :binary, virtual: true
    field :package_entries, {:array, :map}, virtual: true, default: []
    field :manifest_hash, :string
    field :main_js_hash, :string
    field :styles_css_hash, :string
    field :resource_manifest, {:array, :map}, default: []
    field :resource_manifest_hash, :string
    field :bundle_hash, :string
    field :permissions_hash, :string
    field :endpoint_hash, :string
    field :renderer_slots_hash, :string
    field :document_scope_hash, :string
    field :validation_status, :string
    field :validation_errors, {:array, :string}, default: []

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
  end

  @type t :: %__MODULE__{}

  @required_fields [
    :package_id,
    :owner_scope_kind,
    :plugin_id,
    :version,
    :source_kind,
    :source_url_hash,
    :archive_hash,
    :manifest_json,
    :manifest_json_bytes,
    :main_js,
    :styles_css,
    :manifest_hash,
    :main_js_hash,
    :styles_css_hash,
    :resource_manifest,
    :resource_manifest_hash,
    :bundle_hash,
    :permissions_hash,
    :endpoint_hash,
    :renderer_slots_hash,
    :document_scope_hash,
    :validation_status,
    :validation_errors
  ]
  @hash_fields [
    :archive_hash,
    :manifest_hash,
    :main_js_hash,
    :styles_css_hash,
    :resource_manifest_hash,
    :bundle_hash,
    :permissions_hash,
    :endpoint_hash,
    :renderer_slots_hash,
    :document_scope_hash
  ]

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(candidate, attrs) do
    candidate
    |> cast(
      attrs,
      @required_fields ++
        [:workspace_id, :application_id, :source_url, :created_by_user_id, :created_by_device_id]
    )
    |> cast(attrs, [:owner_workspace_id, :owner_user_id, :package_entries])
    |> put_default_owner_scope()
    |> put_default_resource_manifest()
    |> put_change(:styles_css, Map.get(attrs, :styles_css) || Map.get(attrs, "styles_css") || "")
    |> validate_required(@required_fields -- [:styles_css])
    |> validate_inclusion(:source_kind, @source_kinds)
    |> validate_inclusion(:validation_status, @validation_statuses)
    |> validate_non_empty_fields(
      (@required_fields --
         [:manifest_json, :manifest_json_bytes, :styles_css, :validation_errors]) --
        [:resource_manifest]
    )
    |> validate_hash_fields(@hash_fields)
    |> validate_source_url_hash()
    |> validate_source_url()
    |> validate_binary(:manifest_json_bytes)
    |> validate_binary(:main_js)
    |> validate_binary(:styles_css)
    |> validate_owner_scope()
    |> validate_workspace_binding()
    |> unique_constraint([
      :owner_scope_kind,
      :owner_workspace_id,
      :owner_user_id,
      :plugin_id,
      :archive_hash
    ])
    |> foreign_key_constraint(:application_id)
    |> foreign_key_constraint(:owner_workspace_id)
    |> foreign_key_constraint(:owner_user_id)
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:created_by_user_id)
    |> foreign_key_constraint(:created_by_device_id)
  end

  defp put_default_owner_scope(changeset) do
    if get_field(changeset, :owner_scope_kind) do
      changeset
    else
      changeset
      |> put_change(:owner_scope_kind, "workspace")
      |> put_change(:owner_workspace_id, get_field(changeset, :workspace_id))
      |> put_change(:owner_user_id, nil)
    end
  end

  defp put_default_resource_manifest(changeset) do
    changeset
    |> put_change(:resource_manifest, get_field(changeset, :resource_manifest) || [])
    |> put_change(
      :resource_manifest_hash,
      get_field(changeset, :resource_manifest_hash) ||
        Hash.blake3_base64url(JCS.canonical_value_bytes!([]))
    )
  end

  defp validate_owner_scope(changeset) do
    scope = get_field(changeset, :owner_scope_kind)
    workspace_id = get_field(changeset, :owner_workspace_id)
    user_id = get_field(changeset, :owner_user_id)

    case {scope, workspace_id, user_id} do
      {"workspace", workspace_id, nil} when is_binary(workspace_id) -> changeset
      {"user", nil, user_id} when is_binary(user_id) -> changeset
      _ -> add_error(changeset, :owner_scope_kind, "must match exactly one owner id")
    end
  end

  defp validate_workspace_binding(changeset) do
    case {get_field(changeset, :owner_scope_kind), get_field(changeset, :workspace_id)} do
      {"workspace", workspace_id} when is_binary(workspace_id) -> changeset
      {"user", nil} -> changeset
      _ -> add_error(changeset, :workspace_id, "must match owner scope")
    end
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

  defp validate_source_url_hash(changeset) do
    validate_change(changeset, :source_url_hash, fn :source_url_hash, value ->
      try do
        Hash.assert_blake3_base64url!(value, @source_url_hash_sentinels)
        []
      rescue
        ArgumentError -> [source_url_hash: "must be NO_SOURCE_URL or a BLAKE3 base64url hash"]
      end
    end)
  end

  defp validate_source_url(changeset) do
    validate_change(changeset, :source_url, fn :source_url, value ->
      if is_nil(value) or (is_binary(value) and String.trim(value) != "") do
        []
      else
        [source_url: "must not be empty"]
      end
    end)
  end

  defp validate_binary(changeset, field) do
    validate_change(changeset, field, fn ^field, value ->
      if is_binary(value), do: [], else: [{field, "must be binary"}]
    end)
  end
end
