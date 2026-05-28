defmodule RefMD.Plugins.PluginBundle do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Plugins.PluginApplication
  alias RefMD.Repo

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @source_kinds ~w(remote_https_url local_upload)
  @source_url_hash_sentinels MapSet.new(["NO_SOURCE_URL"])

  schema "plugin_bundles" do
    belongs_to :package, RefMD.Plugins.PluginPackage
    belongs_to :application, RefMD.Plugins.PluginApplication
    belongs_to :candidate, RefMD.Plugins.PluginBundleCandidate
    belongs_to :workspace, RefMD.Workspaces.Workspace
    belongs_to :approved_by_user, RefMD.Users.User
    belongs_to :approved_by_device, RefMD.Devices.Device

    field :plugin_id, :string
    field :version, :string
    field :source_kind, :string
    field :source_url_hash, :string
    field :archive_hash, :string
    field :manifest_json, :map
    field :manifest_json_bytes, :binary, virtual: true
    field :main_js, :binary, virtual: true
    field :styles_css, :binary, virtual: true
    field :bundle_hash, :string
    field :manifest_hash, :string
    field :main_js_hash, :string
    field :styles_css_hash, :string
    field :resource_manifest, {:array, :map}, default: []
    field :resource_manifest_hash, :string
    field :permissions_hash, :string
    field :endpoint_hash, :string
    field :renderer_slots_hash, :string
    field :document_scope_hash, :string
    field :approval_epoch, :integer
    field :approval_authority_event_head_sequence, :integer
    field :approval_authority_event_head_hash, :string
    field :approval_authority_checkpoint_sequence, :integer
    field :approval_authority_checkpoint_hash, :string
    field :previous_approval_event_hash, :string
    field :approval_event_hash, :string
    field :hybrid_signature, :map
    field :approved_at_ms, :integer

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @required_fields [
    :candidate_id,
    :package_id,
    :plugin_id,
    :version,
    :source_kind,
    :source_url_hash,
    :archive_hash,
    :manifest_json,
    :bundle_hash,
    :manifest_hash,
    :main_js_hash,
    :styles_css_hash,
    :resource_manifest,
    :resource_manifest_hash,
    :permissions_hash,
    :endpoint_hash,
    :renderer_slots_hash,
    :document_scope_hash,
    :approval_epoch,
    :approval_authority_event_head_sequence,
    :approval_authority_event_head_hash,
    :approval_authority_checkpoint_sequence,
    :approval_authority_checkpoint_hash,
    :previous_approval_event_hash,
    :approval_event_hash
  ]
  @hash_fields [
    :archive_hash,
    :bundle_hash,
    :manifest_hash,
    :main_js_hash,
    :styles_css_hash,
    :resource_manifest_hash,
    :permissions_hash,
    :endpoint_hash,
    :renderer_slots_hash,
    :document_scope_hash,
    :approval_authority_event_head_hash,
    :approval_authority_checkpoint_hash,
    :approval_event_hash
  ]
  @integer_fields [
    :approval_epoch,
    :approval_authority_event_head_sequence,
    :approval_authority_checkpoint_sequence
  ]

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(bundle, attrs) do
    bundle
    |> cast(
      attrs,
      @required_fields ++
        [
          :application_id,
          :workspace_id,
          :approved_by_user_id,
          :approved_by_device_id,
          :approval_authority_event_head_sequence,
          :approval_authority_event_head_hash,
          :approval_authority_checkpoint_sequence,
          :approval_authority_checkpoint_hash,
          :hybrid_signature,
          :approved_at_ms
        ]
    )
    |> put_change(
      :manifest_json_bytes,
      Map.get(attrs, :manifest_json_bytes) || Map.get(attrs, "manifest_json_bytes")
    )
    |> put_change(:main_js, Map.get(attrs, :main_js) || Map.get(attrs, "main_js"))
    |> put_change(:styles_css, Map.get(attrs, :styles_css) || Map.get(attrs, "styles_css") || "")
    |> put_default_package_id()
    |> put_default_resource_manifest()
    |> validate_required(@required_fields ++ [:hybrid_signature])
    |> validate_inclusion(:source_kind, @source_kinds)
    |> validate_number(:approval_epoch, greater_than: 0)
    |> validate_number(:approval_authority_event_head_sequence, greater_than_or_equal_to: 0)
    |> validate_number(:approval_authority_checkpoint_sequence, greater_than: 0)
    |> validate_non_empty_fields(
      (@required_fields -- @integer_fields) -- [:manifest_json, :resource_manifest]
    )
    |> validate_hash_fields(@hash_fields)
    |> validate_source_url_hash()
    |> validate_previous_approval_event_hash()
    |> validate_signature()
    |> validate_runtime_binding()
    |> unique_constraint([:application_id, :bundle_hash])
    |> unique_constraint([:application_id, :approval_event_hash])
    |> unique_constraint([:package_id, :bundle_hash])
    |> foreign_key_constraint(:package_id)
    |> foreign_key_constraint(:application_id)
    |> foreign_key_constraint(:candidate_id)
    |> foreign_key_constraint(:workspace_id)
    |> foreign_key_constraint(:approved_by_user_id)
    |> foreign_key_constraint(:approved_by_device_id)
  end

  defp put_default_package_id(changeset) do
    if get_field(changeset, :package_id) do
      changeset
    else
      case Repo.get(PluginApplication, get_field(changeset, :application_id)) do
        %PluginApplication{package_id: package_id} when is_binary(package_id) ->
          put_change(changeset, :package_id, package_id)

        _ ->
          changeset
      end
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

  defp validate_previous_approval_event_hash(changeset) do
    validate_change(changeset, :previous_approval_event_hash, fn
      :previous_approval_event_hash, "GENESIS" ->
        []

      :previous_approval_event_hash, value ->
        try do
          Hash.assert_blake3_base64url!(value)
          []
        rescue
          ArgumentError ->
            [previous_approval_event_hash: "must be GENESIS or a BLAKE3 base64url hash"]
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

  defp validate_runtime_binding(changeset) do
    case {get_field(changeset, :application_id), get_field(changeset, :workspace_id)} do
      {application_id, workspace_id} when is_binary(application_id) and is_binary(workspace_id) ->
        changeset

      {nil, workspace_id} when is_binary(workspace_id) ->
        changeset

      {nil, nil} ->
        changeset

      _ ->
        add_error(
          changeset,
          :application_id,
          "must have both application and workspace or neither"
        )
    end
  end
end
