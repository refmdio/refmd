defmodule RefMD.Security.AuditEvent do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @classes ~w(authority security_runtime)
  @results ~w(allowed denied failed completed)
  @plaintext_keys MapSet.new(~w(
    plaintext
    document_body
    selected_text
    request_body
    response_body
    credential_secret
    api_key
    oauth_token
    dek
    kek
    umk
    private_key
    password
    recovery_words
  ))
  @allowed_map_keys %{
    actor: MapSet.new(~w(user_id device_id session_id principal_kind principal_id kind id)),
    scope: MapSet.new(~w(workspace_id document_id share_id)),
    resource:
      MapSet.new(
        ~w(kind id version_hash plugin_id package_id application_id activation_id owner_scope_kind capability_grant_id bundle_hash manifest_hash)
      ),
    action:
      MapSet.new(
        ~w(operation result reason_code endpoint_id route method target_origin target_path request_bytes response_bytes credential_handle_used proxy_id fallback_reason)
      ),
    sensitivity:
      MapSet.new(~w(plaintext_scope_kind plaintext_bytes egress_bytes storage_bytes category)),
    correlation:
      MapSet.new(
        ~w(request_id capability_id execution_context_id authority_event_ref package_id application_id activation_id owner_scope_kind capability_grant_id frame_generation candidate_id source_kind canonical_source_host archive_hash bundle_hash manifest_hash permissions_hash endpoint_hash)
      )
  }

  schema "security_audit_events" do
    field :class, :string
    field :type, :string
    field :actor, :map
    field :scope, :map
    field :resource, :map
    field :action, :map
    field :sensitivity, :map
    field :correlation, :map
    field :chain_scope, :string
    field :sequence, :integer
    field :previous_event_hash, :string
    field :event_hash, :string

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
  end

  @required_fields [
    :class,
    :type,
    :actor,
    :scope,
    :resource,
    :action,
    :sensitivity,
    :correlation,
    :chain_scope,
    :sequence,
    :event_hash
  ]
  @optional_fields [:previous_event_hash]

  def changeset(event, attrs) do
    event
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:class, @classes)
    |> validate_number(:sequence, greater_than: 0)
    |> validate_format(:event_hash, ~r/^[A-Za-z0-9_-]{43}$/)
    |> validate_format(:previous_event_hash, ~r/^[A-Za-z0-9_-]{43}$/)
    |> validate_action()
    |> validate_map_fields([:actor, :scope, :resource, :action, :sensitivity, :correlation])
    |> validate_allowed_metadata()
    |> validate_no_sensitive_payload()
  end

  defp validate_action(changeset) do
    validate_change(changeset, :action, fn :action, action ->
      result = Map.get(action || %{}, "result") || Map.get(action || %{}, :result)

      if result in @results do
        []
      else
        [action: "must include a supported result"]
      end
    end)
  end

  defp validate_map_fields(changeset, fields) do
    Enum.reduce(fields, changeset, &validate_map_field(&2, &1))
  end

  defp validate_map_field(changeset, field) do
    validate_change(changeset, field, &map_field_errors/2)
  end

  defp map_field_errors(field, value) do
    if is_map(value), do: [], else: [{field, "must be a map"}]
  end

  defp validate_no_sensitive_payload(changeset) do
    Enum.reduce(@required_fields, changeset, &validate_sensitive_payload_field(&2, &1))
  end

  defp validate_sensitive_payload_field(changeset, field) do
    validate_change(changeset, field, &sensitive_payload_errors/2)
  end

  defp sensitive_payload_errors(field, value) do
    if contains_sensitive_key?(value),
      do: [{field, "must not include sensitive payload"}],
      else: []
  end

  defp contains_sensitive_key?(%{} = value) do
    Enum.any?(value, fn {key, nested} ->
      normalized = key |> to_string() |> Macro.underscore()
      MapSet.member?(@plaintext_keys, normalized) or contains_sensitive_key?(nested)
    end)
  end

  defp contains_sensitive_key?(value) when is_list(value),
    do: Enum.any?(value, &contains_sensitive_key?/1)

  defp contains_sensitive_key?(_value), do: false

  defp validate_allowed_metadata(changeset) do
    Enum.reduce(@allowed_map_keys, changeset, fn {field, allowed}, acc ->
      validate_change(acc, field, &allowed_metadata_errors(&1, &2, allowed))
    end)
  end

  defp allowed_metadata_errors(field, value, allowed) do
    unsupported =
      value
      |> Map.keys()
      |> Enum.map(&to_string/1)
      |> Enum.reject(&MapSet.member?(allowed, &1))

    if unsupported == [], do: [], else: [{field, "contains unsupported metadata fields"}]
  end
end
