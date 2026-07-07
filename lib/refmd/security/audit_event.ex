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

  schema "security_audit_events" do
    field :class, :string
    field :type, :string
    field :actor, :map
    field :scope, :map
    field :resource, :map
    field :action, :map
    field :sensitivity, :map
    field :correlation, :map

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
    :correlation
  ]

  def changeset(event, attrs) do
    event
    |> cast(attrs, @required_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:class, @classes)
    |> validate_action()
    |> validate_map_fields([:actor, :scope, :resource, :action, :sensitivity, :correlation])
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
end
