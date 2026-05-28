defmodule RefMD.Plugins.UserPluginWorkspacePolicy do
  @moduledoc false

  @default_mode "allow_safe"
  @modes ~w(allow_safe allow_all deny_all)
  @plugin_id_pattern ~r/\A[a-z][a-z0-9._-]{2,127}\z/

  @type t :: %{
          optional(String.t()) => String.t() | boolean() | [String.t()]
        }

  @spec normalize(map() | nil) :: {:ok, map() | nil} | {:error, atom()}
  def normalize(nil), do: {:ok, nil}

  def normalize(policy) when is_map(policy) do
    with {:ok, default_mode} <- normalize_default_mode(policy),
         {:ok, allowed_ids} <- normalize_plugin_ids(Map.get(policy, "allowed_plugin_ids", [])),
         {:ok, denied_ids} <- normalize_plugin_ids(Map.get(policy, "denied_plugin_ids", [])),
         {:ok, require_admin_approval?} <- normalize_require_admin_approval(policy),
         :ok <- validate_disjoint_ids(allowed_ids, denied_ids) do
      {:ok,
       %{
         "default_mode" => default_mode,
         "allowed_plugin_ids" => allowed_ids,
         "denied_plugin_ids" => denied_ids,
         "require_admin_approval" => require_admin_approval?
       }}
    end
  end

  def normalize(_policy), do: {:error, :invalid_policy}

  @spec evaluate(map() | nil, String.t(), boolean()) :: String.t()
  def evaluate(policy, plugin_id, admin_approval_required?) do
    policy = normalize_or_default(policy)
    allowed_ids = Map.fetch!(policy, "allowed_plugin_ids")
    denied_ids = Map.fetch!(policy, "denied_plugin_ids")

    cond do
      plugin_id in denied_ids ->
        "denied"

      plugin_id in allowed_ids ->
        "allowed"

      policy["default_mode"] == "deny_all" ->
        "denied"

      policy["default_mode"] == "allow_all" ->
        "allowed"

      policy["require_admin_approval"] and admin_approval_required? ->
        "needs_admin_review"

      true ->
        "allowed"
    end
  end

  defp normalize_or_default(policy) do
    case normalize(policy) do
      {:ok, nil} -> default_policy()
      {:ok, normalized} -> normalized
      {:error, _reason} -> default_policy()
    end
  end

  defp default_policy do
    %{
      "default_mode" => @default_mode,
      "allowed_plugin_ids" => [],
      "denied_plugin_ids" => [],
      "require_admin_approval" => true
    }
  end

  defp normalize_default_mode(policy) do
    mode = Map.get(policy, "default_mode", @default_mode)

    if mode in @modes do
      {:ok, mode}
    else
      {:error, :invalid_default_mode}
    end
  end

  defp normalize_plugin_ids(value) when is_list(value) do
    value
    |> Enum.reduce_while({:ok, []}, fn
      id, {:ok, ids} when is_binary(id) ->
        id = String.trim(id)

        if Regex.match?(@plugin_id_pattern, id) do
          {:cont, {:ok, [id | ids]}}
        else
          {:halt, {:error, :invalid_plugin_id}}
        end

      _value, _acc ->
        {:halt, {:error, :invalid_plugin_id}}
    end)
    |> case do
      {:ok, ids} -> {:ok, ids |> Enum.reverse() |> Enum.uniq()}
      error -> error
    end
  end

  defp normalize_plugin_ids(_value), do: {:error, :invalid_plugin_ids}

  defp normalize_require_admin_approval(policy) do
    case Map.get(policy, "require_admin_approval", true) do
      value when is_boolean(value) -> {:ok, value}
      _value -> {:error, :invalid_require_admin_approval}
    end
  end

  defp validate_disjoint_ids(allowed_ids, denied_ids) do
    if MapSet.disjoint?(MapSet.new(allowed_ids), MapSet.new(denied_ids)) do
      :ok
    else
      {:error, :overlapping_plugin_ids}
    end
  end
end
