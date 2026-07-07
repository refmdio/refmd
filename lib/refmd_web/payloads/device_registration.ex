defmodule RefMDWeb.Payloads.DeviceRegistration do
  @moduledoc false

  def valid_ake_responder_prekeys?(%{
        "umk_distribution" => umk,
        "trust_transfer" => trust,
        "device_approval_kek_initial" => device_approval
      })
      when is_map(umk) and is_map(trust) and is_list(device_approval),
      do: Enum.all?(device_approval, &valid_device_approval_prekey_entry?/1)

  def valid_ake_responder_prekeys?(_), do: false

  def normalize_ake_responder_prekeys(nil), do: nil

  def normalize_ake_responder_prekeys(prekeys) when is_map(prekeys) do
    prekeys
    |> Map.take(["umk_distribution", "trust_transfer"])
    |> Map.merge(
      prekeys
      |> Map.get("device_approval_kek_initial", [])
      |> Map.new(fn %{"workspace_id" => workspace_id, "prekey" => prekey} ->
        {"device_approval_kek_initial:" <> workspace_id, prekey}
      end)
    )
  end

  def denormalize_ake_responder_prekeys(nil), do: nil

  def denormalize_ake_responder_prekeys(prekeys) when is_map(prekeys) do
    device_approval =
      prekeys
      |> Enum.flat_map(fn
        {"device_approval_kek_initial:" <> workspace_id, prekey} ->
          [%{"workspace_id" => workspace_id, "prekey" => prekey}]

        _ ->
          []
      end)
      |> Enum.sort_by(& &1["workspace_id"])

    %{
      "umk_distribution" => Map.fetch!(prekeys, "umk_distribution"),
      "trust_transfer" => Map.fetch!(prekeys, "trust_transfer"),
      "device_approval_kek_initial" => device_approval
    }
  end

  def normalize_approval_delivery_artifacts(params) when is_map(params) do
    Map.update(
      params,
      "device_approval_kek_initial_deliveries",
      nil,
      &normalize_device_approval_kek_initial_deliveries/1
    )
  end

  def denormalize_approval_delivery_artifacts(nil), do: nil

  def denormalize_approval_delivery_artifacts(artifacts) when is_map(artifacts) do
    Map.update(
      artifacts,
      "device_approval_kek_initial_deliveries",
      [],
      &denormalize_device_approval_kek_initial_deliveries/1
    )
  end

  defp valid_device_approval_prekey_entry?(%{"workspace_id" => workspace_id, "prekey" => prekey})
       when is_binary(workspace_id) and is_map(prekey),
       do: true

  defp valid_device_approval_prekey_entry?(_), do: false

  defp normalize_device_approval_kek_initial_deliveries(nil), do: nil

  defp normalize_device_approval_kek_initial_deliveries(deliveries) when is_list(deliveries) do
    Map.new(deliveries, fn %{"workspace_id" => workspace_id, "delivery" => delivery} ->
      {workspace_id, delivery}
    end)
  end

  defp normalize_device_approval_kek_initial_deliveries(deliveries), do: deliveries

  defp denormalize_device_approval_kek_initial_deliveries(deliveries) when is_map(deliveries) do
    deliveries
    |> Enum.map(fn {workspace_id, delivery} ->
      %{"workspace_id" => workspace_id, "delivery" => delivery}
    end)
    |> Enum.sort_by(& &1["workspace_id"])
  end

  defp denormalize_device_approval_kek_initial_deliveries(deliveries), do: deliveries
end
