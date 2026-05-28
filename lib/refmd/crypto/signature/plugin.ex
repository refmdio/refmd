defmodule RefMD.Crypto.Signature.Plugin do
  @moduledoc false

  @protocol_version 1

  import RefMD.Crypto.Signature.Core, only: [assert_transcript!: 4, transcript_base: 4]

  alias RefMD.Crypto.{Hash, JCS}
  alias RefMD.Crypto.SigningSurface

  @spec build_plugin_bundle_approval_transcript!(map()) :: map()
  def build_plugin_bundle_approval_transcript!(params) when is_map(params) do
    actor = fetch_map!(params, :actor)
    approval = fetch_map!(params, :approval)
    assert_owner_actor!(actor, approval, "plugin_bundle_approval_actor_invalid")
    owner_id = Map.fetch!(actor, "device_id")
    surface = SigningSurface.get_active!("plugin_bundle_approval", "none")

    transcript =
      transcript_base("plugin_bundle_approval", surface, "device", owner_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(approval)),
        "subject_protocol" => "refmd.plugin-bundle-approval",
        "subject_version" => @protocol_version,
        "actor" => actor,
        "approval" => approval
      })

    assert_transcript!(transcript, "plugin_bundle_approval", "device", owner_id)
    transcript
  end

  def build_plugin_bundle_approval_transcript!(_),
    do: raise(ArgumentError, "plugin_bundle_approval_transcript_invalid")

  @spec build_plugin_consent_event_transcript!(map()) :: map()
  def build_plugin_consent_event_transcript!(params) when is_map(params) do
    actor = fetch_map!(params, :actor)
    consent = fetch_map!(params, :consent)
    assert_workspace_actor!(actor, consent, "plugin_consent_event_actor_invalid")
    assert_consent_actor_subject!(actor, consent, "plugin_consent_event_actor_invalid")
    owner_id = Map.fetch!(actor, "device_id")
    surface = SigningSurface.get_active!("plugin_consent_event", "none")

    transcript =
      transcript_base("plugin_consent_event", surface, "device", owner_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(consent)),
        "subject_protocol" => "refmd.plugin-consent-event",
        "subject_version" => @protocol_version,
        "actor" => actor,
        "consent" => consent
      })

    assert_transcript!(transcript, "plugin_consent_event", "device", owner_id)
    transcript
  end

  def build_plugin_consent_event_transcript!(_),
    do: raise(ArgumentError, "plugin_consent_event_transcript_invalid")

  @spec build_plugin_network_proxy_request_transcript!(map()) :: map()
  def build_plugin_network_proxy_request_transcript!(params) when is_map(params) do
    subject = fetch_map!(params, :subject)

    assert_plugin_network_proxy_request_subject!(
      subject,
      "plugin_network_proxy_request_subject_invalid"
    )

    runtime =
      required_subject_map!(subject, "runtime", "plugin_network_proxy_request_subject_invalid")

    owner_id = Map.fetch!(runtime, "device_id")
    surface = SigningSurface.get_active!("plugin_network_proxy_request", "none")

    transcript =
      transcript_base("plugin_network_proxy_request", surface, "device", owner_id)
      |> Map.merge(%{
        "subject_hash" => Hash.blake3_base64url(JCS.canonical_bytes!(subject)),
        "subject_protocol" => "refmd.plugin-network-proxy-request-subject",
        "subject_version" => @protocol_version,
        "subject" => subject
      })

    assert_transcript!(transcript, "plugin_network_proxy_request", "device", owner_id)
    transcript
  end

  def build_plugin_network_proxy_request_transcript!(_),
    do: raise(ArgumentError, "plugin_network_proxy_request_transcript_invalid")

  defp fetch_map!(params, key) do
    case Map.fetch(params, key) do
      {:ok, value} when is_map(value) -> value
      :error -> Map.fetch!(params, Atom.to_string(key))
      _ -> raise(ArgumentError, "plugin_transcript_invalid")
    end
  end

  defp required_subject_map!(subject, key, error) do
    case Map.fetch(subject, key) do
      {:ok, value} when is_map(value) -> value
      _ -> raise(ArgumentError, error)
    end
  end

  defp assert_workspace_actor!(actor, subject, error) do
    if actor["key_scope_kind"] == "workspace" and actor["key_scope_id"] == subject["workspace_id"] do
      :ok
    else
      raise ArgumentError, error
    end
  end

  defp assert_consent_actor_subject!(actor, consent, error) do
    if actor["user_id"] == consent["user_id"] and
         actor["device_id"] == consent["device_id"] do
      :ok
    else
      raise ArgumentError, error
    end
  end

  defp assert_plugin_network_proxy_request_subject!(subject, error) do
    assert_exact_subject_keys!(
      subject,
      ["endpoint", "protocol", "proxy", "request_id", "runtime", "target", "version"],
      error
    )

    assert_required_string!(subject, "protocol", error)
    assert_required_positive_integer!(subject, "version", error)
    assert_required_string!(subject, "request_id", error)

    proxy = required_subject_map!(subject, "proxy", error)
    assert_exact_subject_keys!(proxy, ["id", "origin", "scope"], error)
    assert_required_string!(proxy, "id", error)
    assert_required_string!(proxy, "scope", error)
    assert_required_string!(proxy, "origin", error)

    target = required_subject_map!(subject, "target", error)
    assert_exact_subject_keys!(target, ["body_text", "headers", "method", "url"], error)
    assert_required_string!(target, "url", error)
    assert_required_string!(target, "method", error)
    required_subject_map!(target, "headers", error)
    assert_required_string_present!(target, "body_text", error)

    endpoint = required_subject_map!(subject, "endpoint", error)

    assert_exact_subject_keys!(endpoint, proxy_request_endpoint_keys(endpoint), error)

    assert_required_string!(endpoint, "id", error)
    assert_required_positive_integer!(endpoint, "max_request_bytes", error)
    assert_required_positive_integer!(endpoint, "max_response_bytes", error)

    if Map.has_key?(endpoint, "credential_audience") do
      assert_required_string!(endpoint, "credential_audience", error)
    end

    runtime = required_subject_map!(subject, "runtime", error)

    assert_exact_subject_keys!(
      runtime,
      [
        "activation_id",
        "application_id",
        "capability_grant_id",
        "consent_epoch",
        "credential_handle_used",
        "device_id",
        "frame_generation",
        "owner_scope_kind",
        "package_id",
        "plugin_id",
        "request_id",
        "user_id",
        "workspace_id"
      ],
      error
    )

    assert_required_string!(runtime, "workspace_id", error)
    assert_required_string!(runtime, "plugin_id", error)
    assert_required_string!(runtime, "package_id", error)
    assert_required_string!(runtime, "application_id", error)
    assert_required_string!(runtime, "activation_id", error)
    assert_required_positive_integer!(runtime, "frame_generation", error)
    assert_required_string!(runtime, "user_id", error)
    assert_required_string!(runtime, "device_id", error)
    assert_required_string!(runtime, "owner_scope_kind", error)
    assert_required_positive_integer!(runtime, "consent_epoch", error)
    assert_required_string!(runtime, "capability_grant_id", error)
    assert_required_string!(runtime, "request_id", error)
    assert_required_boolean!(runtime, "credential_handle_used", error)
  end

  defp assert_exact_subject_keys!(map, expected_keys, error) do
    if Enum.sort(Map.keys(map)) == Enum.sort(expected_keys) do
      :ok
    else
      raise ArgumentError, error
    end
  end

  defp proxy_request_endpoint_keys(endpoint) do
    keys = ["id", "max_request_bytes", "max_response_bytes"]

    if Map.has_key?(endpoint, "credential_audience"),
      do: ["credential_audience" | keys],
      else: keys
  end

  defp assert_required_string!(map, key, error) do
    case Map.fetch(map, key) do
      {:ok, value} when is_binary(value) and byte_size(value) > 0 -> :ok
      _ -> raise ArgumentError, error
    end
  end

  defp assert_required_string_present!(map, key, error) do
    case Map.fetch(map, key) do
      {:ok, value} when is_binary(value) -> :ok
      _ -> raise ArgumentError, error
    end
  end

  defp assert_required_positive_integer!(map, key, error) do
    case Map.fetch(map, key) do
      {:ok, value} when is_integer(value) and value >= 1 -> :ok
      _ -> raise ArgumentError, error
    end
  end

  defp assert_required_boolean!(map, key, error) do
    case Map.fetch(map, key) do
      {:ok, value} when is_boolean(value) -> :ok
      _ -> raise ArgumentError, error
    end
  end

  defp assert_owner_actor!(actor, subject, error) do
    expected_scope_kind = Map.fetch!(subject, "owner_scope_kind")

    expected_scope_id =
      case expected_scope_kind do
        "workspace" -> Map.fetch!(subject, "owner_workspace_id")
        "user" -> Map.fetch!(subject, "owner_user_id")
        _ -> raise ArgumentError, error
      end

    if actor["key_scope_kind"] == expected_scope_kind and
         actor["key_scope_id"] == expected_scope_id do
      :ok
    else
      raise ArgumentError, error
    end
  end
end
