defmodule RefMD.Sharing.Capability do
  @moduledoc false

  alias RefMD.Crypto.{Blake3, JCS}
  alias RefMD.Sharing.Share

  @max_safe_integer 9_007_199_254_740_991

  @spec hash!(map()) :: binary()
  def hash!(attrs) when is_map(attrs) do
    attrs
    |> context!()
    |> JCS.canonical_bytes!()
    |> Blake3.hash_base64url()
  end

  @spec context!(map()) :: map()
  def context!(attrs) when is_map(attrs) do
    %{
      "protocol" => "refmd.share-capability-context",
      "version" => 1,
      "workspace_id" => fetch!(attrs, :workspace_id),
      "share_id" => fetch!(attrs, :share_id),
      "scope_kind" => fetch!(attrs, :scope_kind),
      "scope_id" => fetch!(attrs, :scope_id),
      "token_hash" => fetch!(attrs, :token_hash),
      "permission" => fetch!(attrs, :permission),
      "share_capability_secret_commitment" => fetch!(attrs, :share_capability_secret_commitment),
      "workspace_pin_bootstrap_hash" => fetch!(attrs, :workspace_pin_bootstrap_hash),
      "authenticated_bootstrap_source" =>
        optional_attr(attrs, :authenticated_bootstrap_source, "url-fragment"),
      "password_protected" => fetch!(attrs, :password_protected),
      "password_auth_metadata_hash" => optional_attr(attrs, :password_auth_metadata_hash, "none"),
      "password_capability_secret_commitment" =>
        optional_attr(attrs, :password_capability_secret_commitment, "none"),
      "max_views" => optional_attr(attrs, :max_views, @max_safe_integer),
      "redeem_authority_policy" =>
        optional_attr(attrs, :redeem_authority_policy, "capability_url")
    }
  end

  @spec from_share!(Share.t(), binary()) :: binary()
  @spec from_share!(Share.t(), binary(), binary() | nil) :: binary()
  def from_share!(%Share{} = share, workspace_id, token_hash \\ nil) do
    hash!(%{
      workspace_id: workspace_id,
      share_id: share.id,
      scope_kind: share.scope,
      scope_id: share.document_id,
      token_hash: token_hash || share.token_hash,
      permission: share.permission,
      password_protected: share.password_protected,
      share_capability_secret_commitment: share.share_capability_secret_commitment,
      password_capability_secret_commitment: share.password_capability_secret_commitment,
      workspace_pin_bootstrap_hash: share.authenticated_workspace_pin_bootstrap_hash,
      max_views: share.max_views || @max_safe_integer,
      redeem_authority_policy:
        if(share.password_protected, do: "password_challenge", else: "capability_url")
    })
  end

  defp fetch!(attrs, key) do
    Map.fetch!(attrs, key)
  rescue
    KeyError -> Map.fetch!(attrs, Atom.to_string(key))
  end

  defp optional_attr(attrs, key, default) do
    Map.get(attrs, key) || Map.get(attrs, Atom.to_string(key)) || default
  end
end
