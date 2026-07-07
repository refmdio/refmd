defmodule RefMD.Sharing.Share do
  use Ecto.Schema
  import Ecto.Changeset
  alias RefMD.Crypto.Signature

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "shares" do
    belongs_to :document, RefMD.Documents.Document
    belongs_to :parent_share, __MODULE__
    belongs_to :created_by_user, RefMD.Users.User, foreign_key: :created_by

    field :scope, :string
    field :token_hash, :string
    field :token_prefix, :string
    field :authorization_public_key_material, :map
    field :share_capability_secret_commitment, :string
    field :password_capability_secret_commitment, :string
    field :capability_context_hash, :string
    field :created_event_hash, :string
    field :latest_bootstrap_event_hash, :string
    field :authenticated_workspace_pin_bootstrap_hash, :string
    field :authenticated_workspace_pin_bootstrap_checkpoint, :map
    field :permission, :string
    field :permission_version, :integer, default: 1
    field :password_protected, :boolean, default: false
    field :max_views, :integer
    field :view_count, :integer, default: 0
    field :expires_event_sequence, :integer

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  def changeset(share, attrs) do
    share
    |> cast(attrs, [
      :id,
      :document_id,
      :parent_share_id,
      :scope,
      :token_hash,
      :token_prefix,
      :authorization_public_key_material,
      :share_capability_secret_commitment,
      :password_capability_secret_commitment,
      :capability_context_hash,
      :created_event_hash,
      :latest_bootstrap_event_hash,
      :authenticated_workspace_pin_bootstrap_hash,
      :authenticated_workspace_pin_bootstrap_checkpoint,
      :permission,
      :permission_version,
      :password_protected,
      :max_views,
      :view_count,
      :created_by,
      :expires_event_sequence
    ])
    |> default_latest_bootstrap_event_hash()
    |> validate_required([
      :id,
      :document_id,
      :scope,
      :token_hash,
      :token_prefix,
      :share_capability_secret_commitment,
      :password_capability_secret_commitment,
      :capability_context_hash,
      :created_event_hash,
      :latest_bootstrap_event_hash,
      :authenticated_workspace_pin_bootstrap_hash,
      :authenticated_workspace_pin_bootstrap_checkpoint,
      :permission,
      :password_protected,
      :max_views,
      :expires_event_sequence,
      :created_by
    ])
    |> validate_inclusion(:scope, ~w(document folder))
    |> validate_inclusion(:permission, ~w(view edit))
    |> validate_length(:token_hash, is: 43)
    |> validate_format(:token_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_length(:token_prefix, is: 4)
    |> validate_format(:token_prefix, ~r/^[A-Za-z0-9\-_]{4}$/)
    |> validate_authorization_public_key_material()
    |> validate_length(:share_capability_secret_commitment, is: 43)
    |> validate_format(:share_capability_secret_commitment, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_change(:password_capability_secret_commitment, fn
      :password_capability_secret_commitment, "none" ->
        []

      :password_capability_secret_commitment, value when is_binary(value) ->
        if String.match?(value, ~r/^[A-Za-z0-9\-_]{43}$/),
          do: [],
          else: [password_capability_secret_commitment: "is invalid"]

      :password_capability_secret_commitment, _ ->
        [password_capability_secret_commitment: "is invalid"]
    end)
    |> validate_length(:capability_context_hash, is: 43)
    |> validate_format(:capability_context_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_length(:created_event_hash, is: 43)
    |> validate_format(:created_event_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_length(:latest_bootstrap_event_hash, is: 43)
    |> validate_format(:latest_bootstrap_event_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_length(:authenticated_workspace_pin_bootstrap_hash, is: 43)
    |> validate_format(:authenticated_workspace_pin_bootstrap_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_number(:view_count, greater_than_or_equal_to: 0)
    |> validate_number(:max_views, greater_than: 0)
    |> validate_number(:expires_event_sequence, greater_than: 0)
    |> check_constraint(:max_views, name: :shares_max_views_positive)
    |> unique_constraint(:token_hash)
    |> unique_constraint([:parent_share_id, :document_id],
      name: :shares_parent_share_document_id_index
    )
    |> unique_constraint(:id, name: :shares_pkey)
    |> foreign_key_constraint(:document_id)
    |> foreign_key_constraint(:created_by)
    |> foreign_key_constraint(:parent_share_id)
  end

  defp validate_authorization_public_key_material(changeset) do
    case {
      get_field(changeset, :parent_share_id),
      get_field(changeset, :token_hash),
      get_field(changeset, :authorization_public_key_material)
    } do
      {nil, token_hash, %{} = material} when is_binary(token_hash) ->
        validate_root_authorization_public_key_material(changeset, token_hash, material)

      {nil, _token_hash, _material} ->
        add_error(changeset, :authorization_public_key_material, "is invalid")

      {_parent_share_id, _token_hash, nil} ->
        changeset

      {_parent_share_id, _token_hash, _material} ->
        add_error(changeset, :authorization_public_key_material, "is invalid")
    end
  end

  defp validate_root_authorization_public_key_material(changeset, token_hash, material) do
    Signature.assert_public_key_material!(material)

    case material do
      %{"owner_kind" => "share_capability", "owner_id" => ^token_hash} ->
        changeset

      _ ->
        add_error(changeset, :authorization_public_key_material, "is invalid")
    end
  rescue
    ArgumentError -> add_error(changeset, :authorization_public_key_material, "is invalid")
  end

  defp default_latest_bootstrap_event_hash(changeset) do
    case {get_field(changeset, :latest_bootstrap_event_hash),
          get_field(changeset, :created_event_hash)} do
      {nil, created_event_hash} when is_binary(created_event_hash) ->
        put_change(changeset, :latest_bootstrap_event_hash, created_event_hash)

      _ ->
        changeset
    end
  end

  def update_settings_changeset(share, attrs) do
    share
    |> cast(attrs, [
      :expires_event_sequence,
      :max_views,
      :permission_version,
      :latest_bootstrap_event_hash
    ])
    |> validate_length(:latest_bootstrap_event_hash, is: 43)
    |> validate_format(:latest_bootstrap_event_hash, ~r/^[A-Za-z0-9\-_]{43}$/)
    |> validate_number(:max_views, greater_than: 0)
    |> validate_number(:expires_event_sequence, greater_than: 0)
    |> validate_number(:permission_version, greater_than: 0)
    |> check_constraint(:max_views, name: :shares_max_views_positive)
  end
end
