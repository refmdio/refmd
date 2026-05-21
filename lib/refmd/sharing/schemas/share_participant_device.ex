defmodule RefMD.Sharing.ShareParticipantDevice do
  use Ecto.Schema
  import Ecto.Changeset

  alias RefMD.Crypto.{HybridEncryptionMaterial, Signature}

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "share_participant_devices" do
    belongs_to :share, RefMD.Sharing.Share
    belongs_to :principal, RefMD.Sharing.ShareParticipantPrincipal

    field :hybrid_signing_public_key_material, :map
    field :signing_key_id, :string
    field :hybrid_encryption_public_key_material, :map
    field :encryption_key_id, :string
    field :revoked_at, :utc_datetime_usec
    field :last_seen_at, :utc_datetime_usec

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(device, attrs) do
    device
    |> cast(attrs, [
      :id,
      :share_id,
      :principal_id,
      :hybrid_signing_public_key_material,
      :signing_key_id,
      :hybrid_encryption_public_key_material,
      :encryption_key_id,
      :revoked_at,
      :last_seen_at
    ])
    |> validate_required([
      :id,
      :share_id,
      :principal_id,
      :hybrid_signing_public_key_material,
      :signing_key_id,
      :hybrid_encryption_public_key_material,
      :last_seen_at
    ])
    |> validate_change(
      :hybrid_signing_public_key_material,
      &validate_hybrid_signing_public_key_material/2
    )
    |> validate_change(:signing_key_id, &validate_signing_key_id/2)
    |> validate_material_binding()
    |> validate_hybrid_encryption_material()
    |> unique_constraint([:share_id, :signing_key_id])
    |> unique_constraint([:share_id, :encryption_key_id])
    |> foreign_key_constraint(:share_id)
    |> foreign_key_constraint(:principal_id)
  end

  defp validate_hybrid_signing_public_key_material(:hybrid_signing_public_key_material, material) do
    Signature.assert_public_key_material!(material)

    if material["owner_kind"] == "share_participant_device" do
      []
    else
      [hybrid_signing_public_key_material: "must belong to a share participant device"]
    end
  rescue
    ArgumentError -> [hybrid_signing_public_key_material: "is invalid"]
  end

  defp validate_signing_key_id(:signing_key_id, signing_key_id) do
    if is_binary(signing_key_id) and byte_size(signing_key_id) > 0 do
      []
    else
      [signing_key_id: "is invalid"]
    end
  end

  defp validate_material_binding(changeset) do
    material = get_field(changeset, :hybrid_signing_public_key_material)
    device_id = get_field(changeset, :id)
    signing_key_id = get_field(changeset, :signing_key_id)

    cond do
      not is_map(material) ->
        changeset

      material["owner_id"] != device_id ->
        add_error(changeset, :hybrid_signing_public_key_material, "owner_id must match device id")

      Signature.compute_signing_key_id!(material) != signing_key_id ->
        add_error(changeset, :signing_key_id, "does not match hybrid signing material")

      true ->
        changeset
    end
  rescue
    ArgumentError -> add_error(changeset, :hybrid_signing_public_key_material, "is invalid")
  end

  defp validate_hybrid_encryption_material(changeset) do
    changeset
    |> put_encryption_key_id()
    |> validate_change(:hybrid_encryption_public_key_material, fn field, material ->
      device_id = get_field(changeset, :id)

      try do
        with :ok <- HybridEncryptionMaterial.assert_public_key_material!(material),
             true <- material["owner_kind"] == "share_participant_device",
             true <- is_binary(device_id),
             true <- material["owner_id"] == device_id do
          []
        else
          _ -> [{field, "must be valid share participant hybrid encryption material"}]
        end
      rescue
        ArgumentError -> [{field, "must be valid share participant hybrid encryption material"}]
      end
    end)
  end

  defp put_encryption_key_id(changeset) do
    case get_change(changeset, :hybrid_encryption_public_key_material) do
      material when is_map(material) ->
        put_change(
          changeset,
          :encryption_key_id,
          HybridEncryptionMaterial.compute_key_id!(material)
        )

      _ ->
        changeset
    end
  rescue
    ArgumentError -> changeset
  end
end
