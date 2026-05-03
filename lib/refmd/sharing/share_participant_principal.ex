defmodule RefMD.Sharing.ShareParticipantPrincipal do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "share_participant_principals" do
    belongs_to :share, RefMD.Sharing.Share

    field :display_name, :string

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: :updated_at)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(principal, attrs) do
    principal
    |> cast(attrs, [:share_id, :display_name])
    |> validate_required([:share_id, :display_name])
    |> validate_length(:display_name, min: 1, max: 120)
    |> foreign_key_constraint(:share_id)
  end
end
