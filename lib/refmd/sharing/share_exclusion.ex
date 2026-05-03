defmodule RefMD.Sharing.ShareExclusion do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @foreign_key_type :binary_id

  schema "share_exclusions" do
    belongs_to :share, RefMD.Sharing.Share, primary_key: true
    belongs_to :document, RefMD.Documents.Document, primary_key: true

    timestamps(type: :utc_datetime_usec, inserted_at: :created_at, updated_at: false)
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(exclusion, attrs) do
    exclusion
    |> cast(attrs, [:share_id, :document_id])
    |> validate_required([:share_id, :document_id])
    |> unique_constraint([:share_id, :document_id], name: :share_exclusions_pkey)
    |> foreign_key_constraint(:share_id)
    |> foreign_key_constraint(:document_id)
  end
end
