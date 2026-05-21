defmodule RefMD.Documents.DocumentSnapshotArchive do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "document_snapshot_archives" do
    belongs_to :document, RefMD.Documents.Document
    belongs_to :snapshot, RefMD.Documents.DocumentSnapshot
    belongs_to :created_by_user, RefMD.Users.User, foreign_key: :created_by

    field :label, :string
    field :notes, :string
    field :kind, :string
    field :created_at, :utc_datetime_usec
  end

  @type t :: %__MODULE__{}

  @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t()
  def changeset(archive, attrs) do
    archive
    |> cast(attrs, [:document_id, :snapshot_id, :label, :notes, :kind, :created_by])
    |> validate_required([:document_id, :snapshot_id, :label, :kind])
    |> validate_inclusion(:kind, ~w(manual auto))
  end
end
