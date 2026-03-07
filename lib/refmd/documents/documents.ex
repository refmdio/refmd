defmodule RefMD.Documents do
  @moduledoc """
  The Documents context. Manages documents, updates, snapshots, and archives.
  """

  import Ecto.Query
  alias RefMD.Repo

  alias RefMD.Documents.{
    Document,
    DocumentUpdate,
    DocumentSnapshot,
    DocumentSnapshotArchive
  }
end
