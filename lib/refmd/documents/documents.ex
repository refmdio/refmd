defmodule RefMD.Documents do
  @moduledoc """
  The Documents context. Manages documents, updates, snapshots, and archives.
  """

  import Ecto.Changeset
  alias RefMD.Documents.Document
  alias RefMD.Repo

  @spec create_document(map()) :: {:ok, Document.t()} | {:error, Ecto.Changeset.t()}
  def create_document(attrs) do
    %Document{}
    |> Document.changeset(attrs)
    |> validate_parent_constraints()
    |> Repo.insert()
  end

  @spec update_document(Document.t(), map()) :: {:ok, Document.t()} | {:error, Ecto.Changeset.t()}
  def update_document(%Document{} = document, attrs) do
    document
    |> Document.changeset(attrs)
    |> validate_parent_constraints()
    |> Repo.update()
  end

  @spec validate_parent_constraints(Ecto.Changeset.t()) :: Ecto.Changeset.t()
  def validate_parent_constraints(changeset) do
    parent_id = get_field(changeset, :parent_id)
    workspace_id = get_field(changeset, :workspace_id)

    if parent_id do
      case Repo.get(Document, parent_id) do
        nil ->
          add_error(changeset, :parent_id, "parent document not found")

        parent ->
          changeset
          |> validate_parent_is_folder(parent)
          |> validate_same_workspace(parent, workspace_id)
      end
    else
      changeset
    end
  end

  defp validate_parent_is_folder(changeset, parent) do
    if parent.doc_type == "folder" do
      changeset
    else
      add_error(changeset, :parent_id, "parent must be a folder")
    end
  end

  defp validate_same_workspace(changeset, parent, workspace_id) do
    if parent.workspace_id == workspace_id do
      changeset
    else
      add_error(changeset, :parent_id, "parent must be in the same workspace")
    end
  end
end
