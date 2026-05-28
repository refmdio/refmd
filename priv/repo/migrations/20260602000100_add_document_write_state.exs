defmodule RefMD.Repo.Migrations.AddDocumentWriteState do
  use Ecto.Migration

  def change do
    alter table(:documents) do
      add :write_state, :string, null: false, default: "writable"
    end

    create constraint(:documents, :documents_write_state_valid,
             check: "write_state IN ('writable', 'read_only', 'archived', 'write_disabled')"
           )

    execute(
      "UPDATE documents SET write_state = 'archived' WHERE archived_at IS NOT NULL",
      "UPDATE documents SET write_state = 'writable' WHERE write_state = 'archived'"
    )
  end
end
