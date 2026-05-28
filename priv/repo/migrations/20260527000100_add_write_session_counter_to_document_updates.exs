defmodule RefMD.Repo.Migrations.AddWriteSessionCounterToDocumentUpdates do
  use Ecto.Migration

  def change do
    alter table(:document_updates) do
      add :write_session_counter, :bigint, null: false, default: 1
    end

    create constraint(:document_updates, :document_updates_write_session_counter_positive,
             check: "write_session_counter > 0"
           )

    create unique_index(:document_updates, [
             :admission_event_hash,
             :signing_key_id,
             :write_session_counter
           ])
  end
end
