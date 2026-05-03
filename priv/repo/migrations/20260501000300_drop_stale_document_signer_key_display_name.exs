defmodule RefMD.Repo.Migrations.DropStaleDocumentSignerKeyDisplayName do
  use Ecto.Migration

  def up do
    alter table(:document_signer_keys) do
      remove_if_exists :display_name, :text
    end
  end

  def down do
    alter table(:document_signer_keys) do
      add :display_name, :text
    end
  end
end
