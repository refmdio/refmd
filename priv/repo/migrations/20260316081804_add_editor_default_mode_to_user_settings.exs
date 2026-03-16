defmodule RefMD.Repo.Migrations.AddEditorDefaultModeToUserSettings do
  use Ecto.Migration

  def change do
    alter table(:user_settings) do
      add :editor_default_mode, :string, default: "split", null: false
    end
  end
end
