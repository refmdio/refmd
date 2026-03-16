defmodule RefMD.Repo.Migrations.AddEditorLayoutModeToUserSettings do
  use Ecto.Migration

  def up do
    execute "ALTER TABLE user_settings DROP COLUMN IF EXISTS editor_split_direction"

    alter table(:user_settings) do
      add :editor_layout_mode, :string, default: "tiling", null: false
    end
  end

  def down do
    alter table(:user_settings) do
      remove :editor_layout_mode
    end
  end
end
