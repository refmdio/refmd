defmodule RefMD.Repo.Migrations.CreatePublicDocuments do
  use Ecto.Migration

  def change do
    create table(:public_author_profiles, primary_key: false) do
      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        primary_key: true,
        null: false

      add :slug, :string, null: false
      add :display_name, :string, null: false
      add :bio, :text

      timestamps(type: :utc_datetime_usec)
    end

    create unique_index(:public_author_profiles, [:slug])

    create table(:public_documents, primary_key: false) do
      add :document_id, references(:documents, type: :binary_id, on_delete: :delete_all),
        primary_key: true,
        null: false

      add :workspace_id, references(:workspaces, type: :binary_id, on_delete: :delete_all),
        null: false

      add :author_profile_id,
          references(:public_author_profiles,
            column: :workspace_id,
            type: :binary_id,
            on_delete: :delete_all
          ),
          null: false

      add :slug, :string, null: false
      add :title, :string, null: false
      add :content, :text, null: false
      add :content_hash, :string, null: false
      add :noindex, :boolean, null: false, default: false
      add :published_by, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :published_at, :utc_datetime_usec, null: false

      timestamps(type: :utc_datetime_usec, inserted_at: false)
    end

    create unique_index(:public_documents, [:author_profile_id, :slug])
    create index(:public_documents, [:workspace_id])
  end
end
