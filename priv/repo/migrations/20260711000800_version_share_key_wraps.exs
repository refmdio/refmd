defmodule RefMD.Repo.Migrations.VersionShareKeyWraps do
  use Ecto.Migration

  def change do
    alter table(:share_keys) do
      add :key_version, :integer, null: false, default: 1
    end

    create constraint(:share_keys, :share_keys_key_version_positive, check: "key_version > 0")

    create table(:share_key_histories, primary_key: false) do
      add :share_id,
          references(:shares, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :key_version, :integer, primary_key: true

      add :document_id, references(:documents, type: :binary_id, on_delete: :delete_all),
        null: false

      add :encrypted_dek, :binary, null: false
      add :nonce, :binary, null: false
      timestamps(type: :utc_datetime_usec, inserted_at: :created_at)
    end

    create index(:share_key_histories, [:document_id, :key_version])

    create constraint(:share_key_histories, :share_key_histories_key_version_positive,
             check: "key_version > 0"
           )

    create constraint(:share_key_histories, :share_key_histories_nonce_size,
             check: "octet_length(nonce) = 24"
           )
  end
end
