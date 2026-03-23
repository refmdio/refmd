defmodule RefMD.Repo.Migrations.CreateEncryptionDocument do
  use Ecto.Migration

  def change do
    create table(:document_encrypted_keys, primary_key: false) do
      add :document_id,
          references(:documents, type: :binary_id, on_delete: :delete_all),
          primary_key: true

      add :key_version, :integer, primary_key: true
      add :encrypted_dek, :binary, null: false
      add :nonce, :binary, null: false
      add :kek_version, :integer, null: false
      add :is_active, :boolean, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    execute(
      "ALTER TABLE document_encrypted_keys ADD CONSTRAINT dek_nonce_size CHECK (octet_length(nonce) = 24)",
      "ALTER TABLE document_encrypted_keys DROP CONSTRAINT dek_nonce_size"
    )

    execute(
      "ALTER TABLE document_encrypted_keys ADD CONSTRAINT dek_ciphertext_size CHECK (octet_length(encrypted_dek) = 48)",
      "ALTER TABLE document_encrypted_keys DROP CONSTRAINT dek_ciphertext_size"
    )

    execute(
      "ALTER TABLE document_encrypted_keys ADD CONSTRAINT dek_key_version_positive CHECK (key_version > 0)",
      "ALTER TABLE document_encrypted_keys DROP CONSTRAINT dek_key_version_positive"
    )

    execute(
      "ALTER TABLE document_encrypted_keys ADD CONSTRAINT dek_kek_version_positive CHECK (kek_version > 0)",
      "ALTER TABLE document_encrypted_keys DROP CONSTRAINT dek_kek_version_positive"
    )
  end
end
