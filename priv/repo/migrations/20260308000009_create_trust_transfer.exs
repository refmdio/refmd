defmodule RefMD.Repo.Migrations.CreateTrustTransfer do
  use Ecto.Migration

  def change do
    create table(:trust_transfer_nonces, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :device_id, :binary_id, null: false
      add :nonce, :binary, null: false
      add :expires_at, :utc_datetime_usec, null: false
      add :created_at, :utc_datetime_usec, null: false
    end

    create unique_index(:trust_transfer_nonces, [:user_id, :device_id])

    create table(:trust_transfer_states, primary_key: false) do
      add :device_id, :binary_id, primary_key: true

      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false

      add :sender_device_id, references(:devices, type: :binary_id, on_delete: :delete_all),
        null: false

      add :ciphertext, :binary, null: false
      add :nonce, :binary, null: false
      add :signature, :binary, null: false
      add :created_at, :utc_datetime_usec, null: false
    end
  end
end
