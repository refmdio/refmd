defmodule RefMD.Repo.Migrations.ReplaceInitialAkePrekeyFreshness do
  use Ecto.Migration

  def change do
    alter table(:sessions) do
      add :pending_registration_prekey_issued_at_ms, :bigint
      add :pending_registration_prekey_expires_at_ms, :bigint
    end

    execute("DELETE FROM initial_ake_prekeys", "SELECT 1")

    alter table(:initial_ake_prekeys) do
      remove :issued_at_event_sequence, :bigint
      remove :expires_event_sequence, :bigint
      add :issued_at_ms, :bigint, null: false
      add :expires_at_ms, :bigint, null: false
    end

    create table(:initial_ake_prekey_clock_watermarks, primary_key: false) do
      add :purpose, :string, primary_key: true
      add :watermark_ms, :bigint, null: false
      timestamps(type: :utc_datetime_usec)
    end

    create constraint(:initial_ake_prekeys, :initial_ake_prekeys_exact_lifetime,
             check: "expires_at_ms = issued_at_ms + 300000"
           )

    create constraint(
             :initial_ake_prekey_clock_watermarks,
             :initial_ake_prekey_clock_watermarks_nonnegative,
             check: "watermark_ms >= 0"
           )
  end
end
