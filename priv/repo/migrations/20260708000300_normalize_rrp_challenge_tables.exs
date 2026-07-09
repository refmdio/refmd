defmodule RefMD.Repo.Migrations.NormalizeRrpChallengeTables do
  use Ecto.Migration

  def up do
    execute("ALTER TABLE IF EXISTS pop_challenges RENAME TO rrp_challenges")

    rename_matching_constraints("rrp_challenges", "pop_challenges", "rrp_challenges")
    rename_matching_indexes("rrp_challenges", "pop_challenges", "rrp_challenges")

    execute(
      "ALTER TABLE IF EXISTS share_participant_pop_challenges RENAME TO share_participant_rrp_challenges"
    )

    rename_matching_constraints(
      "share_participant_rrp_challenges",
      "share_participant_pop_challenges",
      "share_participant_rrp_challenges"
    )

    rename_matching_indexes(
      "share_participant_rrp_challenges",
      "share_participant_pop_challenges",
      "share_participant_rrp_challenges"
    )
  end

  def down, do: :ok

  defp rename_matching_constraints(table_name, old_prefix, new_prefix) do
    execute("""
    DO $$
    DECLARE
      constraint_name text;
      renamed_constraint_name text;
    BEGIN
      IF to_regclass('#{table_name}') IS NULL THEN
        RETURN;
      END IF;

      FOR constraint_name IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = to_regclass('#{table_name}')
          AND conname LIKE '#{old_prefix}%'
      LOOP
        renamed_constraint_name := regexp_replace(
          constraint_name,
          '^#{old_prefix}',
          '#{new_prefix}'
        );

        EXECUTE format(
          'ALTER TABLE %I RENAME CONSTRAINT %I TO %I',
          '#{table_name}',
          constraint_name,
          renamed_constraint_name
        );
      END LOOP;
    END $$;
    """)
  end

  defp rename_matching_indexes(table_name, old_prefix, new_prefix) do
    execute("""
    DO $$
    DECLARE
      index_name text;
      renamed_index_name text;
    BEGIN
      IF to_regclass('#{table_name}') IS NULL THEN
        RETURN;
      END IF;

      FOR index_name IN
        SELECT indexname
        FROM pg_indexes
        WHERE schemaname = current_schema()
          AND tablename = '#{table_name}'
          AND indexname LIKE '#{old_prefix}%'
      LOOP
        renamed_index_name := regexp_replace(index_name, '^#{old_prefix}', '#{new_prefix}');
        EXECUTE format('ALTER INDEX %I RENAME TO %I', index_name, renamed_index_name);
      END LOOP;
    END $$;
    """)
  end
end
