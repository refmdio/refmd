defmodule RefMD.Repo.Migrations.AddRecoveryAuditCheckpoint do
  use Ecto.Migration

  def change do
    alter table(:sessions) do
      add :candidate_user_audit_sequence, :bigint
      add :candidate_user_audit_hash, :text
    end
  end
end
