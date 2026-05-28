defmodule RefMD.Repo.Migrations.AddPluginBundleApprovalAuthorityKeyDirectoryEvidence do
  use Ecto.Migration

  def change do
    alter table(:plugin_bundles) do
      add :approval_authority_event_head_sequence, :integer
      add :approval_authority_event_head_hash, :text
      add :approval_authority_checkpoint_sequence, :integer
      add :approval_authority_checkpoint_hash, :text
    end

    alter table(:plugin_bundles) do
      remove_if_exists :approval_authority_role, :text
    end
  end
end
