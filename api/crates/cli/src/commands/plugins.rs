use anyhow::Result;

use crate::cli::PluginCommand;
use crate::deps::Deps;

pub(crate) async fn handle(deps: &Deps, cmd: PluginCommand) -> Result<()> {
    match cmd {
        PluginCommand::ListGlobal => {
            let manifests = deps.plugin_assets.list_latest_global_manifests().await?;
            println!("{} global plugin(s)", manifests.len());
            for item in manifests {
                println!(
                    "{}@{} manifest={}",
                    item.plugin_id,
                    item.version,
                    serde_json::to_string(&item.manifest)?
                );
            }
            Ok(())
        }
        PluginCommand::UserManifest {
            user_id,
            plugin_id,
            version,
        } => {
            match deps
                .plugin_assets
                .load_user_manifest(&user_id, &plugin_id, &version)
                .await?
            {
                Some(manifest) => {
                    println!(
                        "manifest for {} user {}:\n{}",
                        plugin_id,
                        user_id,
                        serde_json::to_string_pretty(&manifest)?
                    );
                }
                None => println!(
                    "manifest not found for plugin={} user={} version={}",
                    plugin_id, user_id, version
                ),
            }
            Ok(())
        }
        PluginCommand::RemoveUserDir { user_id, plugin_id } => {
            deps.plugin_assets
                .remove_user_plugin_dir(&user_id, &plugin_id)
                .await?;
            println!(
                "removed plugin data for user {} plugin {}",
                user_id, plugin_id
            );
            Ok(())
        }
    }
}
