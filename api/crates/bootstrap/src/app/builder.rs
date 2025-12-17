use dotenvy::dotenv;

use crate::{app, telemetry};

pub struct AppBuilder {
    cfg: crate::config::Config,
    spawn_background_tasks: bool,
}

impl AppBuilder {
    pub fn from_env() -> anyhow::Result<Self> {
        dotenv().ok();

        telemetry::init_tracing();

        let cfg = crate::config::Config::from_env()?;
        Ok(Self {
            cfg,
            spawn_background_tasks: true,
        })
    }

    pub fn new(cfg: crate::config::Config) -> Self {
        Self {
            cfg,
            spawn_background_tasks: true,
        }
    }

    /// Enable or disable background tasks (useful for CLI/tests).
    pub fn with_background_tasks(mut self, enabled: bool) -> Self {
        self.spawn_background_tasks = enabled;
        self
    }

    pub async fn build(self) -> anyhow::Result<app::AppRuntime> {
        app::build_runtime(self.cfg, self.spawn_background_tasks).await
    }
}
