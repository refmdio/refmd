use crate::application::ports::gitignore_port::GitignorePort;

pub struct FsGitignorePort;

#[async_trait::async_trait]
impl GitignorePort for FsGitignorePort {
    async fn ensure_gitignore(&self, dir: &str) -> anyhow::Result<bool> {
        use tokio::io::AsyncWriteExt;
        let path = std::path::Path::new(dir).join(".gitignore");
        let defaults = vec![
            "# RefMD auto-generated .gitignore",
            "*.md.tmp",
            ".DS_Store",
            "Thumbs.db",
            ".env",
            ".env.local",
        ];
        let mut created_or_updated = false;
        if tokio::fs::try_exists(&path).await.unwrap_or(false) {
            let existing = tokio::fs::read_to_string(&path).await.unwrap_or_default();
            let mut lines: std::collections::BTreeSet<String> =
                existing.lines().map(|s| s.to_string()).collect();
            let mut changed = false;
            for d in &defaults {
                if !lines.contains(&d.to_string()) {
                    lines.insert(d.to_string());
                    changed = true;
                }
            }
            if changed {
                let mut buf = String::new();
                for l in lines {
                    buf.push_str(&l);
                    buf.push('\n');
                }
                let mut f = tokio::fs::File::create(&path).await?;
                f.write_all(buf.as_bytes()).await?;
                created_or_updated = true;
            }
        } else {
            let mut f = tokio::fs::File::create(&path).await?;
            for d in &defaults {
                f.write_all(d.as_bytes()).await?;
                f.write_all(b"\n").await?;
            }
            created_or_updated = true;
        }
        Ok(created_or_updated)
    }

    async fn upsert_gitignore_patterns(
        &self,
        dir: &str,
        patterns: &[String],
    ) -> anyhow::Result<usize> {
        use tokio::io::AsyncWriteExt;
        let path = std::path::Path::new(dir).join(".gitignore");
        let mut set: std::collections::BTreeSet<String> =
            if tokio::fs::try_exists(&path).await.unwrap_or(false) {
                tokio::fs::read_to_string(&path)
                    .await
                    .unwrap_or_default()
                    .lines()
                    .map(|s| s.to_string())
                    .collect()
            } else {
                Default::default()
            };
        let before = set.len();
        for p in patterns {
            if !p.trim().is_empty() {
                set.insert(p.trim().to_string());
            }
        }
        if set.len() != before {
            let mut buf = String::new();
            for l in &set {
                buf.push_str(l);
                buf.push('\n');
            }
            let mut f = tokio::fs::File::create(&path).await?;
            f.write_all(buf.as_bytes()).await?;
            return Ok(set.len() - before);
        }
        Ok(0)
    }

    async fn read_gitignore_patterns(&self, dir: &str) -> anyhow::Result<Vec<String>> {
        let path = std::path::Path::new(dir).join(".gitignore");
        let content = if tokio::fs::try_exists(&path).await.unwrap_or(false) {
            tokio::fs::read_to_string(&path).await.unwrap_or_default()
        } else {
            String::new()
        };
        let patterns: Vec<String> = content
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect();
        Ok(patterns)
    }
}
