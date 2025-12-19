use std::collections::HashSet;

use crate::core::services::markdown::{RenderOptions, RenderResponse};

pub trait MarkdownRenderer: Send + Sync {
    fn render(
        &self,
        text: String,
        opts: RenderOptions,
        placeholder_kinds: Option<&HashSet<String>>,
    ) -> anyhow::Result<RenderResponse>;
}

