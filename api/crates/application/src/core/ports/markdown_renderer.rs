use std::collections::HashSet;

use crate::core::ports::errors::PortResult;
use crate::core::services::markdown::{RenderOptions, RenderResponse};

pub trait MarkdownRenderer: Send + Sync {
    fn render(
        &self,
        text: String,
        opts: RenderOptions,
        placeholder_kinds: Option<&HashSet<String>>,
    ) -> PortResult<RenderResponse>;
}
