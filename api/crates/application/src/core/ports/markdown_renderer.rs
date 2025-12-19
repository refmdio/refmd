use std::collections::HashSet;

use crate::core::dtos::markdown::{RenderOptions, RenderResponse};
use crate::core::ports::errors::PortResult;

pub trait MarkdownRenderer: Send + Sync {
    fn render(
        &self,
        text: String,
        opts: RenderOptions,
        placeholder_kinds: Option<&HashSet<String>>,
    ) -> PortResult<RenderResponse>;
}
