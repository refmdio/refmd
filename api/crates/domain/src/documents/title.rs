pub fn duplicate_title(source_title: &str, override_title: Option<String>) -> String {
    if let Some(custom) = override_title {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    let base = source_title.trim();
    let fallback = if base.is_empty() { "Untitled" } else { base };
    format!("{fallback} (Copy)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_override_when_present() {
        assert_eq!(duplicate_title("src", Some("Custom".into())), "Custom");
    }

    #[test]
    fn falls_back_to_source_with_suffix() {
        assert_eq!(duplicate_title("Doc", None), "Doc (Copy)");
    }

    #[test]
    fn empty_source_uses_untitled() {
        assert_eq!(duplicate_title("", None), "Untitled (Copy)");
    }

    #[test]
    fn empty_override_ignored() {
        assert_eq!(duplicate_title("Doc", Some("   ".into())), "Doc (Copy)");
    }
}
