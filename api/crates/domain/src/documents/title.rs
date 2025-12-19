use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Title(String);

impl Title {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub fn from_user_input(raw: &str) -> Self {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            Self("Untitled".to_string())
        } else {
            Self(trimmed.to_string())
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Title {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn duplicate_title(source_title: &Title, override_title: Option<String>) -> Title {
    if let Some(custom) = override_title {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return Title::new(trimmed.to_string());
        }
    }
    let base = source_title.as_str().trim();
    let fallback = if base.is_empty() { "Untitled" } else { base };
    Title::new(format!("{fallback} (Copy)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_user_input_trims_and_falls_back() {
        assert_eq!(Title::from_user_input("  Hello ").as_str(), "Hello");
        assert_eq!(Title::from_user_input("   ").as_str(), "Untitled");
    }

    #[test]
    fn uses_override_when_present() {
        assert_eq!(
            duplicate_title(&Title::new("src"), Some("Custom".into())).as_str(),
            "Custom"
        );
    }

    #[test]
    fn falls_back_to_source_with_suffix() {
        assert_eq!(
            duplicate_title(&Title::new("Doc"), None).as_str(),
            "Doc (Copy)"
        );
    }

    #[test]
    fn empty_source_uses_untitled() {
        assert_eq!(
            duplicate_title(&Title::new(""), None).as_str(),
            "Untitled (Copy)"
        );
    }

    #[test]
    fn empty_override_ignored() {
        assert_eq!(
            duplicate_title(&Title::new("Doc"), Some("   ".into())).as_str(),
            "Doc (Copy)"
        );
    }
}
