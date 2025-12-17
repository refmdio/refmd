use uuid::Uuid;

pub fn generate_slug(name: &str) -> String {
    let mut slug = name
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' => c,
            _ => '-',
        })
        .collect::<String>();
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    let mut slug = slug
        .trim_matches('-')
        .chars()
        .take(40)
        .collect::<String>()
        .if_empty("workspace".to_string());
    let suffix = Uuid::new_v4().to_string();
    slug.push('-');
    slug.push_str(&suffix[..8]);
    slug
}

trait IfEmpty {
    fn if_empty(self, fallback: impl Into<String>) -> String;
}

impl IfEmpty for String {
    fn if_empty(self, fallback: impl Into<String>) -> String {
        if self.is_empty() {
            fallback.into()
        } else {
            self
        }
    }
}
