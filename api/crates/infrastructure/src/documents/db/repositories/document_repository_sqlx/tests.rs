use domain::documents::path as doc_path;

#[test]
fn slug_preserves_unicode_and_case() {
    assert_eq!(doc_path::Slug::from_title("Main").as_str(), "Main");
    assert_eq!(doc_path::Slug::from_title("Résumé2025").as_str(), "Résumé2025");
}

#[test]
fn slug_sanitizes_forbidden_chars() {
    assert_eq!(doc_path::Slug::from_title(" Foo / Bar ").as_str(), "Foo - Bar");
    assert_eq!(doc_path::Slug::from_title("////").as_str(), "untitled");
}

