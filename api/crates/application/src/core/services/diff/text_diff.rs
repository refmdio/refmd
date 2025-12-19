use similar::{Algorithm, ChangeTag, TextDiff};

use crate::core::dtos::{TextDiffLine, TextDiffLineType, TextDiffResult};

pub fn compute_text_diff(old: &str, new: &str, file_path: &str) -> TextDiffResult {
    let diff = TextDiff::configure()
        .algorithm(Algorithm::Myers)
        .diff_lines(old, new);
    let mut diff_lines = Vec::new();
    let mut old_line = 0u32;
    let mut new_line = 0u32;
    for op in diff.ops() {
        for change in diff.iter_changes(op) {
            match change.tag() {
                ChangeTag::Delete => {
                    old_line += 1;
                    diff_lines.push(TextDiffLine {
                        line_type: TextDiffLineType::Deleted,
                        old_line_number: Some(old_line),
                        new_line_number: None,
                        content: change.to_string().trim_end().to_string(),
                    });
                }
                ChangeTag::Insert => {
                    new_line += 1;
                    diff_lines.push(TextDiffLine {
                        line_type: TextDiffLineType::Added,
                        old_line_number: None,
                        new_line_number: Some(new_line),
                        content: change.to_string().trim_end().to_string(),
                    });
                }
                ChangeTag::Equal => {
                    old_line += 1;
                    new_line += 1;
                    diff_lines.push(TextDiffLine {
                        line_type: TextDiffLineType::Context,
                        old_line_number: Some(old_line),
                        new_line_number: Some(new_line),
                        content: change.to_string().trim_end().to_string(),
                    });
                }
            }
        }
    }

    TextDiffResult {
        file_path: file_path.to_string(),
        diff_lines,
        old_content: Some(old.to_string()),
        new_content: Some(new.to_string()),
    }
}
