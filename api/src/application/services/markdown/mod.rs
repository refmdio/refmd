use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
#[serde(default)]
pub struct RenderOptions {
    pub flavor: Option<String>,
    pub theme: Option<String>,
    pub features: Option<Vec<String>>, // e.g., ["gfm","mermaid","highlight"]
    pub sanitize: Option<bool>,
    /// If provided, rewrite attachment-relative links/images to absolute under /uploads/{doc_id}
    pub doc_id: Option<uuid::Uuid>,
    /// If provided, prefix absolute URLs with this origin (e.g., https://api.example.com)
    pub base_origin: Option<String>,
    /// If true, rewrite attachment URLs (./attachments/, attachments/, /uploads/)
    pub absolute_attachments: Option<bool>,
    /// Optional share token to append as query (?token=...)
    pub token: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PlaceholderItem {
    pub kind: String, // e.g., "mermaid" | "math"
    pub id: String,
    pub code: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct RenderResponse {
    pub html: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub placeholders: Vec<PlaceholderItem>,
    pub hash: String,
}

fn wants_feature(opts: &RenderOptions, name: &str) -> bool {
    if let Some(v) = &opts.features {
        return v.iter().any(|s| s.eq_ignore_ascii_case(name));
    }

    match name {
        "gfm" => !matches!(
            opts.flavor.as_deref(),
            Some(flavor) if flavor.eq_ignore_ascii_case("commonmark")
        ),
        _ => false,
    }
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let out = hasher.finalize();
    format!("{:x}", out)
}

fn normalize_wikilink_label(raw: &str) -> (String, bool) {
    let mut label = raw.trim().to_string();
    if label.is_empty() {
        return (label, false);
    }
    let mut inline = false;
    let mut lower = label.to_lowercase();
    if let Some(pos) = lower.rfind("|inline") {
        if lower[pos..].trim() == "|inline" {
            label = label[..pos].trim_end().to_string();
            inline = true;
            lower = label.to_lowercase();
        }
    }
    if label.starts_with('#') {
        label = label.trim_start_matches('#').to_string();
        lower = label.to_lowercase();
    }
    if lower.starts_with("wiki:") {
        label = label["wiki:".len()..].trim().to_string();
    }
    (label.trim().to_string(), inline)
}

pub fn render(text: String, opts: RenderOptions) -> anyhow::Result<RenderResponse> {
    // Build comrak options (GFM-like)
    let mut c_opts = comrak::ComrakOptions::default();
    c_opts.parse.smart = false;
    if wants_feature(&opts, "gfm") {
        c_opts.extension.table = true;
        c_opts.extension.autolink = true;
        c_opts.extension.strikethrough = true;
        c_opts.extension.tasklist = true;
        c_opts.extension.superscript = false;
        c_opts.extension.tagfilter = false;
        c_opts.render.github_pre_lang = true;
    }
    // Provide data-sourcepos for editor<->preview sync
    c_opts.render.sourcepos = true;
    // Allow HtmlBlock/HtmlInline to pass through; will be sanitized by ammonia afterwards
    c_opts.render.unsafe_ = true;

    // Parse AST
    use comrak::nodes::AstNode;
    let arena = comrak::Arena::new();
    let root = comrak::parse_document(&arena, &text, &c_opts);

    // Transform: capture code fences like ```mermaid, highlight code blocks, and inline tag links
    let mut placeholders: Vec<PlaceholderItem> = Vec::new();
    let mut counter: usize = 0;

    fn process_text_node<'a>(
        arena: &'a comrak::Arena<comrak::nodes::AstNode<'a>>,
        node: &'a AstNode<'a>,
    ) {
        use comrak::nodes::{Ast, LineColumn, NodeValue};
        let value = node.data.borrow().value.clone();
        if let NodeValue::Text(t) = value {
            // t: String
            let s = t.as_str();
            if !s.contains('#') && !s.contains("[[") {
                return;
            }
            let mut i = 0usize;
            while i < s.len() {
                // Find next token start: '#' or '[[ '
                let next_hash = s[i..].find('#').map(|off| i + off).unwrap_or(s.len());
                let next_wiki = s[i..].find("[[").map(|off| i + off).unwrap_or(s.len());
                let j = std::cmp::min(next_hash, next_wiki);

                // Emit plain segment before token
                if j > i {
                    let pre = &s[i..j];
                    if !pre.is_empty() {
                        let ast = Ast::new(
                            NodeValue::Text(pre.to_string()),
                            LineColumn { line: 1, column: 1 },
                        );
                        let n =
                            arena.alloc(comrak::nodes::AstNode::new(std::cell::RefCell::new(ast)));
                        node.insert_before(n);
                    }
                }
                if j >= s.len() {
                    break;
                }

                if s[j..].starts_with("[[") {
                    // Bracket wiki: [[target]] or [[target|alias]] (alias may include |inline suffix)
                    let after = &s[j + 2..];
                    if let Some(end_rel) = after.find("]]") {
                        let inside = &after[..end_rel];
                        let mut parts = inside.splitn(2, '|');
                        let target = parts.next().unwrap_or("").trim();
                        let label = parts.next().map(|x| x.trim()).unwrap_or(target);
                        if !target.is_empty() {
                            use comrak::nodes::NodeLink;
                            let link_node = arena.alloc(comrak::nodes::AstNode::new(
                                std::cell::RefCell::new(Ast::new(
                                    NodeValue::Link(NodeLink {
                                        url: format!("#wiki:{}", target),
                                        title: String::new(),
                                    }),
                                    LineColumn { line: 1, column: 1 },
                                )),
                            ));
                            let text_node = arena.alloc(comrak::nodes::AstNode::new(
                                std::cell::RefCell::new(Ast::new(
                                    NodeValue::Text(label.to_string()),
                                    LineColumn { line: 1, column: 1 },
                                )),
                            ));
                            link_node.append(text_node);
                            node.insert_before(link_node);
                        } else {
                            // If target empty, just output raw literal [[...]]
                            let ast = Ast::new(
                                NodeValue::Text(format!("[[{}]]", inside)),
                                LineColumn { line: 1, column: 1 },
                            );
                            let n = arena
                                .alloc(comrak::nodes::AstNode::new(std::cell::RefCell::new(ast)));
                            node.insert_before(n);
                        }
                        i = j + 2 + end_rel + 2; // move past closing ]]
                        continue;
                    } else {
                        // No closing ]], emit the rest as literal and stop
                        let ast = Ast::new(
                            NodeValue::Text(s[j..].to_string()),
                            LineColumn { line: 1, column: 1 },
                        );
                        let n =
                            arena.alloc(comrak::nodes::AstNode::new(std::cell::RefCell::new(ast)));
                        node.insert_before(n);
                        break;
                    }
                } else {
                    // Hashtags and directives starting with '#'
                    let start = j; // position of '#'
                    let rest = &s[start + 1..];
                    let mut kind = "tag";
                    let mut k = start + 1;

                    if rest.starts_with("wiki:") {
                        kind = "wiki";
                        k += 5;
                        while k < s.len() {
                            let ch = s[k..].chars().next().unwrap();
                            if ch.is_ascii_alphanumeric() || matches!(ch, ':' | '-' | '/' | '_') {
                                k += ch.len_utf8();
                            } else {
                                break;
                            }
                        }
                    } else if rest.starts_with("mention:") {
                        kind = "mention";
                        k += 8;
                        while k < s.len() {
                            let ch = s[k..].chars().next().unwrap();
                            if ch.is_ascii_alphanumeric()
                                || matches!(ch, '-' | '_' | ':' | '@' | '.')
                            {
                                k += ch.len_utf8();
                            } else {
                                break;
                            }
                        }
                    } else {
                        // normal tag [A-Za-z0-9_]{1,50}
                        let mut count = 0;
                        while k < s.len() {
                            let ch = s[k..].chars().next().unwrap();
                            if ch.is_ascii_alphanumeric() || ch == '_' {
                                count += 1;
                                k += ch.len_utf8();
                                if count >= 50 {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        if count == 0 {
                            // not a tag, emit '#'
                            let ast = Ast::new(
                                NodeValue::Text("#".to_string()),
                                LineColumn { line: 1, column: 1 },
                            );
                            let n = arena
                                .alloc(comrak::nodes::AstNode::new(std::cell::RefCell::new(ast)));
                            node.insert_before(n);
                            i = start + 1;
                            continue;
                        }
                    }

                    let body = &s[start + 1..k];
                    let (href, class_name, extra_attr) = match kind {
                        "wiki" => (
                            format!("#{}", body),
                            "wikilink",
                            Some(("data-wiki-target", body.to_string())),
                        ),
                        "mention" => (
                            format!("#{}", body),
                            "mention",
                            Some(("data-mention-target", body.to_string())),
                        ),
                        _ => (format!("#tag-{}", body), "hashtag", None),
                    };
                    let text = format!("#{}", body);
                    let html = if kind == "wiki" {
                        let (display_label, is_inline) = normalize_wikilink_label(&text);
                        let variant = if is_inline { "inline" } else { "embed" };
                        format!(
                            "<refmd-wikilink class=\"{}\" target=\"{}\" href=\"{}\" variant=\"{}\">{}</refmd-wikilink>",
                            class_name,
                            htmlescape::encode_minimal(body),
                            htmlescape::encode_minimal(&href),
                            variant,
                            htmlescape::encode_minimal(&display_label)
                        )
                    } else if let Some((k, v)) = extra_attr {
                        format!(
                            "<a href=\"{}\" class=\"{}\" {}=\"{}\">{}</a>",
                            htmlescape::encode_minimal(&href),
                            class_name,
                            k,
                            htmlescape::encode_minimal(&v),
                            htmlescape::encode_minimal(&text)
                        )
                    } else {
                        format!(
                            "<a href=\"{}\" class=\"{}\">{}</a>",
                            htmlescape::encode_minimal(&href),
                            class_name,
                            htmlescape::encode_minimal(&text)
                        )
                    };
                    let ast_html = Ast::new(
                        NodeValue::HtmlInline(html),
                        LineColumn { line: 1, column: 1 },
                    );
                    let hnode = arena.alloc(comrak::nodes::AstNode::new(std::cell::RefCell::new(
                        ast_html,
                    )));
                    node.insert_before(hnode);
                    i = k;
                }
            }
            node.detach();
        }
    }

    fn walk<'a>(
        arena: &'a comrak::Arena<comrak::nodes::AstNode<'a>>,
        node: &'a AstNode<'a>,
        placeholders: &mut Vec<PlaceholderItem>,
        counter: &mut usize,
        enable_highlight: bool,
        theme_name: &str,
        opts: &RenderOptions,
    ) {
        use comrak::nodes::NodeValue;
        fn is_attachment_url(url: &str) -> bool {
            url.starts_with("./attachments/") || url.starts_with("attachments/")
        }
        fn starts_uploads(url: &str) -> bool {
            url.starts_with("/api/uploads/")
        }
        fn rewrite_attachment_url(url: &str, opts: &RenderOptions) -> Option<String> {
            let enabled = opts.absolute_attachments.unwrap_or(false);
            let doc_id = opts.doc_id?;
            if !enabled {
                return None;
            }
            let token = opts.token.as_deref();
            let prefix = opts.base_origin.as_deref().unwrap_or("");
            let mut path = if url.starts_with("./attachments/") {
                format!("/api/uploads/{}/{}", doc_id, &url.trim_start_matches("./"))
            } else if url.starts_with("attachments/") {
                format!("/api/uploads/{}/{}", doc_id, url)
            } else if url.starts_with("/api/uploads/") {
                url.to_string()
            } else {
                return None;
            };
            if let Some(tok) = token {
                if !tok.is_empty() {
                    if path.contains('?') {
                        path.push_str(&format!("&token={}", urlencoding::encode(tok)))
                    } else {
                        path.push_str(&format!("?token={}", urlencoding::encode(tok)))
                    }
                }
            }
            if prefix.is_empty() {
                Some(path)
            } else {
                Some(format!("{}{}", prefix.trim_end_matches('/'), path))
            }
        }
        fn collect_plain_text<'a>(n: &'a AstNode<'a>) -> String {
            use comrak::nodes::NodeValue;
            let mut out = String::new();
            for ch in n.children() {
                match &ch.data.borrow().value {
                    NodeValue::Text(t) => out.push_str(t),
                    NodeValue::Code(code) => out.push_str(&code.literal),
                    NodeValue::SoftBreak | NodeValue::LineBreak => out.push(' '),
                    _ => {
                        out.push_str(&collect_plain_text(ch));
                    }
                }
            }
            out
        }
        for child in node.children() {
            // Recurse first for inner nodes
            walk(
                arena,
                child,
                placeholders,
                counter,
                enable_highlight,
                theme_name,
                opts,
            );

            // Prepare replacement outside the borrow scope to avoid RefCell double-borrows
            let mut replace_with: Option<String> = None;
            let mut is_code_block = false;
            let mut is_link_inline = false;
            {
                if let NodeValue::CodeBlock(ref cb) = child.data.borrow().value {
                    is_code_block = true;
                    let info = cb.info.trim().to_string();
                    let lang = info.split(|c: char| c.is_whitespace()).next().unwrap_or("");
                    if lang.eq_ignore_ascii_case("mermaid") {
                        *counter += 1;
                        let id = format!("m{}", counter);
                        let code = cb.literal.clone();
                        placeholders.push(PlaceholderItem {
                            kind: "mermaid".into(),
                            id: id.clone(),
                            code,
                        });
                        let html = format!("<div data-mermaid=\"{}\"></div>", id);
                        replace_with = Some(html);
                    } else if enable_highlight {
                        let code = cb.literal.clone();
                        let html = highlight_codeblock(&code, lang, theme_name);
                        replace_with = Some(html);
                    }
                } else if let NodeValue::Link(ref ln) = child.data.borrow().value {
                    let url = ln.url.clone();
                    if is_attachment_url(&url) || starts_uploads(&url) {
                        is_link_inline = true;
                        let label = {
                            let txt = collect_plain_text(child).trim().to_string();
                            if !txt.is_empty() {
                                txt
                            } else {
                                url.split('/').last().unwrap_or(&url).to_string()
                            }
                        };
                        let new_url = rewrite_attachment_url(&url, opts).unwrap_or(url.clone());
                        let html = format!(
                            "<a href=\"{}\" class=\"file-attachment\">{}</a>",
                            htmlescape::encode_minimal(&new_url),
                            htmlescape::encode_minimal(&label)
                        );
                        replace_with = Some(html);
                    } else if url.starts_with("#wiki:") {
                        is_link_inline = true;
                        let target = url.trim_start_matches("#wiki:");
                        let label = {
                            let txt = collect_plain_text(child).trim().to_string();
                            if !txt.is_empty() {
                                txt
                            } else {
                                format!("#wiki:{}", target)
                            }
                        };
                        let (display_label, is_inline) = normalize_wikilink_label(&label);
                        let variant = if is_inline { "inline" } else { "embed" };
                        let html = format!(
                            "<refmd-wikilink class=\"wikilink\" target=\"{}\" href=\"{}\" variant=\"{}\">{}</refmd-wikilink>",
                            htmlescape::encode_minimal(target),
                            htmlescape::encode_minimal(&url),
                            variant,
                            htmlescape::encode_minimal(&display_label)
                        );
                        replace_with = Some(html);
                    } else if url.starts_with("#mention:") {
                        is_link_inline = true;
                        let target = url.trim_start_matches("#mention:");
                        let label = {
                            let txt = collect_plain_text(child).trim().to_string();
                            if !txt.is_empty() {
                                txt
                            } else {
                                format!("#mention:{}", target)
                            }
                        };
                        let html = format!(
                            "<a href=\"{}\" class=\"mention\" data-mention-target=\"{}\">{}</a>",
                            htmlescape::encode_minimal(&url),
                            htmlescape::encode_minimal(target),
                            htmlescape::encode_minimal(&label)
                        );
                        replace_with = Some(html);
                    }
                } else if let NodeValue::Image(ref im) = child.data.borrow().value {
                    let url = im.url.clone();
                    if is_attachment_url(&url) || starts_uploads(&url) {
                        // Replace with absolute <img> HTML to avoid mutable borrow conflicts
                        let new_url = rewrite_attachment_url(&url, opts).unwrap_or(url.clone());
                        let alt = collect_plain_text(child);
                        let html = format!(
                            "<img src=\"{}\" alt=\"{}\" />",
                            htmlescape::encode_minimal(&new_url),
                            htmlescape::encode_minimal(&alt)
                        );
                        replace_with = Some(html);
                        // mark as inline image replacement by reusing is_link_inline flag path below
                        is_link_inline = true;
                    }
                }
            }
            if is_code_block {
                if let Some(html) = replace_with.take() {
                    child.data.borrow_mut().value =
                        NodeValue::HtmlBlock(comrak::nodes::NodeHtmlBlock {
                            block_type: 0,
                            literal: html,
                        });
                }
                continue;
            }
            if is_link_inline {
                if let Some(html) = replace_with.take() {
                    child.data.borrow_mut().value = NodeValue::HtmlInline(html);
                    // Remove original link text children to avoid duplicate text rendering
                    // (NodeValue::HtmlInline will render literal; children would render again otherwise)
                    while let Some(grand) = child.first_child() {
                        grand.detach();
                    }
                }
                continue;
            }

            if matches!(child.data.borrow().value, NodeValue::Text(_)) {
                // Hashtag / wiki / mention transform for inline text
                process_text_node(arena, child);
            }
        }
    }
    let enable_highlight = wants_feature(&opts, "highlight");
    // Theme defaults to Nord unless overridden
    let theme_name = opts
        .theme
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("Nord");
    walk(
        &arena,
        root,
        &mut placeholders,
        &mut counter,
        enable_highlight,
        theme_name,
        &opts,
    );

    // Render HTML
    let mut html = Vec::new();
    comrak::format_html(root, &c_opts, &mut html)?;
    let html = String::from_utf8(html)?;

    // Sanitize
    let mut builder = ammonia::Builder::default();
    // Allow common attributes + class, data-mermaid
    builder.add_generic_attributes([
        "class",
        "id",
        "title",
        "data-mermaid",
        "data-sourcepos",
        // for client hydration of custom components
        "data-wiki-target",
        "data-mention-target",
        "data-embed-target",
    ]);
    // Ensure code-related tags & attributes are kept (style allowed here for syntect inline CSS)
    builder.add_tags(["pre", "code", "span", "input"]);
    builder.add_tag_attributes("pre", ["class", "style"]);
    builder.add_tag_attributes("code", ["class", "style"]);
    builder.add_tag_attributes("span", ["class", "style"]);
    builder.add_tag_attributes("input", ["type", "checked", "disabled", "class"]);
    // Allow relative URLs (e.g., href="#wiki:…", ./attachments/…)
    builder.url_relative(ammonia::UrlRelative::PassThrough);
    // Ensure rel="noopener noreferrer" on target=_blank
    builder.link_rel(Some("noopener noreferrer"));
    let safe_html = if opts.sanitize.unwrap_or(true) {
        builder.clean(&html).to_string()
    } else {
        html
    };

    // Hash (of input + options canonicalized)
    let opts_repr = serde_json::to_string(&opts)?;
    let canon = format!("{}\n{}", text, opts_repr);
    let hash = sha256_hex(&canon);

    Ok(RenderResponse {
        html: safe_html,
        placeholders,
        hash,
    })
}

static HIGHLIGHT_ASSETS: Lazy<Mutex<syntect_assets::assets::HighlightingAssets>> =
    Lazy::new(|| Mutex::new(syntect_assets::assets::HighlightingAssets::from_binary()));

fn highlight_codeblock(code: &str, lang: &str, theme_name: &str) -> String {
    use syntect::html::highlighted_html_for_string;

    let assets = HIGHLIGHT_ASSETS
        .lock()
        .expect("highlight assets mutex poisoned");
    let ss = assets.get_syntax_set().unwrap();
    // Prefer requested theme; assets fall back internally when unavailable.
    let theme = assets.get_theme(theme_name);
    let syntax = ss
        .find_syntax_by_token(lang)
        .unwrap_or_else(|| ss.find_syntax_plain_text());
    let out = highlighted_html_for_string(code, ss, syntax, theme).unwrap_or_else(|_| {
        // Fallback to escaped pre/code
        let escaped = htmlescape::encode_minimal(code);
        format!(
            "<pre><code class=\"language-{}\">{}</code></pre>",
            lang, escaped
        )
    });
    format!("<div class=\"not-prose\">{}</div>", out)
}
