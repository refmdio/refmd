#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DocumentDownloadFormat {
    Archive,
    Markdown,
    Html,
    Html5,
    Pdf,
    Docx,
    Latex,
    Beamer,
    Context,
    Man,
    MediaWiki,
    Dokuwiki,
    Textile,
    Org,
    Texinfo,
    Opml,
    Docbook,
    OpenDocument,
    Odt,
    Rtf,
    Epub,
    Epub3,
    Fb2,
    Asciidoc,
    Icml,
    Slidy,
    Slideous,
    Dzslides,
    Revealjs,
    S5,
    Json,
    Plain,
    Commonmark,
    CommonmarkX,
    MarkdownStrict,
    MarkdownPhpextra,
    MarkdownGithub,
    Rst,
    Native,
    Haddock,
}

impl DocumentDownloadFormat {
    pub fn extension(&self) -> &'static str {
        use DocumentDownloadFormat::*;
        match self {
            Archive => "zip",
            Markdown => "md",
            Html | Html5 => "html",
            Pdf => "pdf",
            Docx => "docx",
            Latex | Beamer | Context => "tex",
            Man => "man",
            MediaWiki => "mediawiki",
            Dokuwiki => "txt",
            Textile => "textile",
            Org => "org",
            Texinfo => "texi",
            Opml => "opml",
            Docbook => "xml",
            OpenDocument => "fodt",
            Odt => "odt",
            Rtf => "rtf",
            Epub | Epub3 => "epub",
            Fb2 => "fb2",
            Asciidoc => "adoc",
            Icml => "icml",
            Slidy | Slideous | Dzslides | Revealjs | S5 => "html",
            Json => "json",
            Plain => "txt",
            Commonmark | CommonmarkX | MarkdownStrict | MarkdownPhpextra | MarkdownGithub => "md",
            Rst => "rst",
            Native => "hs",
            Haddock => "txt",
        }
    }

    pub fn content_type(&self) -> &'static str {
        use DocumentDownloadFormat::*;
        match self {
            Archive => "application/zip",
            Markdown | Commonmark | CommonmarkX | MarkdownStrict | MarkdownPhpextra
            | MarkdownGithub => "text/markdown; charset=utf-8",
            Html | Html5 | Slidy | Slideous | Dzslides | Revealjs | S5 => {
                "text/html; charset=utf-8"
            }
            Pdf => "application/pdf",
            Docx => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            Latex | Beamer | Context => "application/x-tex",
            Man => "text/troff",
            MediaWiki | Dokuwiki | Textile | Org | Texinfo | Plain | Rst | Native | Haddock => {
                "text/plain; charset=utf-8"
            }
            Opml | Docbook => "application/xml",
            OpenDocument | Odt => "application/vnd.oasis.opendocument.text",
            Rtf => "application/rtf",
            Epub | Epub3 => "application/epub+zip",
            Fb2 => "application/x-fictionbook+xml",
            Asciidoc => "text/plain; charset=utf-8",
            Icml => "application/vnd.adobe.indesign-icml",
            Json => "application/json",
        }
    }

    pub fn file_name(&self, base: &str) -> String {
        format!("{}.{}", base, self.extension())
    }
}

pub struct DocumentDownload {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}
