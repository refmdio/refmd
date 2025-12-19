use domain::documents::doc_type::DocumentType;
use domain::documents::title::Title;

include!("state/collect.rs");
include!("state/dirty.rs");
include!("state/export.rs");
include!("state/deltas.rs");
include!("state/snapshots.rs");
include!("state/apply.rs");
include!("state/diff.rs");
