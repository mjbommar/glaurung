//! Data directory parsers

pub mod debug;
pub mod export;
pub mod import;
pub mod resource;
pub mod tls;

pub use debug::{parse_debug_directory, CodeViewRsds, DebugDirectory};
pub use export::{parse_exports, ExportTable};
pub use import::{parse_imports, ImportTable};
pub use resource::parse_resources;
pub use tls::{parse_tls, TlsDirectory};
