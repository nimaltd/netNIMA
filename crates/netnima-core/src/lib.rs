//! Everything in netNIMA that does not draw on the screen.
//!
//! Sockets, protocols, config and decoders live here, apart from the window,
//! so they can be tested on their own.

mod ansi;
pub mod certs;
pub mod lines;
pub mod logfile;
pub mod net;
pub mod proto;
pub mod record;
pub mod replay;
pub mod send;
pub mod settings;
mod tomlfile;
pub mod workspace;

/// The version of netNIMA, from the workspace's `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
