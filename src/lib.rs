//! ChinaDNS-NG compatible forwarder.
//!
//! DNS messages are parsed and built with Hickory (`hickory-proto`). Domain
//! lists, the tag:none china-IP test, and nft set updates follow the subset
//! of chinadns-ng that PassWall generates.

mod config;
mod dns;
mod domains;
mod ipset;
mod resolve;
mod server;
mod upstream;

pub use config::{Config, Error};
pub use ipset::{Interval4, Interval6, MemoryAdds, NftSet};
pub use resolve::App;
pub use server::{Server, query_udp};

use std::sync::Arc;

pub async fn cli() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let mut config_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!(
                    "hickory-chinadns {version}\n\nusage: hickory-chinadns -C <config>\n\nReads a chinadns-ng config, answers DNS with Hickory messages,\nand writes result addresses into the configured nft sets.",
                    version = env!("CARGO_PKG_VERSION")
                );
                return Ok(());
            }
            "-V" | "--version" => {
                println!("hickory-chinadns {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "-C" | "--config" => {
                config_path = Some(args.next().ok_or_else(|| Error::msg("-C needs a path"))?);
            }
            other if other.starts_with('-') => {
                return Err(Error::msg(format!("unknown argument {other}")));
            }
            other => return Err(Error::msg(format!("unexpected argument {other}"))),
        }
    }
    let path = config_path.ok_or_else(|| Error::msg("missing -C <config>"))?;
    let cfg = Config::from_file(std::path::Path::new(&path))?;
    init_tracing(cfg.verbose);
    let app = Arc::new(App::boot(cfg)?);
    let server = Server::bind(&app)?;
    tracing::info!(addr = %server.local, "listening");
    tokio::select! {
        res = server.run(app) => res,
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

fn init_tracing(verbose: bool) {
    use tracing_subscriber::EnvFilter;
    let filter = if verbose && std::env::var_os("RUST_LOG").is_none() {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
