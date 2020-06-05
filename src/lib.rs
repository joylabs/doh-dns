//! Library to make DNS over HTTPS requests.
//!
//! This DNS over HTTPS (DoH) library queries public DoH servers provided by Google and
//! Clouflare. It is based on `async/await` with the help of `hyper` and `tokio`.
//!
//! The library supports timeouts and retries which can be fully customized. A utility
//! is provided in this crate to use this library in the command line.
//!
//! # Quick Start
//!
//! To quickly get started, a default client can be created with `Dns:default` and
//! `A` records can be queried using [Dns::resolve_a]. The default resolvers use Google
//! first with a timeout of 3 seconds and Clouflare second with a timeout of 10 seconds.
//! *Note: Cloudlare does not support queries for `ANY` records. You can use the Google
//! resolver for that.
//!
//! # Example
//! ```
//! use doh_dns::{client::HyperDnsClient, Dns, DnsHttpsServer};
//! use std::time::Duration;
//! use tokio;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // The following sets up the main DoH server to be Google with a default timeout
//!     // of 2 seconds. If a retry is needed, the Cloudflare's 1.1.1.1 server is used.
//!     // Alternatively, use your custom server setup with:
//!     // let dns = Dns::with_servers(vec![DnsHttpsServer::new(
//!     //       "doh.opendns.com".to_string(),
//!     //       "dns-query".to_string(),
//!     //       vec!["208.67.222.222".parse().unwrap(), "208.67.220.220".parse().unwrap()],
//!     //       Duration::from_secs(10),
//!     // ));
//!     // Or use the default server setup with:
//!     // let dns = Dns::default();
//!     let dns: Dns<HyperDnsClient> = Dns::with_servers(vec![
//!         DnsHttpsServer::Google(Duration::from_secs(2)),
//!         DnsHttpsServer::Cloudflare(Duration::from_secs(10)),
//!     ])
//!     .unwrap();
//!     match dns.resolve_a("memo.com").await {
//!         Ok(responses) => {
//!             if responses.is_empty() {
//!                 println!("No entries found.");
//!             } else {
//!                 for res in responses {
//!                     println!(
//!                         "name: {}, type: {}, TTL: {}, data: {}",
//!                         res.name,
//!                         dns.rtype_to_name(res.r#type),
//!                         res.TTL,
//!                         res.data
//!                     );
//!                 }
//!             }
//!         }
//!         Err(err) => println!("Error: {}", err),
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Logging
//! This library uses the `log` crate to log errors during retries. Please see that create
//! on methods on display such errors. If no logger is setup, nothing will be logged.
#![feature(proc_macro_hygiene)]
#![feature(stmt_expr_attributes)]
pub mod client;
pub use client::DnsAnswer;
mod dns;
pub use dns::Dns;
pub mod error;
pub mod status;
#[macro_use]
extern crate serde_derive;
extern crate num;
#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate log;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

const GOOGLE: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
    IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)),
];

const CLOUDFLARE: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)),
];

/// The default list of DNS over HTTPS servers allowed to query with their respective timeouts.
/// These servers are given to [Dns::with_servers] in order of priority. Only subsequent
/// servers are used if the request needs to be retried.
#[derive(Clone)]
pub enum DnsHttpsServer {
    /// Googe's DoH server. Unfortunately, Google doesn't allow to query `8.8.8.8` or
    /// `8.8.4.4` directly. It needs the hostname `dns.google`. If this option is
    /// given, `8.8.8.8` and `8.8.4.4` will be used in round robin form for each new
    /// connection.
    Google(Duration),
    /// Cloudflare's DOH server. Cloudflare does not respond to `ANY` Dns
    /// requests so [Dns::resolve_any] will always return an error.
    Cloudflare(Duration),
    /// Custom DOH server configuration with URI, static IPs and timeout.
    Custom {
        domain: String,
        path: String,
        addr: Vec<IpAddr>,
        timeout: Duration,
    },
}

impl DnsHttpsServer {
    pub fn new(
        domain: String,
        path: String,
        addr: Vec<IpAddr>,
        timeout: Duration,
    ) -> DnsHttpsServer {
        DnsHttpsServer::Custom {
            domain,
            path,
            addr,
            timeout,
        }
    }

    fn addr(&self) -> &[IpAddr] {
        match self {
            Self::Google(_) => GOOGLE,
            Self::Cloudflare(_) => CLOUDFLARE,
            Self::Custom {
                domain: _,
                path: _,
                addr,
                timeout: _,
            } => addr,
        }
    }

    fn domain(&self) -> &str {
        match self {
            Self::Google(_) => "dns.google",
            Self::Cloudflare(_) => "cloudflare-dns.com",
            Self::Custom {
                domain,
                path: _,
                addr: _,
                timeout: _,
            } => domain,
        }
    }

    fn path(&self) -> &str {
        match self {
            Self::Google(_) => "resolve",
            Self::Cloudflare(_) => "dns-query",
            Self::Custom {
                domain: _,
                path,
                addr: _,
                timeout: _,
            } => path,
        }
    }

    fn timeout(&self) -> Duration {
        match self {
            Self::Google(t) => *t,
            Self::Cloudflare(t) => *t,
            Self::Custom {
                domain: _,
                path: _,
                addr: _,
                timeout,
            } => *timeout,
        }
    }
}
