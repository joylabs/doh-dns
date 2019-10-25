//! HTTPS client to query DoH servers.
use async_trait::async_trait;
use futures_util::future::{err, ok, Ready};
use hyper::client::connect::dns::{Name, Resolve};
use hyper::{
    client::HttpConnector, error::Result as HyperResult, Body, Client, Request, Response, Uri,
};
use hyper_tls::HttpsConnector;
use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

/// Creates a `GET` request over the given `URI` and returns its response. It is used to
/// request data from DoH servers.
#[async_trait]
pub trait DnsClient: Default {
    async fn get(&self, uri: Uri) -> HyperResult<Response<Body>>;
}

/// Hyper-based DNS client over SSL and with a static resolver to resolve DNS server names
/// such as `dns.google` since Google does not accept request over `8.8.8.8` like Cloudflare
/// does over `1.1.1.1`.
pub struct HyperDnsClient {
    client: Client<HttpsConnector<HttpConnector<UrlStaticResolver>>>,
}

impl Default for HyperDnsClient {
    fn default() -> HyperDnsClient {
        let mut http_connector = HttpConnector::new_with_resolver(UrlStaticResolver::new());
        http_connector.enforce_http(false);
        let mut connector = HttpsConnector::from((
            http_connector,
            native_tls::TlsConnector::new().unwrap().into(),
        ));
        connector.https_only(true);
        HyperDnsClient {
            client: Client::builder().keep_alive(true).build(connector),
        }
    }
}

#[async_trait]
impl DnsClient for HyperDnsClient {
    async fn get(&self, uri: Uri) -> HyperResult<Response<Body>> {
        // The reason to build a request manually is to set the Accept header required by
        // DNS servers.
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("Accept", "application/dns-json")
            .body(Body::default())
            .expect("request builder");
        self.client.request(req).await
    }
}

// This is resolver that statically resolves the Google DNS name to 8.8.8.8 and
// 8.8.4.4 in a round robin fashion. The Cloudflare IPs are not resolved since those
// are already statically defined in the request URL.
#[derive(Clone)]
struct UrlStaticResolver {
    round_robin: Arc<AtomicBool>,
}

impl UrlStaticResolver {
    fn new() -> UrlStaticResolver {
        UrlStaticResolver {
            round_robin: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl Resolve for UrlStaticResolver {
    type Addrs = UrlStaticAddrs;
    type Future = Ready<Result<UrlStaticAddrs, io::Error>>;

    fn resolve(&self, name: Name) -> Self::Future {
        if name.as_str() == "dns.google" {
            let rr_ref = Arc::clone(&self.round_robin);
            let rr = rr_ref.load(Ordering::Relaxed);
            let addr = if rr {
                rr_ref.store(false, Ordering::Relaxed);
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
            } else {
                rr_ref.store(true, Ordering::Relaxed);
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))
            };
            ok(UrlStaticAddrs { inner: Some(addr) })
        } else {
            // This should never occur.
            err(io::Error::from(io::ErrorKind::AddrNotAvailable))
        }
    }
}

// This only contains one IP address so the iterator only needs to go through it once.
struct UrlStaticAddrs {
    inner: Option<IpAddr>,
}

impl Iterator for UrlStaticAddrs {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ip) = self.inner {
            self.inner = None;
            Some(ip)
        } else {
            None
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_static_resolve() {
        let resolver = UrlStaticResolver::new();
        let n = Name::from_str("dns.google").unwrap();
        let mut g1 = resolver.resolve(n.clone()).await.unwrap();
        assert_eq!(g1.next(), Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert_eq!(g1.next(), None);
        let mut g2 = resolver.resolve(n.clone()).await.unwrap();
        assert_eq!(g2.next(), Some(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))));
        assert_eq!(g2.next(), None);
    }
}
