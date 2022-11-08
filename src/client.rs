//! HTTPS client to query DoH servers.
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    task::{self, Poll},
    time::Duration,
    vec::IntoIter,
};

use async_trait::async_trait;
use futures_util::future::{err, ok, Ready};
use hyper::{
    client::{connect::dns::InvalidNameError, connect::dns::Name, connect::Connect, HttpConnector},
    error::Result as HyperResult,
    Body, Client, Request, Response, Uri,
};
use hyper_tls::HttpsConnector;
use tokio::time::timeout;
use tower_service::Service;

use crate::{dns::Rtype, error::QueryError, DnsHttpsServer};

/// Builder for customizing the HyperDnsClient.
pub struct Builder {
    servers: Option<Vec<DnsHttpsServer>>,
    pool_max_idle_per_host: usize,
}

impl Default for Builder {
    fn default() -> Builder {
        Builder {
            servers: Some(vec![
                DnsHttpsServer::Google(Duration::from_secs(3)),
                DnsHttpsServer::Cloudflare(Duration::from_secs(10)),
            ]),
            pool_max_idle_per_host: 1,
        }
    }
}

impl<'a> Builder {
    pub fn with_servers(&'a mut self, servers: Vec<DnsHttpsServer>) -> &'a mut Self {
        self.servers = Some(servers);
        self
    }

    pub fn pool_max_idle_per_host(&'a mut self, max: usize) -> &'a mut Self {
        self.pool_max_idle_per_host = max;
        self
    }

    pub fn build(&mut self) -> HyperDnsClient {
        let servers = self.servers.take().unwrap();
        let mut http_connector = HttpConnector::new_with_resolver(StaticResolver::new(&servers));
        http_connector.enforce_http(false);
        let mut connector = HttpsConnector::from((
            http_connector,
            native_tls::TlsConnector::new().unwrap().into(),
        ));
        connector.https_only(true);

        let client = Client::builder()
            .pool_max_idle_per_host(self.pool_max_idle_per_host)
            .build(connector);
        HyperDnsClient { client, servers }
    }
}

/// Hyper-based DNS client over SSL and with a static resolver to resolve DNS server names
/// such as `dns.google` since Google does not accept request over `8.8.8.8` like Cloudflare
/// does over `1.1.1.1`.
pub struct HyperDnsClient<C = HttpsConnector<HttpConnector<StaticResolver>>> {
    client: Client<C>,
    servers: Vec<DnsHttpsServer>,
}

impl HyperDnsClient {
    pub fn builder() -> Builder {
        Builder::default()
    }
}

impl Default for HyperDnsClient {
    fn default() -> HyperDnsClient {
        Builder::default().build()
    }
}

impl<C> HyperDnsClient<C>
where
    C: Connect,
    C: Send + Sync + Clone + 'static,
{
    pub fn new(client: Client<C>, servers: Vec<DnsHttpsServer>) -> HyperDnsClient<C> {
        HyperDnsClient { client, servers }
    }

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

/// Creates a `GET` request over the given `URI` and returns its response. It is used to
/// request data from DoH servers.
#[async_trait]
pub trait DnsClient {
    async fn request(&self, name: &str, rtype: &Rtype) -> Result<DnsResponse, QueryError>;
}

/// The response from the DoH server returned from the DnsClient implementation.
#[allow(non_snake_case)]
#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct DnsResponse {
    pub Status: u32,
    pub Answer: Option<Vec<DnsAnswer>>,
}

/// The data associated for requests returned by the DNS over HTTPS servers.
#[allow(non_snake_case)]
#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct DnsAnswer {
    /// The name of the record.
    pub name: String,
    /// The type associated with each record. To convert to a string representation use
    /// [Dns::rtype_to_name].
    pub r#type: u32,
    /// The time to live in seconds for this record.
    pub TTL: u32,
    /// The data associated with the record.
    pub data: String,
}

#[async_trait]
impl<C> DnsClient for HyperDnsClient<C>
where
    C: Connect,
    C: Send + Sync + Clone + 'static,
{
    // Creates the HTTPS request to the server. In certain occasions, it retries to a new server
    // if one is available.
    async fn request(&self, name: &str, rtype: &Rtype) -> Result<DnsResponse, QueryError> {
        // Name has to be puny encoded.
        let name = match idna::domain_to_ascii(name) {
            Ok(name) => name,
            Err(e) => return Err(QueryError::InvalidName(format!("{:?}", e))),
        };
        let mut error = QueryError::Unknown;
        for server in self.servers.iter() {
            let url = format!(
                "https://{}/{}?name={}&type={}",
                server.domain(),
                server.path(),
                name,
                rtype.1
            );
            let endpoint = match url.parse::<Uri>() {
                Err(e) => return Err(QueryError::InvalidEndpoint(e.to_string(), url)),
                Ok(endpoint) => endpoint,
            };

            error = match timeout(server.timeout(), self.get(endpoint)).await {
                Ok(Err(e)) => QueryError::Connection(e.to_string()),
                Ok(Ok(res)) => {
                    match res.status().as_u16() {
                        200 => match hyper::body::to_bytes(res).await {
                            Err(e) => QueryError::ReadResponse(e.to_string()),
                            Ok(body) => match serde_json::from_slice::<DnsResponse>(&body) {
                                Err(e) => QueryError::ParseResponse(e.to_string()),
                                Ok(res) => {
                                    return Ok(res);
                                }
                            },
                        },
                        400 => return Err(QueryError::BadRequest400),
                        413 => return Err(QueryError::PayloadTooLarge413),
                        414 => return Err(QueryError::UriTooLong414),
                        415 => return Err(QueryError::UnsupportedMediaType415),
                        501 => return Err(QueryError::NotImplemented501),
                        // If the following errors occur, the request will be retried on
                        // the next server if one is available.
                        429 => QueryError::TooManyRequests429,
                        500 => QueryError::InternalServerError500,
                        502 => QueryError::BadGateway502,
                        504 => QueryError::ResolverTimeout504,
                        _ => QueryError::Unknown,
                    }
                }
                Err(_) => QueryError::Connection(format!(
                    "connection timeout after {:?}",
                    server.timeout()
                )),
            };
            error!("request error on URL {}: {}", url, error);
        }
        Err(error)
    }
}

/// This is a resolver for the HyperDnsClient that statically resolves
/// the provided servers. The default client will try multiple IPs if specified.
#[derive(Clone)]
pub struct StaticResolver(HashMap<Name, Vec<IpAddr>>);

impl StaticResolver {
    pub fn new(servers: &[DnsHttpsServer]) -> StaticResolver {
        StaticResolver(
            servers
                .iter()
                .map(|s| Ok::<_, InvalidNameError>((s.domain().parse()?, s.addr().to_vec())))
                .filter_map(Result::ok)
                .collect(),
        )
    }
}

impl Service<Name> for StaticResolver {
    type Response = IntoIter<IpAddr>;
    type Error = io::Error;
    type Future = Ready<Result<IntoIter<IpAddr>, io::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        match self.0.get(&name) {
            Some(addrs) if addrs.len() > 0 => ok(addrs.to_vec().into_iter()),
            _ => err(io::Error::from(io::ErrorKind::AddrNotAvailable)),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::str::FromStr;
    use std::time::Duration;

    #[tokio::test]
    async fn test_static_resolve() {
        let mut resolver = StaticResolver::new(&[DnsHttpsServer::Google(Duration::from_secs(10))]);
        let n = Name::from_str("dns.google").unwrap();
        let mut g1 = resolver.call(n.clone()).await.unwrap();
        assert_eq!(g1.next(), "8.8.8.8".parse().ok());
        assert_eq!(g1.next(), "2001:4860:4860::8888".parse().ok());
        assert_eq!(g1.next(), "8.8.4.4".parse().ok());
        assert_eq!(g1.next(), "2001:4860:4860::8844".parse().ok());
        assert_eq!(g1.next(), None);
    }

    // TODO: mock hyper request
    //     #[tokio::test]
    //     async fn test_retries() {
    //         let response: DnsResponse = serde_json::from_str(
    //             r#"
    // {
    //   "Status": 0,
    //   "TC": false,
    //   "RD": true,
    //   "RA": true,
    //   "AD": false,
    //   "CD": false,
    //   "Question": [
    //     {
    //       "name": "www.google.com.",
    //       "type": 1
    //     }
    //   ],
    //   "Answer": [
    //     {
    //       "name": "www.google.com.",
    //       "type": 1,
    //       "TTL": 163,
    //       "data": "172.217.11.164"
    //     }
    //   ]
    // }"#,
    //         )
    //         .unwrap();
    //         // Retry if more than server is given.
    //         let d = HyperDnsClient::new(MockTransport::new(&[
    //             Err(QueryError::InternalServerError500),
    //             Ok(response.clone()),
    //         ]));
    //         let r = d.resolve_a("www.google.com").await.unwrap();
    //         assert_eq!(r.len(), 1);
    //         assert_eq!(r[0].name, "www.google.com.");
    //         assert_eq!(r[0].data, "172.217.11.164");
    //         assert_eq!(r[0].r#type, 1);
    //         assert_eq!(r[0].TTL, 163);

    //         // Not all errors should be retried.
    //         let d = HyperDnsClient::new(MockTransport::new(&[
    //             Err(QueryError::BadRequest400),
    //             Ok(response.clone()),
    //         ]));
    //         let r = d.resolve_a("www.google.com").await;
    //         assert!(r.is_err());

    //         // If only one server is given, an error should be received.
    //         let d = HyperDnsClient::new(MockTransport::new(&[
    //             Err(QueryError::InternalServerError500),
    //             Ok(response.clone()),
    //         ]));
    //         let r = d.resolve_a("www.google.com").await;
    //         assert!(r.is_err());
    // }
}
