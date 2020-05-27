//! Errors returned by DoH servers.
use crate::status::RCode;
use std::{error::Error, fmt};

/// Errors returned before or after making a DNS request over HTTPS.
#[derive(Debug)]
pub enum DnsError {
    /// An error occurred before making the request. This can when a name is of
    /// the wrong format, connecting to servers, or parsing the server response.
    Query(QueryError),
    /// An error returned by the DNS server with regards to the name being queried. It
    /// occurs after a successful request/response. An example is a name that does not
    /// exist.
    Status(RCode),
    /// An error returned when an attempt to query a record type that does not exist.
    InvalidRecordType,
    /// An error when trying to setup an empty list of servers to query.
    NoServers,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DnsError::Query(ref e) => write!(f, "query error: {}", e),
            DnsError::Status(ref e) => write!(f, "DNS response error: {}", e),
            DnsError::InvalidRecordType => write!(f, "Invalid record type"),
            DnsError::NoServers => write!(f, "no servers given to resolve query"),
        }
    }
}

impl Error for DnsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

/// Errors returned in the process of generating requests and reading responsed from DoH
/// servers. Google's HTTP response codes can be seen at <https://developers.google.com/speed/public-dns/docs/doh>
/// and Cloudflare's at <https://developers.cloudflare.com/1.1.1.1/dns-over-https/request-structure>.
#[derive(Debug)]
pub enum QueryError {
    /// This error occurs if the name to be resolved cannot be encoded.
    InvalidName(String),
    /// This error occurs if there is a problem building the query URL.
    InvalidEndpoint(String, String),
    /// This error occurs if there is a problem connecting to the server.
    Connection(String),
    /// This error occurs if there is a problem reading a response from the server.
    ReadResponse(String),
    /// This error occurs if there is a problem parsing the JSON response from the server.
    ParseResponse(String),
    /// Unknown error. This occurs if the server returns an unexpected result.
    Unknown,
    /// *HTTP Error: 400 Bad Request.*
    /// Problems parsing the GET parameters, or an invalid DNS request message.
    BadRequest400,
    /// *HTTP Error: 413 Payload Too Large.*
    /// An RFC 8484 POST request body exceeded the 512 byte maximum message size.
    PayloadTooLarge413,
    /// *HTTP Error: 414 URI Too Long.*
    /// The GET query header was too large or the dns parameter had a Base64Url
    /// encoded DNS message exceeding the 512 byte maximum message size.
    UriTooLong414,
    /// *HTTP Error: 415 Unsupported Media Type.*
    /// The POST body did not have an application/dns-message Content-Type header.
    UnsupportedMediaType415,
    /// *HTTP Error: 429 Too Many Requests.*
    /// The client has sent too many requests in a given amount of time.
    TooManyRequests429,
    /// *HTTP Error: 500 Internal Server Error.*
    /// Google Public DNS internal DoH errors.
    InternalServerError500,
    /// *HTTP Error: 501 Not Implemented.*
    /// Only GET and POST methods are implemented, other methods get this error.
    NotImplemented501,
    /// *HTTP Error: 502 Bad Gateway.*
    /// The DoH service could not contact Google Public DNS resolvers.
    BadGateway502,
    /// *HTTP Error: 504.*
    /// Resolver timeout while waiting for the query response.
    ResolverTimeout504,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            QueryError::InvalidName(ref e) => write!(f, "invalid server name given: {}", e),
            QueryError::InvalidEndpoint(ref e, ref url) => write!(f, "invalid endpoint ({}): {}", url, e),
            QueryError::Connection(ref e) => write!(f, "connection error: {}", e),
            QueryError::ReadResponse(ref e) => write!(f, "error reading response: {}", e),
            QueryError::ParseResponse(ref e) => write!(f, "error parsing response: {}", e),
            QueryError::Unknown => write!(f, "unknown query error"),
            QueryError::BadRequest400 => write!(
                f,
                "Problems parsing the GET parameters, or an invalid DNS request message"
            ),
            QueryError::PayloadTooLarge413 => write!(
                f,
                "An RFC 8484 POST request body exceeded the 512 byte maximum message size"
            ),
            QueryError::UriTooLong414 => write!(
                f,
                "The GET query header was too large or the dns parameter had a Base64Url encoded DNS message exceeding the 512 byte maximum message size"
            ),
            QueryError::UnsupportedMediaType415 => write!(
                f,
                "The POST body did not have an application/dns-message Content-Type header"
            ),
            QueryError::TooManyRequests429 => write!(
                f,
                "The client has sent too many requests in a given amount of time"
            ),
            QueryError::InternalServerError500 => write!(
                f,
                "Google Public DNS internal DoH errors"
            ),
            QueryError::NotImplemented501 => write!(
                f,
                "Only GET and POST methods are implemented, other methods get this error"
            ),
            QueryError::BadGateway502 => write!(
                f,
                "The DoH service could not contact Google Public DNS resolvers"
            ),
            QueryError::ResolverTimeout504 => write!(
                f,
                "Resolver timeout while waiting for the query response"
            ),
        }
    }
}

impl Error for QueryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}
