//! Status codes returned from the DNS over HTTP server.
use std::fmt;
/// These codes were obtained from
/// <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6>.
#[derive(Debug, FromPrimitive)]
pub enum RCode {
    /// No Error.
    NoError,
    /// Format Error.
    FormErr,
    /// Server Failure.
    ServFail,
    /// Non-Existent Domain.
    NXDomain,
    /// Not Implemented. Cloudflare returns this for all `ANY` DNS requests.
    NotImp,
    /// Query Refused.
    Refused,
    /// Name Exists when it should not.
    YXDomain,
    /// RR Set Exists when it should not.
    YXRRSet,
    /// RR Set that should exist does not.
    NXRRSet,
    /// Server Not Authoritative for zone.
    NotAuth,
    /// Name not contained in zone.
    NotZone,
    /// DSO-TYPE Not Implemented.
    DSOTYPENI,
    /// Unassigned.
    Unassigned12,
    /// Unassigned.
    Unassigned13,
    /// Unassigned.
    Unassigned14,
    /// Unassigned.
    Unassigned15,
    /// Bad OPT Version.
    BADVERS,
    /// Key not recognized.
    BADKEY,
    /// Signature out of time window.
    BADTIME,
    /// Bad TKEY Mode.
    BADMODE,
    /// Duplicate key name.
    BADNAME,
    /// Algorithm not supported.
    BADALG,
    /// Bad Truncation.
    BADTRUNC,
    /// Bad/missing Server Cookie.
    BADCOOKIE,
    /// Unknown.
    Unknown,
}

impl fmt::Display for RCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RCode::NoError => write!(f, "No Error"),
            RCode::FormErr => write!(f, "Format Error"),
            RCode::ServFail => write!(f, "Server Failure"),
            RCode::NXDomain => write!(f, "Non-Existent Domain"),
            RCode::NotImp => write!(f, "Not Implemented"),
            RCode::Refused => write!(f, "Query Refused"),
            RCode::YXDomain => write!(f, "Name Exists when it should not"),
            RCode::YXRRSet => write!(f, "RR Set Exists when it should not"),
            RCode::NXRRSet => write!(f, "RR Set that should exist does not"),
            RCode::NotAuth => write!(f, "Server Not Authoritative for zone"),
            RCode::NotZone => write!(f, "Name not contained in zone"),
            RCode::DSOTYPENI => write!(f, "DSO-TYPE Not Implemented"),
            RCode::Unassigned12
            | RCode::Unassigned13
            | RCode::Unassigned14
            | RCode::Unassigned15 => write!(f, "Unassigned"),
            RCode::BADVERS => write!(f, "Bad OPT Version"),
            RCode::BADKEY => write!(f, "Key not recognized"),
            RCode::BADTIME => write!(f, "Signature out of time window"),
            RCode::BADMODE => write!(f, "Bad TKEY Mode"),
            RCode::BADNAME => write!(f, "Duplicate key name"),
            RCode::BADALG => write!(f, "Algorithm not supported"),
            RCode::BADTRUNC => write!(f, "Bad Truncation"),
            RCode::BADCOOKIE => write!(f, "Bad/missing Server Cookie"),
            RCode::Unknown => write!(f, "Unknown"),
        }
    }
}
