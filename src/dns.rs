use crate::client::{DnsAnswer, DnsClient, HyperDnsClient};
use crate::error::DnsError;
use crate::status::RCode;
use crate::DnsHttpsServer;

/// The main interface to this library. It provides all functions to query records.
pub struct Dns<C = HyperDnsClient> {
    client: C,
}

impl Default for Dns<HyperDnsClient> {
    fn default() -> Dns<HyperDnsClient> {
        Dns {
            client: HyperDnsClient::default(),
        }
    }
}

impl Dns<HyperDnsClient> {
    /// Creates an instance with the given servers along with their respective timeouts
    /// (in seconds). These servers are tried in the given order. If a request fails on
    /// the first one, each subsequent server is tried. Only on certain failures a new
    /// request is retried such as a connection failure or certain server return codes.
    pub fn with_servers(servers: Vec<DnsHttpsServer>) -> Result<Dns<HyperDnsClient>, DnsError> {
        if servers.is_empty() {
            return Err(DnsError::NoServers);
        }

        Ok(Dns::new(
            HyperDnsClient::builder().with_servers(servers).build(),
        ))
    }
}

impl<C: DnsClient> Dns<C> {
    /// Use a specific DnsClient implementation when resolving records.
    /// If you don't need to customize the client, you may use the Dns::default()
    /// instead.
    pub fn new(client: C) -> Dns<C> {
        Dns { client }
    }

    /// Returns MX records in order of priority for the given name. It removes the priorities
    /// from the data.
    pub async fn resolve_mx_and_sort(&self, domain: &str) -> Result<Vec<DnsAnswer>, DnsError> {
        match self.client.request(domain, &RTYPE_mx).await {
            Err(e) => Err(DnsError::Query(e)),
            Ok(res) => match num::FromPrimitive::from_u32(res.Status) {
                Some(RCode::NoError) => {
                    let mut mxs = res
                        .Answer
                        .unwrap_or_else(|| vec![])
                        .iter()
                        .filter_map(|a| {
                            // Get only MX records.
                            if a.r#type == RTYPE_mx.0 {
                                // Get only the records that have a priority.
                                let mut parts = a.data.split_ascii_whitespace();
                                if let Some(part_1) = parts.next() {
                                    // Convert priority to an integer.
                                    if let Ok(priority) = part_1.parse::<u32>() {
                                        if let Some(mx) = parts.next() {
                                            // Change data from "priority name" -> "name".
                                            let mut m = a.clone();
                                            m.data = mx.to_string();
                                            return Some((m, priority));
                                        }
                                    }
                                }
                            }
                            None
                        })
                        .collect::<Vec<_>>();
                    // Order MX records by priority.
                    mxs.sort_unstable_by_key(|x| x.1);
                    Ok(mxs.into_iter().map(|x| x.0).collect())
                }
                Some(code) => Err(DnsError::Status(code)),
                None => Err(DnsError::Status(RCode::Unknown)),
            },
        }
    }

    // Generates the DNS over HTTPS request on the given name for rtype. It filters out
    // results that are not of the given rtype with the exception of `ANY`. Also
    // CNAME chains are returned when requesting A/AAAA records.
    async fn request_and_process(
        &self,
        name: &str,
        rtype: &Rtype,
    ) -> Result<Vec<DnsAnswer>, DnsError> {
        match self.client.request(name, rtype).await {
            Err(e) => Err(DnsError::Query(e)),
            Ok(res) => match num::FromPrimitive::from_u32(res.Status) {
                Some(RCode::NoError) => Ok(res
                    .Answer
                    .unwrap_or_else(|| vec![])
                    .into_iter()
                    // Get only the record types requested. There is only exception and that is
                    // the ANY record which has a value of 0.
                    .filter(|a| a.r#type == rtype.0 || rtype.0 == 0 || allow_cname(a, rtype))
                    .collect::<Vec<_>>()),
                Some(code) => Err(DnsError::Status(code)),
                None => Err(DnsError::Status(RCode::Unknown)),
            },
        }
    }
}

fn allow_cname(answer: &DnsAnswer, request: &Rtype) -> bool {
    if request.0 == 1 || request.0 == 28 {
        return answer.r#type == 5;
    }
    return false;
}

/// DNS record type.
pub struct Rtype(pub u32, pub &'static str);

macro_rules! rtypes {
    (
        $(
            $(#[$docs:meta])*
            ($konst:ident, $num:expr);
        )+
    ) => {
        paste::item! {
            impl<C: DnsClient> Dns<C> {
                $(
                    $(#[$docs])*
                    pub async fn [<resolve_ $konst>](&self, name: &str) -> Result<Vec<DnsAnswer>, DnsError> {
                        self.request_and_process(name, &[<RTYPE_ $konst>]).await
                    }
                )+

                pub async fn resolve_str_type(&self, name: &str, rtype: &str) -> Result<Vec<DnsAnswer>, DnsError> {
                    match rtype.to_ascii_lowercase().as_ref() {
                        $(
                        stringify!($konst) => self.[<resolve_ $konst>](name).await,
                        )+
                        _ => Err(DnsError::InvalidRecordType),
                    }
                }

                /// Converts the given record type to a string representation.
                pub fn rtype_to_name(&self, rtype: u32) -> String {
                    let name = match rtype {
                        $(
                        $num => stringify!($konst),
                        )+
                        _ => "unknown",
                    };
                    name.to_ascii_uppercase()
                }
            }
        $(
            #[allow(non_upper_case_globals)]
            const [<RTYPE_ $konst>]: Rtype = Rtype($num, stringify!($konst));
        )+
        }
    }
}

// The following types were obtained from the following address:
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
rtypes! {
    /// Queries a host address for the given name.
    (a, 1);
    /// Queries an IP6 Address for the given name.
    (aaaa, 28);
    /// Queries all record types for a given name.
    (any, 0);
    /// Queries a certification authority restriction record for the given name.
    (caa, 257);
    /// Queries a child DS record for the given name.
    (cds, 59);
    /// Queries a CERT record for the given name.
    (cert, 37);
    /// Queries the canonical name for an alias for the given name.
    (cname, 5);
    /// Queries a DNAME record for the given name.
    (dname, 39);
    /// Queries a DNSKEY record for the given name.
    (dnskey, 48);
    /// Queries a delegation signer record for the given name.
    (ds, 43);
    /// Queries a host information record for the given name.
    (hinfo, 13);
    /// Queries a IPSECKEY record for the given name.
    (ipseckey, 45);
    /// Queries a mail exchange record for the given name.
    (mx, 15);
    /// Queries a naming authority pointer record for the given name.
    (naptr, 35);
    /// Queries an authoritative name server record for the given name.
    (ns, 2);
    /// Queries a NSEC record for the given name.
    (nsec, 47);
    /// Queries a NSEC3 record for the given name.
    (nsec3, 50);
    /// Queries a NSEC3PARAM record for the given name.
    (nsec3param, 51);
    /// Queries a domain name pointer record for the given name.
    (ptr, 12);
    /// Queries a responsible person record for the given name.
    (rp, 17);
    /// Queries a RRSIG record for the given name.
    (rrsig, 46);
    /// Queries the start of a zone of authority record for the given name.
    (soa, 6);
    /// Queries an SPF record for the given name. See RFC7208.
    (spf, 99);
    /// Queries a server selection record for the given name.
    (srv, 33);
    /// Queries an SSH key fingerprint record for the given name.
    (sshfp, 44);
    /// Queries a TLSA record for the given name.
    (tlsa, 52);
    /// Queries a text strings record for the given name.
    (txt, 16);
    /// Queries a well known service description record for the given name.
    (wks, 11);
}

#[cfg(test)]
pub mod tests {
    use async_trait::async_trait;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use crate::client::DnsResponse;
    use crate::error::QueryError;

    struct MockDnsClient {
        response: Vec<Result<DnsResponse, QueryError>>,
        counter: Arc<AtomicUsize>,
    }

    impl MockDnsClient {
        fn new(response: &[Result<DnsResponse, QueryError>]) -> MockDnsClient {
            MockDnsClient {
                response: response.to_vec(),
                counter: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl DnsClient for MockDnsClient {
        async fn request(&self, _name: &str, _rtype: &Rtype) -> Result<DnsResponse, QueryError> {
            let counter = Arc::clone(&self.counter);
            let index = counter.fetch_add(1, Ordering::SeqCst);
            self.response[index].clone()
        }
    }

    impl Default for MockDnsClient {
        fn default() -> MockDnsClient {
            MockDnsClient {
                response: vec![],
                counter: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    use super::*;

    #[tokio::test]
    async fn test_a() {
        let response = serde_json::from_str(
            r#"
        {
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [
    {
      "name": "www.sendgrid.com.",
      "type": 1
    }
  ],
  "Answer": [
    {
      "name": "www.sendgrid.com.",
      "type": 5,
      "TTL": 988,
      "data": "sendgrid.com."
    },
    {
      "name": "sendgrid.com.",
      "type": 1,
      "TTL": 89,
      "data": "169.45.113.198"
    },
    {
      "name": "sendgrid.com.",
      "type": 1,
      "TTL": 89,
      "data": "167.89.118.63"
    },
    {
      "name": "sendgrid.com.",
      "type": 1,
      "TTL": 89,
      "data": "169.45.89.183"
    },
    {
      "name": "sendgrid.com.",
      "type": 1,
      "TTL": 89,
      "data": "167.89.118.65"
    }
  ],
  "Comment": "Response from 2600:1801:13::1."
    }"#,
        )
        .unwrap();
        let d = Dns::new(MockDnsClient::new(&[Ok(response)]));
        let r = d.resolve_a("sendgrid.com").await.unwrap();
        assert_eq!(r.len(), 5); // Including CNAME
        assert_eq!(r[0].name, "www.sendgrid.com.");
        assert_eq!(r[0].data, "sendgrid.com.");
        assert_eq!(r[0].r#type, 5);
        assert_eq!(r[0].TTL, 988);
        assert_eq!(r[1].name, "sendgrid.com.");
        assert_eq!(r[1].data, "169.45.113.198");
        assert_eq!(r[1].r#type, 1);
        assert_eq!(r[1].TTL, 89);
        assert_eq!(r[2].name, "sendgrid.com.");
        assert_eq!(r[2].data, "167.89.118.63");
        assert_eq!(r[2].r#type, 1);
        assert_eq!(r[2].TTL, 89);
        assert_eq!(r[3].name, "sendgrid.com.");
        assert_eq!(r[3].data, "169.45.89.183");
        assert_eq!(r[3].r#type, 1);
        assert_eq!(r[3].TTL, 89);
        assert_eq!(r[4].name, "sendgrid.com.");
        assert_eq!(r[4].data, "167.89.118.65");
        assert_eq!(r[4].r#type, 1);
        assert_eq!(r[4].TTL, 89);
    }

    #[tokio::test]
    async fn test_mx() {
        let response: DnsResponse = serde_json::from_str(
            r#"
        {
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [
    {
      "name": "gmail.com.",
      "type": 15
    }
  ],
  "Answer": [
    {
      "name": "gmail.com.",
      "type": 15,
      "TTL": 3599,
      "data": "30 alt3.gmail-smtp-in.l.google.com."
    },
    {
      "name": "gmail.com.",
      "type": 15,
      "TTL": 3599,
      "data": "5 gmail-smtp-in.l.google.com."
    },
    {
      "name": "gmail.com.",
      "type": 15,
      "TTL": 3599,
      "data": "40 alt4.gmail-smtp-in.l.google.com."
    },
    {
      "name": "gmail.com.",
      "type": 15,
      "TTL": 3599,
      "data": "10 alt1.gmail-smtp-in.l.google.com."
    },
    {
      "name": "gmail.com.",
      "type": 15,
      "TTL": 3599,
      "data": "20 alt2.gmail-smtp-in.l.google.com."
    }
  ],
  "Comment": "Response from 2001:4860:4802:32::a."
}"#,
        )
        .unwrap();
        let d = Dns::new(MockDnsClient::new(&[Ok(response.clone())]));
        let r = d.resolve_mx_and_sort("gmail.com").await.unwrap();
        assert_eq!(r.len(), 5);
        assert_eq!(r[0].name, "gmail.com.");
        assert_eq!(r[0].data, "gmail-smtp-in.l.google.com.");
        assert_eq!(r[0].r#type, 15);
        assert_eq!(r[0].TTL, 3599);
        assert_eq!(r[1].name, "gmail.com.");
        assert_eq!(r[1].data, "alt1.gmail-smtp-in.l.google.com.");
        assert_eq!(r[1].r#type, 15);
        assert_eq!(r[1].TTL, 3599);
        assert_eq!(r[2].name, "gmail.com.");
        assert_eq!(r[2].data, "alt2.gmail-smtp-in.l.google.com.");
        assert_eq!(r[2].r#type, 15);
        assert_eq!(r[2].TTL, 3599);
        assert_eq!(r[3].name, "gmail.com.");
        assert_eq!(r[3].data, "alt3.gmail-smtp-in.l.google.com.");
        assert_eq!(r[3].r#type, 15);
        assert_eq!(r[3].TTL, 3599);
        assert_eq!(r[4].name, "gmail.com.");
        assert_eq!(r[4].data, "alt4.gmail-smtp-in.l.google.com.");
        assert_eq!(r[4].r#type, 15);
        assert_eq!(r[4].TTL, 3599);

        let d = Dns::new(MockDnsClient::new(&[Ok(response)]));
        let r = d.resolve_mx("gmail.com").await.unwrap();
        assert_eq!(r.len(), 5);
        assert_eq!(r[0].name, "gmail.com.");
        assert_eq!(r[0].data, "30 alt3.gmail-smtp-in.l.google.com.");
        assert_eq!(r[0].r#type, 15);
        assert_eq!(r[0].TTL, 3599);
        assert_eq!(r[1].name, "gmail.com.");
        assert_eq!(r[1].data, "5 gmail-smtp-in.l.google.com.");
        assert_eq!(r[1].r#type, 15);
        assert_eq!(r[1].TTL, 3599);
        assert_eq!(r[2].name, "gmail.com.");
        assert_eq!(r[2].data, "40 alt4.gmail-smtp-in.l.google.com.");
        assert_eq!(r[2].r#type, 15);
        assert_eq!(r[2].TTL, 3599);
        assert_eq!(r[3].name, "gmail.com.");
        assert_eq!(r[3].data, "10 alt1.gmail-smtp-in.l.google.com.");
        assert_eq!(r[3].r#type, 15);
        assert_eq!(r[3].TTL, 3599);
        assert_eq!(r[4].name, "gmail.com.");
        assert_eq!(r[4].data, "20 alt2.gmail-smtp-in.l.google.com.");
        assert_eq!(r[4].r#type, 15);
        assert_eq!(r[4].TTL, 3599);
    }

    #[tokio::test]
    async fn test_txt() {
        let response = serde_json::from_str(
            r#"
        {
  "Status": 0,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": false,
  "CD": false,
  "Question": [
    {
      "name": "google.com.",
      "type": 16
    }
  ],
  "Answer": [
    {
      "name": "google.com.",
      "type": 16,
      "TTL": 3599,
      "data": "\"facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95\""
    },
    {
      "name": "google.com.",
      "type": 16,
      "TTL": 3599,
      "data": "\"globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8=\""
    },
    {
      "name": "google.com.",
      "type": 16,
      "TTL": 299,
      "data": "\"docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e\""
    },
    {
      "name": "google.com.",
      "type": 16,
      "TTL": 299,
      "data": "\"docusign=1b0a6754-49b1-4db5-8540-d2c12664b289\""
    },
    {
      "name": "google.com.",
      "type": 16,
      "TTL": 3599,
      "data": "\"v=spf1 include:_spf.google.com ~all\""
    }
  ],
  "Comment": "Response from 216.239.36.10."
}"#,
        )
        .unwrap();
        let d = Dns::new(MockDnsClient::new(&[Ok(response)]));
        let r = d.resolve_txt("google.com").await.unwrap();
        assert_eq!(r.len(), 5);
        assert_eq!(r[0].name, "google.com.");
        assert_eq!(
            r[0].data,
            "\"facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95\""
        );
        assert_eq!(r[0].r#type, 16);
        assert_eq!(r[0].TTL, 3599);
        assert_eq!(r[1].name, "google.com.");
        assert_eq!(
            r[1].data,
            "\"globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8=\""
        );
        assert_eq!(r[1].r#type, 16);
        assert_eq!(r[1].TTL, 3599);
        assert_eq!(r[2].name, "google.com.");
        assert_eq!(
            r[2].data,
            "\"docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e\""
        );
        assert_eq!(r[2].r#type, 16);
        assert_eq!(r[2].TTL, 299);
        assert_eq!(r[3].name, "google.com.");
        assert_eq!(
            r[3].data,
            "\"docusign=1b0a6754-49b1-4db5-8540-d2c12664b289\""
        );
        assert_eq!(r[3].r#type, 16);
        assert_eq!(r[3].TTL, 299);
        assert_eq!(r[4].name, "google.com.");
        assert_eq!(r[4].data, "\"v=spf1 include:_spf.google.com ~all\"");
        assert_eq!(r[4].r#type, 16);
        assert_eq!(r[4].TTL, 3599);
    }
}
