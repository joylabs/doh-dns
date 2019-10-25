use doh_dns::{client::HyperDnsClient, Dns, DnsHttpServer};
use log::{Level, LevelFilter, Metadata, Record};
#[macro_use]
extern crate prettytable;
use prettytable::Table;
use std::env;
use std::time::Duration;
use tokio;

static LOGGER: SimpleLogger = SimpleLogger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} rtype name", args[0]);
        return Ok(());
    }

    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Info))
        .unwrap();

    let dns: Dns<HyperDnsClient> = Dns::with_servers(&[
        DnsHttpServer::Google(Duration::from_secs(2)),
        DnsHttpServer::Cloudflare1_1_1_1(Duration::from_secs(10)),
    ])
    .unwrap();
    match dns.resolve_str_type(&args[2], &args[1]).await {
        Ok(responses) => {
            if responses.is_empty() {
                println!("No entries found.");
            } else {
                let mut table = Table::new();
                table.add_row(row![c =>
                    "Name",
                    "Type",
                    "TTL",
                    "Data"
                ]);
                for res in responses {
                    table.add_row(row![
                        res.name,
                        r->dns.rtype_to_name(res.r#type),
                        r->res.TTL,
                        res.data
                    ]);
                }
                table.printstd();
            }
        }
        Err(err) => println!("Error: {}", err),
    }
    Ok(())
}

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}
