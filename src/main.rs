use std::net::UdpSocket;
use toy_dns_server::handle_query;

fn main() -> anyhow::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    loop {
        if let Err(e) = handle_query(&socket) {
            eprintln!("An error occurred: {}", e);
        }
    }
}
