use std::net::UdpSocket;
use toy_dns_server::handle_query;

fn main() {
    let socket = UdpSocket::bind(("0.0.0.0", 2053)).expect("couldn't bind to address");

    loop {
        if let Err(e) = handle_query(&socket) {
            eprintln!("An error occurred: {}", e);
        }
    }
}
