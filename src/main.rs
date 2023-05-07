use std::net::UdpSocket;
use toy_dns_server::{BytePacketBuffer, DnsPacket, DnsQuestion, QueryType};

fn main() -> anyhow::Result<()> {
    let qname = "google.com";
    let qtype = QueryType::A;

    let server = ("8.8.8.8", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut req_packet = DnsPacket::new();
    req_packet.header.id = 6666;
    req_packet.header.questions = 1;
    req_packet.header.recursion_desired = true;
    req_packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    req_packet.write(&mut req_buffer)?;
    socket.send_to(&req_buffer.buffer[0..req_buffer.position], server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buffer)?;

    let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;
    println!("{:#?}", res_packet.header);

    for question in res_packet.questions {
        println!("{:#?}", question);
    }

    for record in res_packet.answers {
        println!("{:#?}", record);
    }

    for record in res_packet.authorities {
        println!("{:#?}", record);
    }

    for record in res_packet.resources {
        println!("{:#?}", record);
    }

    Ok(())
}
