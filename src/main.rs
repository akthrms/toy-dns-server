use std::net::UdpSocket;
use toy_dns_server::{BytePacketBuffer, DnsPacket, DnsQuestion, QueryType, ResultCode};

fn main() -> anyhow::Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    loop {
        if let Err(e) = handle_query(&socket) {
            eprintln!("An error occurred: {}", e);
        }
    }
}

fn lookup(qname: &str, qtype: QueryType) -> anyhow::Result<DnsPacket> {
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

    DnsPacket::from_buffer(&mut res_buffer)
}

fn handle_query(socket: &UdpSocket) -> anyhow::Result<()> {
    let mut req_buffer = BytePacketBuffer::new();
    let (_, src) = socket.recv_from(&mut req_buffer.buffer)?;
    let mut req_packet = DnsPacket::from_buffer(&mut req_buffer)?;

    let mut res_packet = DnsPacket::new();
    res_packet.header.id = req_packet.header.id;
    res_packet.header.recursion_desired = true;
    res_packet.header.recursion_available = true;
    res_packet.header.response = true;

    if let Some(question) = req_packet.questions.pop() {
        println!("Received query: {:?}", question);

        if let Ok(result) = lookup(&question.name, question.qtype) {
            res_packet.questions.push(question);
            res_packet.header.rescode = result.header.rescode;

            for record in result.answers {
                println!("Answer: {:?}", record);
                res_packet.answers.push(record);
            }

            for record in result.authorities {
                println!("Authority: {:?}", record);
                res_packet.authorities.push(record);
            }

            for record in result.resources {
                println!("Resource: {:?}", record);
                res_packet.resources.push(record);
            }
        } else {
            res_packet.header.rescode = ResultCode::ServFail;
        }
    } else {
        res_packet.header.rescode = ResultCode::FormErr;
    }

    let mut res_buffer = BytePacketBuffer::new();
    res_packet.write(&mut res_buffer)?;
    let data = res_buffer.get_range(0, res_buffer.position)?;
    socket.send_to(data, src)?;

    Ok(())
}
