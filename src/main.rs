use std::{fs::File, io::Read};
use toy_dns_server::{BytePacketBuffer, DnsPacket};

fn main() -> anyhow::Result<()> {
    let mut file = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    let _ = file.read(&mut buffer.buffer)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for question in packet.questions {
        println!("{:#?}", question);
    }

    for record in packet.answers {
        println!("{:#?}", record);
    }

    for record in packet.authorities {
        println!("{:#?}", record);
    }

    for record in packet.resources {
        println!("{:#?}", record);
    }

    Ok(())
}
