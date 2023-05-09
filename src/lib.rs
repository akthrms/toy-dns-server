use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use thiserror::Error;

#[derive(Debug, Error)]
enum BytePacketBufferError {
    #[error("End of buffer")]
    EndOfBuffer,
    #[error("Limit of {0} jumps exceeded")]
    LimitOfJumpsExceeded(usize),
    #[error("Single label exceeds 63 characters of length")]
    SingleLabelExceedsCharactersOfLength,
}

const MAX_BUFFER_SIZE: usize = 512;

#[derive(Debug)]
struct BytePacketBuffer {
    buffer: [u8; MAX_BUFFER_SIZE],
    position: usize,
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        Self {
            buffer: [0; MAX_BUFFER_SIZE],
            position: 0,
        }
    }
}

impl BytePacketBuffer {
    fn new() -> Self {
        Self::default()
    }

    fn step(&mut self, steps: usize) -> anyhow::Result<()> {
        self.position += steps;
        Ok(())
    }

    fn seek(&mut self, position: usize) -> anyhow::Result<()> {
        self.position = position;
        Ok(())
    }

    fn read(&mut self) -> anyhow::Result<u8> {
        if self.position >= MAX_BUFFER_SIZE {
            return Err(BytePacketBufferError::EndOfBuffer.into());
        }

        let result = self.buffer[self.position];
        self.position += 1;
        Ok(result)
    }

    fn get(&mut self, position: usize) -> anyhow::Result<u8> {
        if position >= MAX_BUFFER_SIZE {
            return Err(BytePacketBufferError::EndOfBuffer.into());
        }

        Ok(self.buffer[position])
    }

    fn get_range(&mut self, start: usize, len: usize) -> anyhow::Result<&[u8]> {
        if start + len >= MAX_BUFFER_SIZE {
            return Err(BytePacketBufferError::EndOfBuffer.into());
        }

        Ok(&self.buffer[start..start + len as usize])
    }

    fn read_u16(&mut self) -> anyhow::Result<u16> {
        Ok(((self.read()? as u16) << 8) | (self.read()? as u16))
    }

    fn read_u32(&mut self) -> anyhow::Result<u32> {
        Ok(((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32))
    }

    fn read_qname(&mut self, out: &mut String) -> anyhow::Result<()> {
        let mut position = self.position;

        let mut jumped = false;
        let max_jumps = 5;
        let mut jump_performed = 0;

        let mut delim = "";

        loop {
            if jump_performed > max_jumps {
                return Err(BytePacketBufferError::LimitOfJumpsExceeded(max_jumps).into());
            }

            let len = self.get(position)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(position + 2)?;
                }

                let b2 = self.get(position + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                position = offset as usize;

                jumped = true;
                jump_performed += 1;

                continue;
            } else {
                position += 1;

                if len == 0 {
                    break;
                }

                out.push_str(delim);
                out.push_str(
                    &String::from_utf8_lossy(self.get_range(position, len as usize)?)
                        .to_lowercase(),
                );

                delim = ".";
                position += len as usize;
            }
        }

        if !jumped {
            self.seek(position)?;
        }

        Ok(())
    }

    fn write(&mut self, value: u8) -> anyhow::Result<()> {
        if self.position >= MAX_BUFFER_SIZE {
            return Err(BytePacketBufferError::EndOfBuffer.into());
        }

        self.buffer[self.position] = value;
        self.position += 1;
        Ok(())
    }

    fn write_u8(&mut self, value: u8) -> anyhow::Result<()> {
        self.write(value)?;
        Ok(())
    }

    fn write_u16(&mut self, value: u16) -> anyhow::Result<()> {
        self.write((value >> 8) as u8)?;
        self.write((value & 0xFF) as u8)?;
        Ok(())
    }

    fn write_u32(&mut self, value: u32) -> anyhow::Result<()> {
        self.write(((value >> 24) & 0xFF) as u8)?;
        self.write(((value >> 16) & 0xFF) as u8)?;
        self.write(((value >> 8) & 0xFF) as u8)?;
        self.write((value & 0xFF) as u8)?;
        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> anyhow::Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                return Err(BytePacketBufferError::SingleLabelExceedsCharactersOfLength.into());
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;
        Ok(())
    }

    fn set(&mut self, position: usize, value: u8) -> anyhow::Result<()> {
        self.buffer[position] = value;
        Ok(())
    }

    fn set_u16(&mut self, position: usize, value: u16) -> anyhow::Result<()> {
        self.set(position, (value >> 8) as u8)?;
        self.set(position + 1, (value & 0xFF) as u8)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultCode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
}

impl From<u8> for ResultCode {
    fn from(num: u8) -> Self {
        match num {
            1 => ResultCode::FormErr,
            2 => ResultCode::ServFail,
            3 => ResultCode::NxDomain,
            4 => ResultCode::NotImp,
            5 => ResultCode::Refused,
            _ => ResultCode::NoError,
        }
    }
}

#[derive(Debug, Clone)]
struct DnsHeader {
    id: u16,
    recursion_desired: bool,
    truncated_message: bool,
    authoritative_answer: bool,
    opcode: u8,
    response: bool,
    rescode: ResultCode,
    checking_disabled: bool,
    authentic_data: bool,
    z: bool,
    recursion_available: bool,
    questions: u16,
    answers: u16,
    authoritative_entries: u16,
    resource_entries: u16,
}

impl Default for DnsHeader {
    fn default() -> Self {
        Self {
            id: 0,
            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,
            rescode: ResultCode::NoError,
            checking_disabled: false,
            authentic_data: false,
            z: false,
            recursion_available: false,
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }
}

impl DnsHeader {
    fn new() -> Self {
        Self::default()
    }

    fn read(&mut self, buffer: &mut BytePacketBuffer) -> anyhow::Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;
        self.rescode = ResultCode::from(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authentic_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    fn write(&mut self, buffer: &mut BytePacketBuffer) -> anyhow::Result<()> {
        buffer.write_u16(self.id)?;
        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7),
        )?;
        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authentic_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;
        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryType {
    A,
    Ns,
    Cname,
    Mx,
    Aaaa,
    Unknown(u16),
}

impl From<u16> for QueryType {
    fn from(num: u16) -> Self {
        match num {
            1 => QueryType::A,
            2 => QueryType::Ns,
            5 => QueryType::Cname,
            15 => QueryType::Mx,
            28 => QueryType::Aaaa,
            _ => QueryType::Unknown(num),
        }
    }
}

impl From<QueryType> for u16 {
    fn from(qtype: QueryType) -> Self {
        match qtype {
            QueryType::A => 1,
            QueryType::Ns => 2,
            QueryType::Cname => 5,
            QueryType::Mx => 15,
            QueryType::Aaaa => 28,
            QueryType::Unknown(num) => num,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsQuestion {
    name: String,
    qtype: QueryType,
}

impl DnsQuestion {
    fn new(name: String, qtype: QueryType) -> Self {
        DnsQuestion { name, qtype }
    }

    fn read(&mut self, buffer: &mut BytePacketBuffer) -> anyhow::Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from(buffer.read_u16()?);
        let _ = buffer.read_u16()?;

        Ok(())
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> anyhow::Result<()> {
        buffer.write_qname(&self.name)?;

        let type_num = self.qtype.into();
        buffer.write_u16(type_num)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DnsRecord {
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    Ns {
        domain: String,
        host: String,
        ttl: u32,
    },
    Cname {
        domain: String,
        host: String,
        ttl: u32,
    },
    Mx {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    Aaaa {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
    Unknown {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
}

impl DnsRecord {
    fn read(buffer: &mut BytePacketBuffer) -> anyhow::Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = qtype_num.into();
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;

                Ok(DnsRecord::A {
                    domain,
                    addr: Ipv4Addr::new(
                        ((raw_addr >> 24) & 0xFF) as u8,
                        ((raw_addr >> 16) & 0xFF) as u8,
                        ((raw_addr >> 8) & 0xFF) as u8,
                        (raw_addr & 0xFF) as u8,
                    ),
                    ttl,
                })
            }
            QueryType::Ns => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::Ns {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::Cname => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::Cname {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::Mx => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::Mx {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::Aaaa => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    (raw_addr1 & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    (raw_addr2 & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    (raw_addr3 & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    (raw_addr4 & 0xFFFF) as u16,
                );

                Ok(DnsRecord::Aaaa { domain, addr, ttl })
            }
            QueryType::Unknown(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::Unknown {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }

    fn write(&self, buffer: &mut BytePacketBuffer) -> anyhow::Result<usize> {
        let start = buffer.position;

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::Ns {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Ns.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let position = buffer.position;
                buffer.write_u16(0)?;
                buffer.write_qname(host)?;

                let size = buffer.position - (position + 2);
                buffer.set_u16(position, size as u16)?;
            }
            DnsRecord::Cname {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Cname.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let position = buffer.position;
                buffer.write_u16(0)?;
                buffer.write_qname(host)?;

                let size = buffer.position - (position + 2);
                buffer.set_u16(position, size as u16)?;
            }
            DnsRecord::Mx {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Mx.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let position = buffer.position;
                buffer.write_u16(0)?;
                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.position - (position + 2);
                buffer.set_u16(position, size as u16)?;
            }
            DnsRecord::Aaaa {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Aaaa.into())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for segment in &addr.segments() {
                    buffer.write_u16(*segment)?;
                }
            }
            DnsRecord::Unknown { .. } => {
                println!("Skipping record: {:?}", self)
            }
        }

        Ok(buffer.position - start)
    }
}

#[derive(Debug, Clone)]
struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    resources: Vec<DnsRecord>,
}

impl Default for DnsPacket {
    fn default() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }
}

impl DnsPacket {
    fn new() -> Self {
        Self::default()
    }

    fn from_buffer(buffer: &mut BytePacketBuffer) -> anyhow::Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::Unknown(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            result.answers.push(DnsRecord::read(buffer)?);
        }

        for _ in 0..result.header.authoritative_entries {
            result.authorities.push(DnsRecord::read(buffer)?);
        }

        for _ in 0..result.header.resource_entries {
            result.resources.push(DnsRecord::read(buffer)?);
        }

        Ok(result)
    }

    fn write(&mut self, buffer: &mut BytePacketBuffer) -> anyhow::Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }

        for record in &self.answers {
            record.write(buffer)?;
        }

        for record in &self.authorities {
            record.write(buffer)?;
        }

        for record in &self.resources {
            record.write(buffer)?;
        }

        Ok(())
    }

    fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().find_map(|record| match record {
            DnsRecord::A { addr, .. } => Some(*addr),
            _ => None,
        })
    }

    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DnsRecord::Ns { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(addr),
                        _ => None,
                    })
            })
            .copied()
            .next()
    }

    fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }
}

fn recursive_lookup(qname: &str, qtype: QueryType) -> anyhow::Result<DnsPacket> {
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    loop {
        println!("Attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let ns_copy = ns;

        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;

        if !response.answers.is_empty() && response.header.rescode == ResultCode::NoError {
            return Ok(response);
        }

        if response.header.rescode == ResultCode::NxDomain {
            return Ok(response);
        }

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;
            continue;
        }

        let new_ns = match response.get_unresolved_ns(qname) {
            Some(ns) => ns,
            None => return Ok(response),
        };
        let recursive_response = recursive_lookup(new_ns, QueryType::A)?;

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}

fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> anyhow::Result<DnsPacket> {
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

pub fn handle_query(socket: &UdpSocket) -> anyhow::Result<()> {
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

        if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
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
