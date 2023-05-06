use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Debug, Error)]
enum BytePacketBufferError {
    #[error("End of buffer")]
    EndOfBuffer,
    #[error("Limit of {0} jumps exceeded")]
    LimitOfJumpsExceeded(usize),
}

#[derive(Debug)]
pub struct BytePacketBuffer {
    pub buffer: [u8; 512],
    pub position: usize,
}

#[allow(clippy::new_without_default)]
impl BytePacketBuffer {
    pub fn new() -> Self {
        BytePacketBuffer {
            buffer: [0; 512],
            position: 0,
        }
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
        if self.position >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer.into());
        }

        let result = self.buffer[self.position];
        self.position += 1;
        Ok(result)
    }

    fn get(&mut self, position: usize) -> anyhow::Result<u8> {
        if position >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer.into());
        }

        Ok(self.buffer[position])
    }

    fn get_range(&mut self, start: usize, len: usize) -> anyhow::Result<&[u8]> {
        if start + len >= 512 {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
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
pub struct DnsHeader {
    pub id: u16,
    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8,
    pub response: bool,
    pub rescode: ResultCode,
    pub checking_disabled: bool,
    pub authentic_data: bool,
    pub z: bool,
    pub recursion_available: bool,
    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

#[allow(clippy::new_without_default)]
impl DnsHeader {
    pub fn new() -> Self {
        DnsHeader {
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

    pub fn read(&mut self, buf: &mut BytePacketBuffer) -> anyhow::Result<()> {
        self.id = buf.read_u16()?;

        let flags = buf.read_u16()?;
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

        self.questions = buf.read_u16()?;
        self.answers = buf.read_u16()?;
        self.authoritative_entries = buf.read_u16()?;
        self.resource_entries = buf.read_u16()?;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    Unknown(u16),
    A,
}

impl From<u16> for QueryType {
    fn from(num: u16) -> Self {
        match num {
            1 => QueryType::A,
            _ => QueryType::Unknown(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> Self {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buf: &mut BytePacketBuffer) -> anyhow::Result<()> {
        buf.read_qname(&mut self.name)?;
        self.qtype = QueryType::from(buf.read_u16()?);
        let _ = buf.read_u16()?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecord {
    Unknown {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> anyhow::Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from(qtype_num);
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
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

#[allow(clippy::new_without_default)]
impl DnsPacket {
    pub fn new() -> Self {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> anyhow::Result<DnsPacket> {
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
}
