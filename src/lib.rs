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
    buf: [u8; 512],
    pos: usize,
}

#[allow(clippy::new_without_default)]
impl BytePacketBuffer {
    pub fn new() -> Self {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) -> anyhow::Result<()> {
        self.pos += steps;
        Ok(())
    }

    fn seek(&mut self, pos: usize) -> anyhow::Result<()> {
        self.pos = pos;
        Ok(())
    }

    fn read(&mut self) -> anyhow::Result<u8> {
        if self.pos >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer.into());
        }

        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    fn get(&mut self, pos: usize) -> anyhow::Result<u8> {
        if pos >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer.into());
        }

        Ok(self.buf[self.pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> anyhow::Result<&[u8]> {
        if start + len >= 512 {
            return Err(BytePacketBufferError::EndOfBuffer.into());
        }

        Ok(&self.buf[start..start + len as usize])
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

    fn read_qname(&mut self, outstr: &mut String) -> anyhow::Result<()> {
        let mut pos = self.pos();

        let mut jumped = false;
        let max_jumps = 5;
        let mut jump_performed = 0;

        let mut delim = "";

        loop {
            if jump_performed > max_jumps {
                return Err(BytePacketBufferError::LimitOfJumpsExceeded(max_jumps).into());
            }

            let len = self.get(pos)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                jumped = true;
                jump_performed += 1;

                continue;
            } else {
                pos += 1;

                if len == 0 {
                    break;
                }

                outstr.push_str(delim);

                let str_buf = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buf).to_lowercase());

                delim = ".";

                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}
