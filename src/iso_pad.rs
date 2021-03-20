use std::io::{Read, Write, Result};
use std::cmp::min;

pub struct PaddedReader<'a> {
    pub block_size: usize,
    pub reader: &'a mut dyn Read,
    pub bytes_read: usize,
    pub header_byte_read: bool,
}

impl<'a> PaddedReader<'a> {
    pub fn new(block_size: usize, reader: &'a mut dyn Read) -> Self {
        Self { block_size, reader, bytes_read: 0, header_byte_read: false }
    }
}

impl<'a> Read for PaddedReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.reader.read(buf) {
            Err(e) => Err(e),
            Ok(0) =>
            {
                if buf.len() == 0 {
                    return Ok(0);
                }
                let mut read_size = 0;
                if !self.header_byte_read {
                    buf[0] = 0x80u8;
                    self.header_byte_read = true;
                    read_size += 1;
                }
                let extra_bytes = (self.bytes_read + read_size) % self.block_size;
                if extra_bytes != 0 {
                    let zeroes_to_write = min(self.block_size - extra_bytes, buf.len() - read_size);
                    buf[read_size..(read_size + zeroes_to_write)].fill(0x00u8);
                    read_size += zeroes_to_write;
                }
                self.bytes_read += read_size;
                Ok(read_size)
            }
            Ok(read_size) => {
                self.bytes_read += read_size;
                Ok(read_size)
            }
        }
    }
}

pub struct PaddedWriter<'a> {
    pub block_size: usize,
    pub writer: &'a mut dyn Write,
    pub bytes_written: usize,
    pub last_block: Vec<u8>,
}

impl<'a> PaddedWriter<'a> {
    pub fn new(block_size: usize, writer: &'a mut dyn Write) -> Self {
        Self { block_size, writer, bytes_written: 0, last_block: vec![0u8; block_size] }
    }
}

impl<'a> Write for PaddedWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let bytes_buffered = min(self.block_size, self.bytes_written);
        let writeable_bytes = bytes_buffered + buf.len();
        if writeable_bytes < self.block_size {
            // Copy bytes into the local buffer
            self.last_block[bytes_buffered..bytes_buffered + buf.len()].copy_from_slice(buf);
            self.bytes_written += buf.len();
            return Ok(buf.len());
        }
        let bytes_to_write = writeable_bytes - self.block_size;
        if writeable_bytes - self.block_size < bytes_buffered {
            // Write out bytes from the internal buffer, then move remaining bytes to the front of
            // the buffer and save bytes from buf.
            self.writer.write_all(&self.last_block[0..bytes_to_write])?;
            self.last_block.copy_within(bytes_to_write..bytes_buffered, 0);
            let bytes_remaining = bytes_buffered - bytes_to_write;
            self.last_block[bytes_remaining..bytes_remaining + buf.len()].copy_from_slice(buf);
            self.bytes_written += buf.len();
            Ok(buf.len())
        } else {
            // Write out everything from the internal buffer, and all but the last block_size
            // bytes from buf.
            self.writer.write_all(&self.last_block[..bytes_buffered])?;
            self.writer.write_all(&buf[0..buf.len() - self.block_size])?;
            self.last_block[..].copy_from_slice(&buf[buf.len() - self.block_size..]);
            self.bytes_written += buf.len();
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> Result<()> {
        if self.bytes_written % self.block_size != 0 {
            panic!("invalid padding");
        }
        if self.bytes_written == 0 {
            return Ok(());
        }
        // At this point we can assume that is full.
        // Iterate backwards until we find a 0x80
        let mut padding_index: usize = 0;
        for (i, &byte) in self.last_block.iter().enumerate().rev() {
            if byte == 0x80u8 {
                padding_index = i;
                break;
            } else if byte == 0x00u8 {
                continue;
            } else {
                panic!("invalid padding");
            }
        }
        self.writer.write_all(&self.last_block[..padding_index]).unwrap();
        self.writer.flush()
    }
}
