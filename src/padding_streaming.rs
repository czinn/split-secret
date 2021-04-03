use std::io::{Read, Write, Result, Error, ErrorKind};
use std::marker::PhantomData;
use std::cmp::min;

use crate::utils::read_full;

use block_padding::Padding;

// mod_positive(n, k) == n (mod k); 1 <= mod_positive(n, k) <= k
fn mod_positive(n: usize, k: usize) -> usize {
    if n % k == 0 {
        k
    } else {
        n % k
    }
}

pub enum Op {
    Pad,
    Unpad,
}

pub struct PaddedReader<P, R>
where P: Padding,
      R: Read,
{
    _p: PhantomData<P>,
    block_size: usize,
    reader: R,
    op: Op,
    buf: Vec<u8>,
    bytes_read: usize,
    // If output_buf is Some, then we've reached the end of the wrapped reader and applied the
    // operation, and all that is left to do is output these remaining bytes and finish.
    output_buf: Option<Vec<u8>>,
}

impl<P, R> PaddedReader<P, R>
where P: Padding,
      R: Read,
{
    pub fn new(block_size: usize, reader: R, op: Op) -> Self {
        Self { _p: PhantomData, block_size, reader, op, buf: vec![0u8; block_size], bytes_read: 0, output_buf: None }
    }
}

impl<P, R> Read for PaddedReader<P, R>
where P: Padding,
      R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let buf_len = buf.len();
        if buf_len == 0 {
            return Ok(0);
        }

        match &self.output_buf {
            Some(output_buf) => {
                let read_size = min(output_buf.len(), buf_len);
                buf[..read_size].copy_from_slice(&output_buf[..read_size]);
                self.output_buf = Some(output_buf[read_size..].to_vec());
                return Ok(read_size);
            }
            None => {}
        }

        let buf_bytes = min(self.block_size, self.bytes_read);
        
        let mut bytes_here = buf_bytes;
        if buf_len < buf_bytes {
            // Fill buf with bytes from self.buf
            buf[..].copy_from_slice(&self.buf[..buf_len]);
            // Move remaining bytes in self.buf backwards
            self.buf.copy_within(buf_len..buf_bytes, 0);
            // Try to fill up the rest of self.buf
            bytes_here += read_full(&mut self.reader, &mut self.buf[buf_bytes - buf_len..])?;
        } else {
            // Copy over all the bytes from self.buf
            buf[..buf_bytes].copy_from_slice(&self.buf[..buf_bytes]);
            // Try to fill up the rest of buf and self.buf
            bytes_here += read_full(&mut self.reader, &mut buf[buf_bytes..])?;
            bytes_here += read_full(&mut self.reader, &mut self.buf[..])?;
        }
        self.bytes_read += bytes_here - buf_bytes;

        if bytes_here == 0 {
            // Wrapped reader must have been empty.
            return Ok(0);
        }

        if bytes_here == buf_len + self.buf.len() {
            // The internal buffer is full, which means everything in buf is safe to read.
            Ok(buf_len)
        } else {
            // We've reached the end of the wrapped reader. Add or remove padding and store any
            // remaining bytes to be read in output_buf.

            // Figure out where the penultimate block ends, and copy everything after that into
            // last_block.
            let mut last_block = vec![0u8; self.block_size * 2];
            let last_block_size = mod_positive(self.bytes_read, self.block_size);
            let mut read_size = bytes_here - last_block_size;
            let last_block_bytes_in_buf = min(buf_len, bytes_here) - read_size;
            last_block[..last_block_bytes_in_buf].copy_from_slice(&buf[read_size..read_size + last_block_bytes_in_buf]);
            if last_block_bytes_in_buf < last_block_size {
                last_block[last_block_bytes_in_buf..last_block_size]
                    .copy_from_slice(&self.buf[..last_block_size - last_block_bytes_in_buf]);
            }

            // Apply the padding or unpadding to last block
            let output =
                match &self.op {
                    Op::Pad => {
                        P::pad(&mut last_block[..], last_block_size, self.block_size).map_err(|_| Error::new(ErrorKind::InvalidData, "error padding data"))?
                    },
                    Op::Unpad => {
                        if last_block_size != self.block_size {
                            return Err(Error::new(ErrorKind::InvalidData, "input reader did not contain a multiple of block_size bytes"));
                        }
                        P::unpad(&last_block[..last_block_size]).map_err(|_| Error::new(ErrorKind::InvalidData, "error unpadding data"))?
                    },
                };

            // Copy as much as possible into buf, save the rest in self.output_buf
            let bytes_copied_to_buf = min(buf_len - read_size, output.len());
            buf[read_size..read_size + bytes_copied_to_buf].copy_from_slice(&output[..bytes_copied_to_buf]);
            read_size += bytes_copied_to_buf;
            self.output_buf = Some(output[bytes_copied_to_buf..].to_vec());

            Ok(read_size)
        }
    }
}

pub struct PaddedWriter<P, W>
where P: Padding,
      W: Write,
{
    _p: PhantomData<P>,
    block_size: usize,
    writer: W,
    op: Op,
    buf: Vec<u8>,
    bytes_written: usize,
    flushed: bool,
}

impl<P, W> PaddedWriter<P, W>
where P: Padding,
      W: Write,
{
    pub fn new(block_size: usize, writer: W, op: Op) -> Self {
        Self { _p: PhantomData, block_size, writer, op, buf: vec![0u8; block_size], bytes_written: 0, flushed: false }
    }
}

impl<P, W> Write for PaddedWriter<P, W>
where P: Padding,
      W: Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let bytes_buffered = min(self.block_size, self.bytes_written);
        let writeable_bytes = bytes_buffered + buf.len();
        if writeable_bytes < self.block_size {
            // Copy bytes into the local buffer
            self.buf[bytes_buffered..bytes_buffered + buf.len()].copy_from_slice(buf);
            self.bytes_written += buf.len();
            return Ok(buf.len());
        }
        let bytes_to_write = writeable_bytes - self.block_size;
        if writeable_bytes - self.block_size < bytes_buffered {
            // Write out bytes from the internal buffer, then move remaining bytes to the front of
            // the buffer and save bytes from buf.
            self.writer.write_all(&self.buf[0..bytes_to_write])?;
            self.buf.copy_within(bytes_to_write..bytes_buffered, 0);
            let bytes_remaining = bytes_buffered - bytes_to_write;
            self.buf[bytes_remaining..bytes_remaining + buf.len()].copy_from_slice(buf);
            self.bytes_written += buf.len();
            Ok(buf.len())
        } else {
            // Write out everything from the internal buffer, and all but the last block_size
            // bytes from buf.
            self.writer.write_all(&self.buf[..bytes_buffered])?;
            self.writer.write_all(&buf[0..buf.len() - self.block_size])?;
            self.buf[..].copy_from_slice(&buf[buf.len() - self.block_size..]);
            self.bytes_written += buf.len();
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> Result<()> {
        if self.flushed {
            return Ok(());
        }
        self.flushed = true;
        let last_block_size = mod_positive(self.bytes_written, self.block_size);
        let mut last_block = vec![0u8; self.block_size * 2];
        last_block[..last_block_size].copy_from_slice(&self.buf[..last_block_size]);
        let to_write =
            match &self.op {
                Op::Pad => {
                    P::pad(&mut last_block[..], last_block_size, self.block_size).map_err(|_| Error::new(ErrorKind::InvalidData, "error padding data"))?
                },
                Op::Unpad => {
                    if last_block_size % self.block_size != 0 {
                        return Err(Error::new(ErrorKind::InvalidData, "number of bytes written was not a multiple of block_size"));
                    }
                    P::unpad(&last_block[..last_block_size]).map_err(|_| Error::new(ErrorKind::InvalidData, "error unpadding data"))?
                },
            };
        self.writer.write_all(&to_write)?;
        self.writer.flush()
    }
}
