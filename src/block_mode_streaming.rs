use std::cmp::min;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::marker::PhantomData;
use std::ops::Range;

use crate::utils::read_full;

use block_modes::cipher::block::{BlockCipher, NewBlockCipher};
use block_modes::cipher::generic_array::{ArrayLength, GenericArray};
use block_modes::{block_padding::Padding, BlockMode};
use core::slice;
use typenum::Unsigned;

pub enum Direction {
    Encrypt,
    Decrypt,
}

const BUF_SIZE: usize = 1024;

pub struct ReadStream<T, C, P, R>
where
    T: BlockMode<C, P>,
    C: BlockCipher + NewBlockCipher,
    P: Padding,
    R: Read,
{
    block_mode: T,
    reader: R,
    direction: Direction,
    buf: [u8; BUF_SIZE],
    filled_buf: Range<usize>,
    _c: PhantomData<C>,
    _p: PhantomData<P>,
}

fn to_blocks<N>(data: &mut [u8]) -> &mut [GenericArray<u8, N>]
where
    N: ArrayLength<u8>,
{
    let n = N::to_usize();
    debug_assert!(data.len() % n == 0);

    #[allow(unsafe_code)]
    unsafe {
        slice::from_raw_parts_mut(data.as_ptr() as *mut GenericArray<u8, N>, data.len() / n)
    }
}

impl<T, C, P, R> ReadStream<T, C, P, R>
where
    T: BlockMode<C, P>,
    C: BlockCipher + NewBlockCipher,
    P: Padding,
    R: Read,
{
    const BLOCK_SIZE: usize = <<C as BlockCipher>::BlockSize as Unsigned>::USIZE;

    pub fn new(block_mode: T, reader: R, direction: Direction) -> Self {
        let buf = [0u8; BUF_SIZE];
        Self {
            block_mode,
            reader,
            direction,
            buf,
            filled_buf: 0..0,
            _c: PhantomData,
            _p: PhantomData,
        }
    }

    fn fill_buf(&mut self) -> Result<usize> {
        let target_read_size = BUF_SIZE - BUF_SIZE % Self::BLOCK_SIZE;
        if self.filled_buf.len() != 0 {
            return Ok(self.filled_buf.len());
        }
        let read_size = read_full(&mut self.reader, &mut self.buf[0..target_read_size])?;
        if read_size % Self::BLOCK_SIZE != 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "number of bytes in reader was not a multiple of block size",
            ));
        }
        self.filled_buf = 0..read_size;

        // Encrypt or decrypt the bytes in the buffer
        let mut blocks = to_blocks(&mut self.buf[self.filled_buf.clone()]);
        match &self.direction {
            Direction::Encrypt => {
                T::encrypt_blocks(&mut self.block_mode, &mut blocks);
            }
            Direction::Decrypt => {
                T::decrypt_blocks(&mut self.block_mode, &mut blocks);
            }
        }
        Ok(self.filled_buf.len())
    }
}

impl<T, C, P, R> Read for ReadStream<T, C, P, R>
where
    T: BlockMode<C, P>,
    C: BlockCipher + NewBlockCipher,
    P: Padding,
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut read_size = 0;
        loop {
            let local_read_size = self.fill_buf()?;
            if local_read_size == 0 {
                break Ok(read_size);
            }
            if buf.len() - read_size >= local_read_size {
                buf[read_size..read_size + local_read_size]
                    .copy_from_slice(&self.buf[self.filled_buf.clone()]);
                read_size += local_read_size;
                self.filled_buf = 0..0;
            } else {
                let read_to = self.filled_buf.start + buf.len() - read_size;
                buf[read_size..].copy_from_slice(&self.buf[self.filled_buf.start..read_to]);
                self.filled_buf = read_to..self.filled_buf.end;
                break Ok(buf.len());
            }
        }
    }
}

pub struct WriteStream<T, C, P, W>
where
    T: BlockMode<C, P>,
    C: BlockCipher + NewBlockCipher,
    P: Padding,
    W: Write,
{
    block_mode: T,
    writer: W,
    direction: Direction,
    buf: Vec<u8>,
    buf_bytes: usize,
    _c: PhantomData<C>,
    _p: PhantomData<P>,
}

impl<T, C, P, W> WriteStream<T, C, P, W>
where
    T: BlockMode<C, P>,
    C: BlockCipher + NewBlockCipher,
    P: Padding,
    W: Write,
{
    const BLOCK_SIZE: usize = <<C as BlockCipher>::BlockSize as Unsigned>::USIZE;

    pub fn new(block_mode: T, writer: W, direction: Direction) -> Self {
        Self {
            block_mode,
            writer,
            direction,
            buf: vec![0u8; Self::BLOCK_SIZE * 8],
            buf_bytes: 0,
            _c: PhantomData,
            _p: PhantomData,
        }
    }
}

impl<T, C, P, W> Write for WriteStream<T, C, P, W>
where
    T: BlockMode<C, P>,
    C: BlockCipher + NewBlockCipher,
    P: Padding,
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut bytes_written = 0;
        while bytes_written < buf.len() {
            // Fill up the local buffer with bytes from the read buffer
            let bytes_to_copy_into_local_buf =
                min(self.buf.len() - self.buf_bytes, buf.len() - bytes_written);
            self.buf[self.buf_bytes..self.buf_bytes + bytes_to_copy_into_local_buf]
                .copy_from_slice(&buf[bytes_written..bytes_written + bytes_to_copy_into_local_buf]);
            self.buf_bytes += bytes_to_copy_into_local_buf;
            bytes_written += bytes_to_copy_into_local_buf;

            // Process and write as many blocks from the write buffer as possible
            let bytes_to_write_immediately = self.buf_bytes - self.buf_bytes % Self::BLOCK_SIZE;
            let mut blocks = to_blocks(&mut self.buf[..bytes_to_write_immediately]);
            match &self.direction {
                Direction::Encrypt => T::encrypt_blocks(&mut self.block_mode, &mut blocks),
                Direction::Decrypt => T::decrypt_blocks(&mut self.block_mode, &mut blocks),
            };
            self.writer
                .write_all(&self.buf[..bytes_to_write_immediately])?;
            // Move any remaining bytes to the beginning of the buffer
            self.buf
                .copy_within(bytes_to_write_immediately..self.buf_bytes, 0);
            self.buf_bytes -= bytes_to_write_immediately;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        if self.buf_bytes != 0 {
            Err(Error::new(
                ErrorKind::InvalidData,
                "the number of bytes written was not a multiple of block size",
            ))
        } else {
            self.writer.flush()
        }
    }
}
