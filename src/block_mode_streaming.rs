use std::io::{Read, Write, Result};
use std::ops::Range;
use std::marker::{PhantomData};

use block_modes::cipher::generic_array::{GenericArray, ArrayLength};
use block_modes::cipher::block::{BlockCipher, NewBlockCipher};
use block_modes::{BlockMode, block_padding::Padding};
use typenum::Unsigned;
use core::slice;

pub enum Direction {
    Encrypt,
    Decrypt,
}

const BUF_SIZE: usize = 1024;

pub struct ReadStream<'a, T, C, P>
where T: BlockMode<C, P>,
      C: BlockCipher + NewBlockCipher,
      P: Padding,
{
    block_mode: T,
    reader: &'a mut dyn Read,
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

impl<'a, T, C, P> ReadStream<'a, T, C, P>
where T: BlockMode<C, P>,
      C: BlockCipher + NewBlockCipher,
      P: Padding,
{
    const BLOCK_SIZE: usize = <<C as BlockCipher>::BlockSize as Unsigned>::USIZE;

    pub fn new(block_mode: T, reader: &'a mut dyn Read, direction: Direction) -> Self {
        let buf = [0u8; BUF_SIZE];
        Self { block_mode, reader, direction, buf, filled_buf: 0..0, _c: PhantomData, _p: PhantomData }
    }

    fn fill_buf(&mut self) -> Result<usize> {
        let usable_buf_size = BUF_SIZE - BUF_SIZE % Self::BLOCK_SIZE;
        if self.filled_buf.len() != 0 {
            return Ok(self.filled_buf.len());
        }
        let mut read_size = 0;
        loop {
            match self.reader.read(&mut self.buf[read_size..usable_buf_size - Self::BLOCK_SIZE])? {
                0 => break,
                n => read_size += n,
            }
        }
        // Encrypt or decrypt the bytes in the buffer
        match &self.direction {
            Direction::Encrypt => {
                self.filled_buf = 0..P::pad(&mut self.buf, read_size, Self::BLOCK_SIZE).unwrap().len();
                let mut blocks = to_blocks(&mut self.buf[self.filled_buf.clone()]);
                T::encrypt_blocks(&mut self.block_mode, &mut blocks);
            },
            Direction::Decrypt => {
                self.filled_buf = 0..read_size;
                let mut blocks = to_blocks(&mut self.buf[self.filled_buf.clone()]);
                T::decrypt_blocks(&mut self.block_mode, &mut blocks);
                self.filled_buf = 0..P::unpad(&mut self.buf[self.filled_buf.clone()]).unwrap().len();
            },
        }
        Ok(self.filled_buf.len())
    }
}

impl<'a, T, C, P> Read for ReadStream<'a, T, C, P>
where T: BlockMode<C, P>,
      C: BlockCipher + NewBlockCipher,
      P: Padding,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read_size = self.fill_buf()?;
        if buf.len() >= read_size {
            buf[..read_size].copy_from_slice(&self.buf[self.filled_buf.clone()]);
            self.filled_buf = 0..0;
            Ok(read_size)
        } else {
            let read_to = self.filled_buf.start + buf.len();
            buf.copy_from_slice(&self.buf[self.filled_buf.start..read_to]);
            self.filled_buf = read_to..self.filled_buf.end;
            Ok(buf.len())
        }
    }
}

pub struct WriteStream<'a, T, C, P>
where T: BlockMode<C, P>,
      C: BlockCipher + NewBlockCipher,
      P: Padding,
{
    block_mode: T,
    writer: &'a mut dyn Write,
    direction: Direction,
    buf: Vec<u8>,
    buf_bytes: usize,
    _c: PhantomData<C>,
    _p: PhantomData<P>,
}

impl<'a, T, C, P> WriteStream<'a, T, C, P>
where T: BlockMode<C, P>,
      C: BlockCipher + NewBlockCipher,
      P: Padding,
{
    const BLOCK_SIZE: usize = <<C as BlockCipher>::BlockSize as Unsigned>::USIZE;

    pub fn new(block_mode: T, writer: &'a mut dyn Write, direction: Direction) -> Self {
        Self { block_mode, writer, direction, buf: vec![u8; Self::BLOCK_SIZE], buf_bytes: 0, _c: PhantomData, _p: PhantomData }
    }
}

impl<'a, T, C, P> Write for WriteStream<'a, T, C, P>
where T: BlockMode<C, P>,
      C: BlockCipher + NewBlockCipher,
      P: Padding,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let writeable_bytes = self.buf_bytes + buf.len();
        if writeable_bytes < Self::BLOCK_SIZE {
            // Copy bytes into the local buffer
            self.buf[self.buf_bytes..self.buf_bytes + buf.len()].copy_from_slice(buf);
            self.buf_bytes += buf.len();
            return Ok(buf.len());
        }
        let bytes_to_copy_into_local_buf = Self::BLOCK_SIZE - self.buf_bytes;
        self.buf[self.buf_bytes..self.buf.len()].copy_from_slice(buf[..bytes_to_copy_into_local_buf]);
        // Process and write this single block
        match &self.direction {
            Direction::Encrypt => {
                T::encrypt_blocks(&mut self.block_mode, &mut to_blocks(self.buf[..]));
                self.writer.write_all(&self.buf[..])?;
            }
            Direction::Decrypt => {

            }
        }
    }
}
