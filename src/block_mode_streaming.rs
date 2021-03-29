use std::io::{Read, Write, Result};
use std::marker::{PhantomData};

use block_modes::cipher::generic_array::GenericArray;
use block_modes::cipher::block::{BlockCipher, NewBlockCipher};
use block_modes::{BlockMode, block_padding::Padding};
use typenum::{Unsigned, U8, op};

pub enum Direction {
    Encrypt,
    Decrypt,
}

pub struct ReadStream<'a, T, C, P>
where T: BlockMode<C, P>,
      C: BlockCipher + NewBlockCipher,
      P: Padding,
{
    block_mode: T,
    _c: PhantomData<C>,
    _p: PhantomData<P>,
    reader: &'a mut dyn Read,
    direction: Direction,
    foo: [u8; <C as BlockCipher>::BlockSize::ArrayType::USIZE],
    //buf: GenericArray<u8, op!(<C as BlockCipher>::BlockSize * U8)>,
    buf: [u8; <U8 as Unsigned>::USIZE],
    filled_buf: &'a [u8],
}

/*
impl<'a, T, C, P> ReadStream<'a, T, C, P>
where T: BlockMode<C, P>,
      C: BlockCipher + NewBlockCipher,
      P: Padding,
{
    const BLOCK_SIZE: usize = <<C as BlockCipher>::BlockSize as Unsigned>::to_usize();

    pub fn new(block_mode: T, reader: &'a mut dyn Read, direction: Direction) {
        let buf = [0u8; Self::BLOCK_SIZE];
        Self { block_mode, reader, direction, buf, filled_buf: &buf[0..0] }
    }

    fn fill_buff(&mut self) -> Result<usize> {
        if self.filled_buf.len() != 0 {
            return Ok(self.filled_buf.len());
        }
        let mut read_size = 0;
        loop {
            match self.reader.read(self.buf[read_size..self.buf.len() - Self::BLOCK_SIZE])? {
                0 => break,
                Ok(n) => read_size += n,
            }
        }
        // Encrypt or decrypt the bytes in the buffer
        match self.direction {
            Encrypt => {
                self.filled_buf = P::pad(&mut self.buf, read_size, Self::BLOCK_SIZE).unwrap();
                let mut blocks = self.filled_buf.chunks(Self::BLOCK_SIZE).map(|block| GenericArray::from_slice(block)).collect();
                T::encrypt_blocks(&mut self.block_mode, &mut blocks);
            },
            Decrypt => {
                self.filled_buf = &self.buf[..read_size];
                let mut blocks = self.filled_buf.chunks(Self::BLOCK_SIZE).map(|block| GenericArray::from_slice(block)).collect();
                T::decrypt_blocks(&mut self.block_mode, &mut blocks);
                self.filled_buf = P::unpad(self.filled_buf).unwrap();
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
            buf[..read_size].copy_from_slice(self.filled_buf);
            self.filled_buf = self.buf[0..0];
            Ok(read_size)
        } else {
            buf.copy_from_slice(self.filled_buf[..buf.len()]);
            self.filled_buf = self.filled_buf[buf.len()..];
            Ok(buf.len())
        }
    }
} */
