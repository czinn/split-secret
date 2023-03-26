use std::cmp::min;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::marker::PhantomData;
use std::ops::Range;

use crate::padding_streaming::{Op, PaddedReader, PaddedWriter};
use crate::utils::read_full;

use cipher::{BlockSizeUser, BlockEncryptMut, BlockDecryptMut, Unsigned};
use block_padding::RawPadding;
use cipher::generic_array::{ArrayLength, GenericArray};
use core::slice;

const BUF_SIZE: usize = 1024;

pub struct EncryptReadStream<C, P, R>
where
    C: BlockEncryptMut,
    P: RawPadding,
    R: Read,
{
    cipher: C,
    reader: PaddedReader<P, R>,
    buf: [u8; BUF_SIZE],
    filled_buf: Range<usize>,
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

impl<C, P, R> EncryptReadStream<C, P, R>
where
    C: BlockEncryptMut,
    P: RawPadding,
    R: Read,
{
    const BLOCK_SIZE: usize = <C as BlockSizeUser>::BlockSize::USIZE;

    pub fn new(cipher: C, reader: R) -> Self {
        let buf = [0u8; BUF_SIZE];
        let reader = PaddedReader::<P, _>::new(Self::BLOCK_SIZE, reader, Op::Pad);
        Self {
            cipher,
            reader,
            buf,
            filled_buf: 0..0,
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
        self.cipher.encrypt_blocks_mut(&mut blocks);
        Ok(self.filled_buf.len())
    }
}

impl<C, P, R> Read for EncryptReadStream<C, P, R>
where
    C: BlockEncryptMut,
    P: RawPadding,
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

pub struct DecryptWriteStream<C, P, W>
where
    C: BlockDecryptMut,
    P: RawPadding,
    W: Write,
{
    cipher: C,
    writer: PaddedWriter<P, W>,
    buf: Vec<u8>,
    buf_bytes: usize,
    _p: PhantomData<P>,
}

impl<C, P, W> DecryptWriteStream<C, P, W>
where
    C: BlockDecryptMut,
    P: RawPadding,
    W: Write,
{
    const BLOCK_SIZE: usize = <C as BlockSizeUser>::BlockSize::USIZE;

    pub fn new(cipher: C, writer: W) -> Self {
        let writer = PaddedWriter::<P, _>::new(Self::BLOCK_SIZE, writer, Op::Unpad);
        Self {
            cipher,
            writer,
            buf: vec![0u8; Self::BLOCK_SIZE * 8],
            buf_bytes: 0,
            _p: PhantomData,
        }
    }
}

impl<C, P, W> Write for DecryptWriteStream<C, P, W>
where
    C: BlockDecryptMut,
    P: RawPadding,
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
            self.cipher.decrypt_blocks_mut(&mut blocks);
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
