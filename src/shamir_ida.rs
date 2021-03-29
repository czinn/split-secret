use std::io::{Read, Write, Cursor};
use std::cmp;

use crate::partitioner::{Partitioner, InputPartition, OutputPartition};
use crate::shamir::Shamir;
use crate::ida::Ida;
use crate::bit_pad::{PaddedReader, PaddedWriter};

use rand::rngs::OsRng;
use rand::RngCore;
use aes::Aes256;
use aes::cipher::{BlockCipher, NewBlockCipher};
use aes::cipher::generic_array::GenericArray;
use typenum::Unsigned;

pub struct ShamirIda {
    k: u8,
    shamir: Shamir,
    ida: Ida,
}

impl ShamirIda {
    pub fn new(k: u8) -> Self {
        assert!(k > 1);
        return ShamirIda { k, shamir: Shamir::new(k), ida: Ida::new(k) };
    }
}

const BUF_SIZE: usize = 1024;
/*
impl Partitioner for ShamirIda {
    fn split(&self, input: &mut impl Read, outputs: &mut Vec<OutputPartition>) {
        let mut key = [0u8, 32];
        OsRng.fill_bytes(&mut key);
        let cipher = Aes256::new(&GenericArray::from_slice(&key));

        // Write the key using Shamir's secret sharing
        self.shamir.split(&mut Cursor::new(key), outputs);

        let block_size = <<Aes256 as BlockCipher>::BlockSize as Unsigned>::to_usize();
        let mut input = PaddedReader::new(block_size, input);
        let target_read_size = BUF_SIZE - BUF_SIZE % block_size;

        loop {
            let mut read_size = 0;
            loop {
                match input.read(&mut read_buf[read_size..target_read_size]) {
                    Err(_) | Ok(0) => break,
                    Ok(block_read_size) =>
                    {
                        read_size += block_read_size;
                    }
                }
            }
            if read_size % k_usize != 0 {
                panic!("input was not correctly padded");
            }
            if read_size == 0 {
                break;
            }
    }

    fn join(&self, inputs: &mut Vec<InputPartition>, output: &mut impl Write) {
    }
} */
