use std::io::{Read, Write, Cursor};

use crate::partitioner::{Partitioner, InputPartition, OutputPartition};
use crate::shamir::Shamir;
use crate::ida::Ida;
use crate::block_mode_streaming::{ReadStream, Direction};

use rand::rngs::OsRng;
use rand::RngCore;
use aes::Aes256;
use aes::cipher::NewBlockCipher;
use aes::cipher::generic_array::GenericArray;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Iso7816;

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

impl Partitioner for ShamirIda {
    fn split(&self, input: &mut impl Read, outputs: &mut Vec<OutputPartition>) {
        let mut key = [0u8, 64];
        OsRng.fill_bytes(&mut key);
        let cipher = Aes256::new(&GenericArray::from_slice(&key[..32]));
        let block_mode: Cbc<Aes256, Iso7816> = Cbc::new(cipher, &GenericArray::from_slice(&key[32..]));
        let mut input = ReadStream::new(block_mode, input, Direction::Encrypt);

        // Write the key using Shamir's secret sharing
        self.shamir.split(&mut Cursor::new(key), outputs);

        // Write the input using IDA
        self.ida.split(&mut input, outputs);
    }

    fn join(&self, inputs: &mut Vec<InputPartition>, output: &mut impl Write) {
    }
}
