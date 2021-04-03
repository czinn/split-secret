use std::io::{Read, Write, Cursor, Take};

use crate::partitioner::{Partitioner, InputPartition, OutputPartition};
use crate::shamir::Shamir;
use crate::ida::Ida;
use crate::block_mode_streaming::{ReadStream, WriteStream, Direction};
use crate::padding_streaming::{PaddedReader, PaddedWriter, Op};

use rand::rngs::OsRng;
use rand::RngCore;
use aes::Aes256;
use aes::cipher::{BlockCipher, NewBlockCipher};
use aes::cipher::generic_array::GenericArray;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Iso7816;
use typenum::Unsigned;

pub struct ShamirIda {
    shamir: Shamir,
    ida: Ida,
}

impl ShamirIda {
    pub fn new(k: u8) -> Self {
        assert!(k > 1);
        return ShamirIda { shamir: Shamir::new(k), ida: Ida::new(k) };
    }

    const BLOCK_SIZE: usize = <<Aes256 as BlockCipher>::BlockSize as Unsigned>::USIZE;
}

impl Partitioner for ShamirIda {
    fn split<R: Read, W: Write>(&self, input: R, outputs: &mut [OutputPartition<W>]) {
        let mut key = [0u8; 48];
        OsRng.fill_bytes(&mut key[..]);
        let cipher = Aes256::new(&GenericArray::from_slice(&key[..32]));
        let block_mode: Cbc<Aes256, Iso7816> = Cbc::new(cipher, &GenericArray::from_slice(&key[32..]));
        let mut input = PaddedReader::<Iso7816, _>::new(Self::BLOCK_SIZE, input, Op::Pad);
        let mut input = ReadStream::new(block_mode, &mut input, Direction::Encrypt);

        // Write the key using Shamir's secret sharing
        self.shamir.split(&mut Cursor::new(key), outputs);

        // Write the input using IDA
        self.ida.split(&mut input, outputs);
    }

    fn join<R: Read, W: Write>(&self, inputs: &mut [InputPartition<R>], output: W) {
        let mut key = Vec::new();
        let mut limited_inputs: Vec<(u8, Take<_>)> = inputs.iter_mut().map(|input| (input.x, (&mut input.reader).take(48))).collect();
        self.shamir.join(&mut limited_inputs.iter_mut().map(|(x, reader)| InputPartition { x: *x, reader }).collect::<Vec<_>>(), &mut key);
        assert!(key.len() == 48);

        let cipher = Aes256::new(&GenericArray::from_slice(&key[..32]));
        let block_mode: Cbc<Aes256, Iso7816> = Cbc::new(cipher, &GenericArray::from_slice(&key[32..]));
        let mut output = PaddedWriter::<Iso7816, _>::new(Self::BLOCK_SIZE, output, Op::Unpad);
        let mut output = WriteStream::new(block_mode, &mut output, Direction::Decrypt);
        self.ida.join(inputs, &mut output);
        output.flush().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partitioner::test_join;

    #[test]
    fn two_of_three() {
        let plaintext: Vec<u8> = "hello world".as_bytes().into();
        let shamir = ShamirIda::new(2);
        let mut partitions = shamir.split_in_memory(&plaintext, 3);
        for partition in partitions.iter() {
            assert_ne!(plaintext, partition.value);
        }
        test_join(&shamir, &mut partitions[..], 2, &plaintext);
    }

    #[test]
    fn five_of_ten() {
        let plaintext: Vec<u8> = "this is a much longer text".as_bytes().into();
        let shamir = ShamirIda::new(5);
        let mut partitions = shamir.split_in_memory(&plaintext, 10);
        for partition in partitions.iter() {
            assert_ne!(plaintext, partition.value);
        }
        test_join(&shamir, &mut partitions[..], 5, &plaintext);
    }
}
