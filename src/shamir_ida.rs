use std::io::{Read, Write, Cursor, Take};
use std::marker::PhantomData;

use crate::partitioner::{Partitioner, InputPartition, OutputPartition};
use crate::shamir::Shamir;
use crate::ida::Ida;
use crate::block_mode_streaming::{ReadStream, WriteStream, Direction};
use crate::padding_streaming::{PaddedReader, PaddedWriter, Op};

use rand::rngs::OsRng;
use rand::RngCore;
use cipher::{BlockCipher, NewBlockCipher};
use cipher::generic_array::GenericArray;
use block_modes::BlockMode;
use block_modes::block_padding::Padding;
use typenum::Unsigned;

pub struct ShamirIda<T, C, P>
where T: BlockMode<C, P>,
      C: BlockCipher + NewBlockCipher,
      P: Padding,
{
    shamir: Shamir,
    ida: Ida<P>,
    _t: PhantomData<T>,
    _c: PhantomData<C>,
    _p: PhantomData<P>,
}

impl<T, C, P> ShamirIda<T, C, P>
where T: BlockMode<C, P>,
      C: BlockCipher + NewBlockCipher,
      P: Padding,
{
    pub fn new(k: u8) -> Self {
        assert!(k > 1);
        return ShamirIda {
            shamir: Shamir::new(k),
            ida: Ida::new(k),
            _t: PhantomData,
            _c: PhantomData,
            _p: PhantomData,
        };
    }

    const BLOCK_SIZE: usize = <<C as BlockCipher>::BlockSize as Unsigned>::USIZE;
    const KEY_SIZE: usize = <<C as NewBlockCipher>::KeySize as Unsigned>::USIZE;
    const IV_SIZE: usize = <<T as BlockMode<C, P>>::IvSize as Unsigned>::USIZE;
}

impl<T, C, P> Partitioner for ShamirIda<T, C, P>
where T: BlockMode<C, P>,
      C: BlockCipher + NewBlockCipher,
      P: Padding,
{
    fn split<R: Read, W: Write>(&self, input: R, outputs: &mut [OutputPartition<W>]) {
        let mut key = vec![0u8; Self::KEY_SIZE + Self::IV_SIZE];
        OsRng.fill_bytes(&mut key[..]);
        let cipher = C::new(&GenericArray::from_slice(&key[..Self::KEY_SIZE]));
        let block_mode: T =
            T::new(cipher, &GenericArray::from_slice(&key[Self::KEY_SIZE..]));
        let mut input = PaddedReader::<P, _>::new(Self::BLOCK_SIZE, input, Op::Pad);
        let mut input = ReadStream::new(block_mode, &mut input, Direction::Encrypt);

        // Write the key using Shamir's secret sharing
        self.shamir.split(&mut Cursor::new(key), outputs);

        // Write the input using IDA
        self.ida.split(&mut input, outputs);
    }

    fn join<R: Read, W: Write>(&self, inputs: &mut [InputPartition<R>], output: W) {
        let mut key = Vec::new();
        let mut limited_inputs: Vec<(u8, Take<_>)> =
            inputs.iter_mut().map(|input| (input.x, (&mut input.reader).take((Self::KEY_SIZE + Self::IV_SIZE) as u64))).collect();
        self.shamir.join(&mut limited_inputs.iter_mut().map(|(x, reader)| InputPartition { x: *x, reader }).collect::<Vec<_>>(), &mut key);
        debug_assert!(key.len() == Self::KEY_SIZE + Self::IV_SIZE);

        let cipher = C::new(&GenericArray::from_slice(&key[..Self::KEY_SIZE]));
        let block_mode: T =
            T::new(cipher, &GenericArray::from_slice(&key[Self::KEY_SIZE..]));
        let mut output = PaddedWriter::<P, _>::new(Self::BLOCK_SIZE, output, Op::Unpad);
        let mut output = WriteStream::new(block_mode, &mut output, Direction::Decrypt);
        self.ida.join(inputs, &mut output);
        output.flush().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partitioner::test_join;

    use aes::{Aes256, Aes128};
    use block_padding::{Iso7816, Pkcs7};
    use block_modes::{Cbc, Cfb};

    fn base_two_of_three<T, C, P>()
    where T: BlockMode<C, P>,
          C: BlockCipher + NewBlockCipher,
          P: Padding,
    {
        let plaintext: Vec<u8> = "hello world".as_bytes().into();
        let shamir = ShamirIda::<T, C, P>::new(2);
        let mut partitions = shamir.split_in_memory(&plaintext, 3);
        for partition in partitions.iter() {
            assert_ne!(plaintext, partition.value);
        }
        test_join(&shamir, &mut partitions[..], 2, &plaintext);
    }

    #[test]
    fn two_of_three_cbc_aes256_iso() {
        base_two_of_three::<Cbc<_, _>, Aes256, Iso7816>();
    }

    #[test]
    fn two_of_three_cfb_aes128_pkcs() {
        base_two_of_three::<Cfb<_, _>, Aes128, Pkcs7>();
    }

    #[test]
    fn five_of_ten() {
        let plaintext: Vec<u8> = "this is a much longer text".as_bytes().into();
        let shamir = ShamirIda::<Cbc<_, _>, Aes256, Iso7816>::new(5);
        let mut partitions = shamir.split_in_memory(&plaintext, 10);
        for partition in partitions.iter() {
            assert_ne!(plaintext, partition.value);
        }
        test_join(&shamir, &mut partitions[..], 5, &plaintext);
    }
}
