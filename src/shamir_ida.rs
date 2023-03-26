use std::io::{Cursor, Read, Take, Write};
use std::marker::PhantomData;

use crate::block_mode_streaming::{DecryptWriteStream, EncryptReadStream};
use crate::ida::Ida;
use crate::partitioner::{InputPartition, OutputPartition, Partitioner};
use crate::shamir::Shamir;

use block_padding::RawPadding;
use cipher::{KeyIvInit, BlockEncryptMut, BlockDecryptMut};
use rand::rngs::OsRng;

pub struct ShamirIda<E, D, P>
where
    E: KeyIvInit + BlockEncryptMut,
    D: KeyIvInit + BlockDecryptMut,
    P: RawPadding,
{
    shamir: Shamir,
    ida: Ida<P>,
    _e: PhantomData<E>,
    _d: PhantomData<D>,
    _p: PhantomData<P>,
}

impl<E, D, P> ShamirIda<E, D, P>
where
    E: KeyIvInit + BlockEncryptMut,
    D: KeyIvInit + BlockDecryptMut,
    P: RawPadding,
{
    pub fn new(k: u8) -> Self {
        assert!(k > 1);
        return ShamirIda {
            shamir: Shamir::new(k),
            ida: Ida::new(k),
            _e: PhantomData,
            _d: PhantomData,
            _p: PhantomData,
        };
    }
}

impl<E, D, P> Partitioner for ShamirIda<E, D, P>
where
    E: KeyIvInit + BlockEncryptMut,
    D: KeyIvInit + BlockDecryptMut,
    P: RawPadding,
{
    fn split<R: Read, W: Write>(&self, mut input: R, outputs: &mut [OutputPartition<W>]) {
        let (key, iv) = <E as KeyIvInit>::generate_key_iv(OsRng);
        let cipher = E::new(&key, &iv);
        let mut input: EncryptReadStream<E, P, &mut R> = EncryptReadStream::new(cipher, &mut input);

        // Write the key using Shamir's secret sharing
        self.shamir.split(&mut Cursor::new(key), outputs);
        self.shamir.split(&mut Cursor::new(iv), outputs);

        // Write the input using IDA
        self.ida.split(&mut input, outputs);
    }

    fn join<R: Read, W: Write>(&self, inputs: &mut [InputPartition<R>], mut output: W) {
        let mut key = Vec::new();
        let mut limited_inputs: Vec<(u8, Take<_>)> = inputs
            .iter_mut()
            .map(|input| {
                (
                    input.x,
                    (&mut input.reader).take((D::key_size() + D::iv_size()) as u64),
                )
            })
            .collect();
        self.shamir.join(
            &mut limited_inputs
                .iter_mut()
                .map(|(x, reader)| InputPartition { x: *x, reader })
                .collect::<Vec<_>>(),
            &mut key,
        );
        debug_assert!(key.len() == D::key_size() + D::iv_size());

        let cipher = D::new_from_slices(&key[..D::key_size()], &key[D::key_size()..]).unwrap();
        let mut output: DecryptWriteStream<D, P, &mut W> = DecryptWriteStream::new(cipher, &mut output);
        self.ida.join(inputs, &mut output);
        output.flush().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::partitioner::test_join;

    use aes::{Aes128, Aes256};
    use block_padding::{Iso7816, Pkcs7};

    fn base_two_of_three<E, D, P>()
    where
        E: KeyIvInit + BlockEncryptMut,
        D: KeyIvInit + BlockDecryptMut,
        P: RawPadding,
    {
        let plaintext: Vec<u8> = "hello world".as_bytes().into();
        let shamir = ShamirIda::<E, D, P>::new(2);
        let mut partitions = shamir.split_in_memory(&plaintext, 3);
        for partition in partitions.iter() {
            assert_ne!(plaintext, partition.value);
        }
        test_join(&shamir, &mut partitions[..], 2, &plaintext);
    }

    #[test]
    fn two_of_three_cbc_aes256_iso() {
        base_two_of_three::<cbc::Encryptor<Aes256>, cbc::Decryptor<Aes256>, Iso7816>();
    }

    #[test]
    fn two_of_three_cfb_aes128_pkcs() {
        base_two_of_three::<cfb_mode::Encryptor<Aes128>, cfb_mode::Decryptor<Aes128>, Pkcs7>();
    }

    #[test]
    fn five_of_ten() {
        let plaintext: Vec<u8> = "this is a much longer text".as_bytes().into();
        let shamir = ShamirIda::<cbc::Encryptor<Aes256>, cbc::Decryptor<Aes256>, Iso7816>::new(5);
        let mut partitions = shamir.split_in_memory(&plaintext, 10);
        for partition in partitions.iter() {
            assert_ne!(plaintext, partition.value);
        }
        test_join(&shamir, &mut partitions[..], 5, &plaintext);
    }
}
