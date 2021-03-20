use std::io::{Read, Write};
use std::cmp;

use crate::partitioner::{Partitioner, InputPartition, OutputPartition};

use galois_2p8::{PrimitivePolynomialField, IrreducablePolynomial, Field};
use rand::rngs::OsRng;
use rand::RngCore;

pub struct Shamir {
    k: u8,
    base: IrreducablePolynomial,
}

impl Shamir {
    pub fn new(k: u8) -> Self {
        assert!(k > 1);
        return Shamir { k: k, base: IrreducablePolynomial::Poly84320 };
    }
}

const BUF_SIZE: usize = 512;

impl Partitioner for Shamir {
    fn split(&self, input: &mut impl Read, outputs: &mut Vec<OutputPartition>) {
        let n = outputs.len() as u8;
        assert!(n >= self.k);
        // TODO: check that all the indicies in the outputs are unique

        let field = PrimitivePolynomialField::new_might_panic(self.base);

        let mut read_buf: [u8; BUF_SIZE] = [0u8; BUF_SIZE];
        let mut write_bufs: Vec<[u8; BUF_SIZE]> = vec![[0u8; BUF_SIZE]; n.into()];
        let mut coefficients_buf: [u8; BUF_SIZE] = [0u8; BUF_SIZE];

        loop {
            match input.read(&mut read_buf) {
                Err(_) | Ok(0) => break,
                Ok(read_size) =>
                {
                    let slice = &read_buf[0..read_size];
                    for write_buf in write_bufs.iter_mut() {
                        write_buf[0..read_size].copy_from_slice(slice);
                    }
                    let mut xs = vec![1u8; n.into()];
                    for _i in 1u8..=self.k - 1 {
                        for (x, output) in xs.iter_mut().zip(outputs.iter()) {
                            *x = field.mult(*x, output.x);
                        }
                        OsRng.fill_bytes(&mut coefficients_buf[0..read_size]);
                        for (write_buf, scale) in write_bufs.iter_mut().zip(xs.iter()) {
                            field.add_scaled_multiword(&mut write_buf[0..read_size], &coefficients_buf[0..read_size], *scale);
                        }
                    }
                    for (write_buf, output) in write_bufs.iter().zip(outputs.iter_mut()) {
                        output.writer.write(&write_buf[0..read_size]).expect("write failed");
                    }
                },
            }
        }
    }

    fn join(&self, inputs: &mut Vec<InputPartition>, output: &mut impl Write) {
        assert!(inputs.len() == self.k.into());

        let field = PrimitivePolynomialField::new_might_panic(self.base);

        let mut read_bufs: Vec<[u8; BUF_SIZE]> = vec![[0u8; BUF_SIZE]; self.k.into()];
        let mut write_buf: [u8; BUF_SIZE] = [0u8; BUF_SIZE];

        let mut combine_coefficients: Vec<u8> = Vec::new();
        for input in inputs.iter() {
            let mut coefficient = 1u8;
            for other_input in inputs.iter() {
                if other_input.x == input.x {
                    continue;
                }
                coefficient = field.mult(coefficient, field.div(other_input.x, field.sub(input.x, other_input.x)));
            }
            combine_coefficients.push(coefficient);
        }

        loop {
            let mut read_size = BUF_SIZE;
            for (input, read_buf) in inputs.iter_mut().zip(read_bufs.iter_mut()) {
                match input.reader.read(read_buf) {
                    Err(_) => {
                        read_size = 0;
                        break;
                    },
                    Ok(n) => read_size = cmp::min(read_size, n),
                }
            }
            if read_size == 0 {
                break;
            }

            write_buf.fill(0u8);
            for (read_buf, scale) in read_bufs.iter().zip(combine_coefficients.iter()) {
                field.add_scaled_multiword(&mut write_buf[0..read_size], &read_buf[0..read_size], *scale);
            }
            output.write(&write_buf[0..read_size]).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_of_three() {
        let plaintext: Vec<u8> = "hello world".as_bytes().into();
        let s = Shamir::new(2);
        let partitions = s.split_in_memory(&plaintext, 3);
        for partition in partitions.iter() {
            assert_ne!(plaintext, partition.value);
            assert_eq!(plaintext.len(), partition.value.len());
        }
        {
            let result = s.join_in_memory(&partitions[0..2]);
            assert_eq!(plaintext, result);
        }
        {
            let result = s.join_in_memory(&partitions[1..3]);
            assert_eq!(plaintext, result);
        }
    }

    #[test]
    fn five_of_ten() {
        let plaintext: Vec<u8> = "this is a much longer text".as_bytes().into();
        let s = Shamir::new(5);
        let partitions = s.split_in_memory(&plaintext, 10);
        for partition in partitions.iter() {
            assert_ne!(plaintext, partition.value);
            assert!(plaintext.len() == partition.value.len());
        }
        {
            let result = s.join_in_memory(&partitions[0..5]);
            assert_eq!(plaintext, result);
        }
        {
            let result = s.join_in_memory(&partitions[1..6]);
            assert_eq!(plaintext, result);
        }
        {
            let result = s.join_in_memory(&partitions[5..10]);
            assert_eq!(plaintext, result);
        }
    }
}
