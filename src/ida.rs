use std::io::{Read, Write};
use std::cmp;

use crate::partitioner::{Partitioner, InputPartition, OutputPartition};
use crate::poly::lagrange_eval;
use crate::iso_pad::{PaddedReader, PaddedWriter};

use galois_2p8::{PrimitivePolynomialField, IrreducablePolynomial, Field};

pub struct Ida {
    k: u8,
    base: IrreducablePolynomial,
}

impl Ida {
    pub fn new(k: u8) -> Self {
        assert!(k > 1);
        return Ida { k: k, base: IrreducablePolynomial::Poly84320 };
    }
}

const BUF_SIZE: usize = 512;

impl Partitioner for Ida {
    fn split(&self, input: &mut impl Read, outputs: &mut Vec<OutputPartition>) {
        let n = outputs.len() as u8;
        assert!(n >= self.k);
        // TODO: check that all the indicies in the outputs are unique

        let k_usize: usize = self.k.into();
        let mut input = PaddedReader::new(k_usize, input);
        let target_read_size = BUF_SIZE - BUF_SIZE % k_usize;

        let field = PrimitivePolynomialField::new_might_panic(self.base);

        let mut read_buf: [u8; BUF_SIZE] = [0u8; BUF_SIZE];
        let mut write_bufs: Vec<[u8; BUF_SIZE]> = vec![[0u8; BUF_SIZE]; n.into()];

        let data_xs: Vec<u8> = (0u8..self.k).collect();
        let output_xs: Vec<u8> = outputs.iter().map(|output| output.x).collect();
        let lagrange = lagrange_eval(&field, &data_xs[..], &output_xs[..]);

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
            for (i, slice) in read_buf[0..read_size].chunks(k_usize).enumerate() {
                for (write_buf, output_lagrange) in write_bufs.iter_mut().zip(lagrange.iter()) {
                    write_buf[i] = 0u8;
                    for (y, lagrange_coefficient) in slice.iter().zip(output_lagrange.iter()) {
                        write_buf[i] = field.add(write_buf[i], field.mult(*y, *lagrange_coefficient));
                    }
                }
            }
            let write_size = read_size / k_usize;
            for (write_buf, output) in write_bufs.iter().zip(outputs.iter_mut()) {
                output.writer.write_all(&write_buf[0..write_size]).expect("write failed");
            }
        }
    }

    fn join(&self, inputs: &mut Vec<InputPartition>, output: &mut impl Write) {
        let k_usize: usize = self.k.into();
        assert!(inputs.len() == k_usize);
        let mut output = PaddedWriter::new(k_usize, output);

        let field = PrimitivePolynomialField::new_might_panic(self.base);

        let mut read_bufs: Vec<[u8; BUF_SIZE]> = vec![[0u8; BUF_SIZE]; k_usize];
        let mut write_buf: Vec<u8> = vec![0u8; BUF_SIZE * k_usize];

        let input_xs: Vec<u8> = inputs.iter().map(|input| input.x).collect();
        let data_xs: Vec<u8> = (0u8..self.k).collect();
        let lagrange_t = lagrange_eval(&field, &input_xs[..], &data_xs[..]);
        let lagrange: Vec<Vec<u8>> = (0..k_usize).map(|i| lagrange_t.iter().map(|l| l[i]).collect()).collect();

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
            for (i, slice) in write_buf.chunks_mut(k_usize).take(read_size).enumerate() {
                for (read_buf, input_lagrange) in read_bufs.iter().zip(lagrange.iter()) {
                    field.add_scaled_multiword(slice, input_lagrange, read_buf[i]);
                }
            }

            output.write_all(&write_buf[0..read_size * k_usize]).unwrap();
        }
        output.flush().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_of_three() {
        let plaintext: Vec<u8> = "hello worlds".as_bytes().into();
        let i = Ida::new(2);
        let partitions = i.split_in_memory(&plaintext, 3);
        for partition in partitions.iter() {
            assert_ne!(plaintext, partition.value);
            assert!(plaintext.len() > partition.value.len());
        }
        {
            let result = i.join_in_memory(&partitions[0..2]);
            assert_eq!(plaintext, result);
        }
        {
            let result = i.join_in_memory(&partitions[1..3]);
            assert_eq!(plaintext, result);
        }
    }

    #[test]
    fn five_of_ten() {
        let plaintext: Vec<u8> = "this is a much longer text".as_bytes().into();
        let i = Ida::new(5);
        let partitions = i.split_in_memory(&plaintext, 10);
        for partition in partitions.iter() {
            assert_ne!(plaintext, partition.value);
            assert!(plaintext.len() > partition.value.len());
        }
        {
            let result = i.join_in_memory(&partitions[0..5]);
            assert_eq!(plaintext, result);
        }
        {
            let result = i.join_in_memory(&partitions[1..6]);
            assert_eq!(plaintext, result);
        }
        {
            let result = i.join_in_memory(&partitions[5..10]);
            assert_eq!(plaintext, result);
        }
    }
}
