use std::io::{Read, Write};
use std::cmp;

use crate::partitioner::{Partitioner, InputPartition, OutputPartition};
use crate::poly::lagrange_eval;
use crate::padding_streaming::{PaddedReader, PaddedWriter, Op};

use galois_2p8::{PrimitivePolynomialField, IrreducablePolynomial, Field};
use block_padding::Iso7816;

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

const BUF_SIZE: usize = 1024;

impl Partitioner for Ida {
    fn split<R: Read, W: Write>(&self, input: R, outputs: &mut Vec<OutputPartition<W>>) {
        let n = outputs.len() as u8;
        assert!(n >= self.k);
        // TODO: check that all the indicies in the outputs are unique

        let k_usize: usize = self.k.into();
        let mut input = PaddedReader::<Iso7816, _>::new(k_usize, input, Op::Pad);
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

    fn join<R: Read, W: Write>(&self, inputs: &mut Vec<InputPartition<R>>, output: W) {
        let k_usize: usize = self.k.into();
        assert!(inputs.len() == k_usize);
        let mut output = PaddedWriter::<Iso7816, _>::new(k_usize, output, Op::Unpad);

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
    use crate::partitioner::test_join;

    #[test]
    fn two_of_three() {
        let plaintext: Vec<u8> = "hello worlds".as_bytes().into();
        let ida = Ida::new(2);
        let mut partitions = ida.split_in_memory(&plaintext, 3);
        for partition in partitions.iter() {
            assert_ne!(plaintext, partition.value);
            assert!(plaintext.len() > partition.value.len());
        }
        test_join(&ida, &mut partitions[..], 2, &plaintext);
    }

    #[test]
    fn five_of_ten() {
        let plaintext: Vec<u8> = "this is a much longer text".as_bytes().into();
        let ida = Ida::new(5);
        let mut partitions = ida.split_in_memory(&plaintext, 10);
        for partition in partitions.iter() {
            assert_ne!(plaintext, partition.value);
            assert!(plaintext.len() > partition.value.len());
        }
        test_join(&ida, &mut partitions[..], 5, &plaintext);
    }
}
