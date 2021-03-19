use std::io::{Read, Write};

use crate::partitioner::{Partitioner, InputPartition, OutputPartition};
use crate::poly::lagrange_eval;

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
        let target_read_size = BUF_SIZE - BUF_SIZE % k_usize;

        let field = PrimitivePolynomialField::new_might_panic(self.base);

        let mut read_buf: [u8; BUF_SIZE] = [0u8; BUF_SIZE];
        let mut write_bufs: Vec<[u8; BUF_SIZE]> = vec![[0u8; BUF_SIZE]; n.into()];

        let data_xs: Vec<u8> = (0u8..self.k.into()).collect();
        let output_xs: Vec<u8> = outputs.iter().map(|output| output.x).collect();
        let lagrange = lagrange_eval(&field, &data_xs[..], &output_xs[..]);

        loop {
            match input.read(&mut read_buf[0..target_read_size]) {
                Err(_) | Ok(0) => break,
                Ok(read_size) =>
                {
                    for (i, slice) in read_buf[0..read_size].chunks(self.k.into()).enumerate() {
                        if slice.len() < self.k.into() {
                            // We don't have a full k characters remaining, dump the whole thing
                            // into each write buffer
                            for write_buf in write_bufs.iter_mut() {
                                write_buf[i..i + slice.len()].clone_from_slice(slice);
                            }
                        } else {
                            for (write_buf, output_lagrange) in write_bufs.iter_mut().zip(lagrange.iter()) {
                                write_buf[i] = 0u8;
                                for (y, lagrange_coefficient) in slice.iter().zip(output_lagrange.iter()) {
                                    write_buf[i] = field.add(write_buf[i], field.mult(*y, *lagrange_coefficient));
                                }
                            }
                        }
                    }
                    let write_size = read_size / k_usize + read_size % k_usize;
                    for (write_buf, output) in write_bufs.iter().zip(outputs.iter_mut()) {
                        output.writer.write(&write_buf[0..write_size]).expect("write failed");
                    }
                }
            }
        }
    }

    fn join(&self, inputs: &mut Vec<InputPartition>, output: &mut impl Write) {
    }
}
