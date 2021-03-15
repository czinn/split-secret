use std::io::{Read, Write};

pub struct InputPartition<R: Read> {
    pub x: u8,
    pub reader: R,
}

pub struct OutputPartition<W: Write> {
    pub x: u8,
    pub writer: W
}

pub trait Splitter<W: Write> {
    fn split(&self, input: &mut impl Read, outputs: &mut Vec<OutputPartition<W>>);
}

pub trait Joiner<R: Read> {
    fn join(&self, inputs: &mut Vec<InputPartition<R>>, output: &mut impl Write);
}
