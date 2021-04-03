use std::io::{Read, Write, Cursor};

#[allow(dead_code)]
pub struct InMemoryPartition {
    pub x: u8,
    pub value: Vec<u8>,
}

pub struct InputPartition<R: Read> {
    pub x: u8,
    pub reader: R,
}

pub struct OutputPartition<W: Write> {
    pub x: u8,
    pub writer: W,
}

pub trait Partitioner {
    fn split<R: Read, W: Write>(&self, input: R, outputs: &mut [OutputPartition<W>]);

    fn split_in_memory(&self, input: &[u8], n: u8) -> Vec<InMemoryPartition> {
        let mut outputs = Vec::new();
        for x in 1u8..=n {
            outputs.push(InMemoryPartition { x: x, value: Vec::new() });
        }
        self.split(Cursor::new(input), &mut outputs.iter_mut().map(|p| OutputPartition { x: p.x, writer: &mut p.value }).collect::<Vec<_>>());

        outputs
    }

    fn join<R: Read, W: Write>(&self, inputs: &mut [InputPartition<R>], output: W);

    fn join_in_memory(&self, inputs: &mut [&mut InMemoryPartition]) -> Vec<u8> {
        let mut input_readers: Vec<(u8, Cursor<_>)> = inputs.iter_mut().map(|input| (input.x, Cursor::new(&mut input.value))).collect();
        let mut inputs = input_readers.iter_mut().map(|(x, reader)| InputPartition { x: *x, reader: reader}).collect::<Vec<_>>();
        let mut output = Vec::new();
        self.join(&mut inputs, &mut output);
        output
    }
}

// Tests all subsets of k inputs and verifies that the output is correct.
#[cfg(test)]
pub fn test_join(partitioner: &impl Partitioner, inputs: &mut [InMemoryPartition], k: u8, expected_output: &Vec<u8>) {
    for i in 0..2u32.pow(k.into()) {
        if i.count_ones() != k.into() {
            continue;
        }
        let mut inputs_subset: Vec<_> = inputs.iter_mut().enumerate().filter_map(|(j, input)| if (i >> j) & 1 != 0 { Some(input) } else { None }).collect();
        let output = partitioner.join_in_memory(&mut inputs_subset);
        assert_eq!(*expected_output, output);
    }
}
