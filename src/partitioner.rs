use std::io::{Read, Write, Cursor};

#[allow(dead_code)]
pub struct InMemoryPartition {
    pub x: u8,
    pub value: Vec<u8>,
}

pub struct InputPartition<'a> {
    pub x: u8,
    pub reader: &'a mut dyn Read,
}

pub struct OutputPartition<'a> {
    pub x: u8,
    pub writer: &'a mut dyn Write
}

pub trait Partitioner {
    fn split<'a>(&self, input: &mut impl Read, outputs: &mut Vec<OutputPartition<'a>>);

    fn split_in_memory(&self, input: &Vec<u8>, n: u8) -> Vec<InMemoryPartition> {
        let mut outputs = Vec::new();
        for x in 1u8..=n {
            outputs.push(InMemoryPartition { x: x, value: Vec::new() });
        }
        self.split(&mut Cursor::new(input), &mut outputs.iter_mut().map(|p| OutputPartition { x: p.x, writer: &mut p.value }).collect());

        outputs
    }

    fn join<'a>(&self, inputs: &mut Vec<InputPartition<'a>>, output: &mut impl Write);

    fn join_in_memory(&self, inputs: &Vec<&InMemoryPartition>) -> Vec<u8> {
        let mut input_readers: Vec<(u8, Cursor<Vec<u8>>)> = inputs.iter().map(|input| (input.x, Cursor::new(input.value.clone()))).collect();
        let mut inputs = input_readers.iter_mut().map(|(x, reader)| InputPartition { x: *x, reader: reader}).collect();
        let mut output = Vec::new();
        self.join(&mut inputs, &mut output);
        output
    }
}

// Tests all subsets of k inputs and verifies that the output is correct.
#[cfg(test)]
pub fn test_join(partitioner: &impl Partitioner, inputs: &[InMemoryPartition], k: u8, expected_output: &Vec<u8>) {
    for i in 0..2u32.pow(k.into()) {
        if i.count_ones() != k.into() {
            continue;
        }
        let inputs_subset: Vec<&InMemoryPartition> = inputs.iter().enumerate().filter_map(|(j, input)| if (i >> j) & 1 != 0 { Some(input) } else { None }).collect();
        let output = partitioner.join_in_memory(&inputs_subset);
        assert_eq!(*expected_output, output);
    }
}
