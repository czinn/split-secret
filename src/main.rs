mod block_mode_streaming;
mod ida;
mod padding_streaming;
mod partitioner;
mod poly;
mod shamir;
mod shamir_ida;
mod utils;

use std::fs::File;
use std::io::{Read, Write};

use crate::partitioner::{InputPartition, OutputPartition, Partitioner};

use aes::Aes256;
use block_modes::Cbc;
use block_padding::Iso7816;

use clap::Clap;

#[derive(Clap)]
#[clap(
    version = "0.1.0",
    author = "Charles Zinn",
    about = "An implementation of Shamir's Secret Sharing"
)]
struct Opts {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(Clap)]
enum Subcommand {
    #[clap(about = "Split a file into multiple shares")]
    Split(SplitOpts),
    #[clap(about = "Combine shares into the original file")]
    Join(JoinOpts),
}

#[derive(Clap)]
struct SplitOpts {
    #[clap(short, about = "number of shares to generate")]
    n: u8,
    #[clap(
        short,
        about = "number of shares required to reconstruct original (default: n)"
    )]
    k: Option<u8>,
    #[clap(about = "input file")]
    input: String,
    #[clap(
        short,
        long,
        about = "prefix for output files; output will be in [output].1, [output].2, etc."
    )]
    output: String,
}

#[derive(Clap)]
struct JoinOpts {
    #[clap(required = true, about = "input share files")]
    inputs: Vec<String>,
    #[clap(short, long, about = "output file for original")]
    output: String,
}

struct ShareHeader {
    k: u8, // number of shares needed to reconstruct original (polynomial is of degree k - 1)
    x: u8, // index of this share
}

fn write_share_header(writer: &mut impl Write, share_header: &ShareHeader) {
    writer.write(&[share_header.k, share_header.x]).unwrap();
}

fn read_share_header(reader: &mut impl Read) -> ShareHeader {
    let mut buf = [0u8; 2];
    reader.read(&mut buf).unwrap();
    ShareHeader {
        k: buf[0],
        x: buf[1],
    }
}

fn main() {
    let opts: Opts = Opts::parse();

    match opts.subcommand {
        Subcommand::Split(opts) => {
            let n = opts.n;
            let k = opts.k.unwrap_or(opts.n);
            let shamir_ida = shamir_ida::ShamirIda::<Cbc<_, _>, Aes256, Iso7816>::new(k);

            let mut input_file = File::open(opts.input).unwrap();
            let mut output_files = Vec::new();
            for x in 1u8..=n {
                let mut output_file = File::create(format!("{}.{}", opts.output, x))
                    .expect("Error creating output file");
                write_share_header(&mut output_file, &ShareHeader { k: k, x: x });
                output_files.push(output_file);
            }
            let mut output_partitions: Vec<_> = output_files
                .iter_mut()
                .enumerate()
                .map(|(i, output_file)| OutputPartition {
                    x: (i + 1) as u8,
                    writer: output_file,
                })
                .collect();

            shamir_ida.split(&mut input_file, &mut output_partitions);
        }
        Subcommand::Join(opts) => {
            let mut input_files = Vec::new();
            let mut k = None;
            for input in opts.inputs {
                let mut input_file = File::open(input).unwrap();
                let share_header = read_share_header(&mut input_file);
                assert!(share_header.k == k.unwrap_or(share_header.k));
                k = Some(share_header.k);

                input_files.push((share_header.x, input_file));
                if input_files.len() == k.unwrap().into() {
                    break;
                }
            }
            let k = k.unwrap_or(0);
            assert!(input_files.len() == k.into());
            assert!(k > 0);
            let mut input_partitions: Vec<_> = input_files
                .iter_mut()
                .map(|(x, input_file)| InputPartition {
                    x: *x,
                    reader: input_file,
                })
                .collect();
            let mut output_file = File::create(opts.output).unwrap();

            let shamir_ida = shamir_ida::ShamirIda::<Cbc<_, _>, Aes256, Iso7816>::new(k);

            shamir_ida.join(&mut input_partitions, &mut output_file);
        }
    }
}
