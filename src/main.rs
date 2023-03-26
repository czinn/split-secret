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
use block_padding::Iso7816;

use clap::{Parser, Subcommand, Args};

#[derive(Parser)]
#[command(
    version = "0.1.0",
    author = "Charles Zinn",
    about = "An implementation of Shamir's Secret Sharing"
)]
struct Opts {
    #[command(subcommand)]
    subcommand: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Split a file into multiple shares")]
    Split(SplitOpts),
    #[command(about = "Combine shares into the original file")]
    Join(JoinOpts),
}

#[derive(Args)]
struct SplitOpts {
    #[arg(short, help = "number of shares to generate")]
    n: u8,
    #[arg(
        short,
        help = "number of shares required to reconstruct original (default: n)"
    )]
    k: Option<u8>,
    #[arg(help = "input file")]
    input: String,
    #[arg(
        short,
        long,
        help = "prefix for output files; output will be in [output].1, [output].2, etc."
    )]
    output: String,
}

#[derive(Args)]
struct JoinOpts {
    #[arg(required = true, help = "input share files")]
    inputs: Vec<String>,
    #[arg(short, long, help = "output file for original")]
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
        Commands::Split(opts) => {
            let n = opts.n;
            let k = opts.k.unwrap_or(opts.n);
            let shamir_ida = shamir_ida::ShamirIda::<cbc::Encryptor<Aes256>, cbc::Decryptor<Aes256>, Iso7816>::new(k);

            let mut input_file = File::open(&opts.input).unwrap();
            let mut output_files: Vec<_> = (1u8..=n)
                .map(|x| {
                    File::create(format!("{}.{}", &opts.output, x))
                        .expect("Error creating output file")
                })
                .collect();
            output_files
                .iter_mut()
                .enumerate()
                .for_each(|(x, output_file)| {
                    write_share_header(output_file, &ShareHeader { k: k, x: x as u8 })
                });
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
        Commands::Join(opts) => {
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
                    x: *x + 1,
                    reader: input_file,
                })
                .collect();
            let mut output_file = File::create(opts.output).unwrap();

            let shamir_ida = shamir_ida::ShamirIda::<cbc::Encryptor<Aes256>, cbc::Decryptor<Aes256>, Iso7816>::new(k);

            shamir_ida.join(&mut input_partitions, &mut output_file);
        }
    }
}
