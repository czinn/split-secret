use std::io::{Read, Write};
use std::fs::File;
use std::cmp;

use clap::Clap;
use galois_2p8::{PrimitivePolynomialField, IrreducablePolynomial, Field};
use rand::rngs::OsRng;
use rand::RngCore;

#[derive(Clap)]
#[clap(version = "0.1.0", author = "Charles Zinn", about = "An implementation of Shamir's Secret Sharing")]
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
    #[clap(short, about = "number of shares required to reconstruct original (default: n)")]
    k: Option<u8>,
    #[clap(about = "input file")]
    input: String,
    #[clap(short, long, about = "prefix for output files; output will be in [output].1, [output].2, etc.")]
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

const BUF_SIZE: usize = 512;

fn main() {
    let opts: Opts = Opts::parse();

    let field = PrimitivePolynomialField::new_might_panic(IrreducablePolynomial::Poly84320);

    match opts.subcommand {
        Subcommand::Split(opts) => {
            let n = opts.n;
            let k = opts.k.unwrap_or(opts.n);
            assert!(k > 1);
            assert!(n >= k);

            let mut read_buf: [u8; BUF_SIZE] = [0u8; BUF_SIZE];
            let mut coefficients_buf: [u8; BUF_SIZE] = [0u8; BUF_SIZE];
            let mut write_bufs: Vec<[u8; BUF_SIZE]> = vec![[0u8; BUF_SIZE]; opts.n.into()];

            let mut input_file = File::open(opts.input).unwrap();
            let mut output_files = Vec::new();
            for x in 1u8..=n {
                let mut output_file = File::create(format!("{}.{}", opts.output, x)).expect("Error creating output file");
                write_share_header(&mut output_file, &ShareHeader { k: k, x: x });
                output_files.push(output_file);
            }

            loop {
                match input_file.read(&mut read_buf) {
                    Err(_) | Ok(0) => break,
                    Ok(read_size) =>
                    {
                        let slice = &read_buf[0..read_size];
                        for write_buf in write_bufs.iter_mut() {
                            write_buf[0..read_size].clone_from_slice(slice);
                        }
                        let mut xs = vec![1u8; opts.n.into()];
                        for _i in 1u8..=k - 1 {
                            for (j, x) in xs.iter_mut().enumerate() {
                                *x = field.mult(*x, 1u8 + (j as u8));
                            }
                            OsRng.fill_bytes(&mut coefficients_buf[0..read_size]);
                            for (write_buf, scale) in write_bufs.iter_mut().zip(xs.iter()) {
                                field.add_scaled_multiword(&mut write_buf[0..read_size], &coefficients_buf[0..read_size], *scale);
                            }
                        }
                        for (write_buf, output_file) in write_bufs.iter().zip(output_files.iter_mut()) {
                            output_file.write(&write_buf[0..read_size]).expect("write failed");
                        }
                    },
                }
            }
        },
        Subcommand::Join(opts) => {
            let mut input_files: Vec<File> = Vec::new();
            let mut share_headers: Vec<ShareHeader> = Vec::new();
            for input in opts.inputs {
                let mut input_file = File::open(input).unwrap();
                let share_header = read_share_header(&mut input_file);
                share_headers.push(share_header);
                input_files.push(input_file);
                assert!(share_headers.last().unwrap().k == share_headers[0].k);
                if input_files.len() == share_headers[0].k.into() {
                    break;
                }
            }
            assert!(input_files.len() == share_headers[0].k.into());
            let mut output_file = File::create(opts.output).unwrap();

            let mut read_bufs: Vec<[u8; BUF_SIZE]> = vec![[0u8; BUF_SIZE]; input_files.len()];
            let mut write_buf: [u8; BUF_SIZE];

            let mut combine_coefficients: Vec<u8> = Vec::new();
            for share_header in share_headers.iter() {
                let mut coefficient = 1u8;
                for other_share_header in share_headers.iter() {
                    if other_share_header.x == share_header.x {
                        continue;
                    }
                    coefficient = field.mult(coefficient, field.div(other_share_header.x, field.sub(share_header.x, other_share_header.x)));
                }
                combine_coefficients.push(coefficient);
            }

            loop {
                let mut read_size = BUF_SIZE;
                for (input_file, read_buf) in input_files.iter_mut().zip(read_bufs.iter_mut()) {
                    match input_file.read(read_buf) {
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

                write_buf = [0u8; BUF_SIZE];
                for (read_buf, scale) in read_bufs.iter_mut().zip(combine_coefficients.iter()) {
                    field.add_scaled_multiword(&mut write_buf[0..read_size], &read_buf[0..read_size], *scale);
                }
                output_file.write(&write_buf[0..read_size]).unwrap();
            }
        }
    }
}
