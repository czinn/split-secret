use std::io::{Read, Result};

pub fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut read_size = 0;
    loop {
        match reader.read(&mut buf[read_size..])? {
            0 => break,
            n => read_size += n,
        }
    }
    Ok(read_size)
}
