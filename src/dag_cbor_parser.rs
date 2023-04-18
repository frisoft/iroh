//! CBOR decoder
use crate::Hash;
use anyhow::Result;
use byteorder::{BigEndian, ByteOrder};
use std::any::type_name;
use std::io::{Read, Seek, SeekFrom};
use thiserror::Error;

/// Length larger than usize or too small, for example zero length cid field.
#[derive(Debug, Error)]
#[error("Length out of range when decoding {ty}.")]
pub struct LengthOutOfRange {
    /// Type.
    pub ty: &'static str,
}

impl LengthOutOfRange {
    /// Creates a new `LengthOutOfRange` error.
    pub fn new<T>() -> Self {
        Self {
            ty: type_name::<T>(),
        }
    }
}

/// Unexpected cbor code.
#[derive(Debug, Error)]
#[error("Unexpected cbor code `0x{code:x}` when decoding `{ty}`.")]
pub struct UnexpectedCode {
    /// Code.
    pub code: u8,
    /// Type.
    pub ty: &'static str,
}

impl UnexpectedCode {
    /// Creates a new `UnexpectedCode` error.
    pub fn new<T>(code: u8) -> Self {
        Self {
            code,
            ty: type_name::<T>(),
        }
    }
}

/// Unexpected key.
#[derive(Debug, Error)]
#[error("Unexpected key `{key}` when decoding `{ty}`.")]
pub struct UnexpectedKey {
    /// Key.
    pub key: String,
    /// Type.
    pub ty: &'static str,
}

/// Unknown cbor tag.
#[derive(Debug, Error)]
#[error("Unkown cbor tag `{0}`.")]
pub struct UnknownTag(pub u8);

/// Unexpected eof.
#[derive(Debug, Error)]
#[error("Unexpected end of file.")]
pub struct UnexpectedEof;

/// The byte before Cid was not multibase identity prefix.
#[derive(Debug, Error)]
#[error("Invalid Cid prefix: {0}")]
pub struct InvalidCidPrefix(pub u8);

/// Reads a u8 from a byte stream.
pub fn read_u8<R: Read + Seek>(r: &mut R) -> Result<u8> {
    let mut buf = [0; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

/// Reads a u16 from a byte stream.
pub fn read_u16<R: Read + Seek>(r: &mut R) -> Result<u16> {
    let mut buf = [0; 2];
    r.read_exact(&mut buf)?;
    Ok(BigEndian::read_u16(&buf))
}

/// Reads a u32 from a byte stream.
pub fn read_u32<R: Read + Seek>(r: &mut R) -> Result<u32> {
    let mut buf = [0; 4];
    r.read_exact(&mut buf)?;
    Ok(BigEndian::read_u32(&buf))
}

/// Reads a u64 from a byte stream.
pub fn read_u64<R: Read + Seek>(r: &mut R) -> Result<u64> {
    let mut buf = [0; 8];
    r.read_exact(&mut buf)?;
    Ok(BigEndian::read_u64(&buf))
}

/// Reads `len` number of bytes from a byte stream.
pub fn read_bytes<R: Read + Seek>(r: &mut R, len: usize) -> Result<Vec<u8>> {
    // Limit up-front allocations to 16KiB as the length is user controlled.
    let mut buf = Vec::with_capacity(len.min(16 * 1024));
    r.take(len as u64).read_to_end(&mut buf)?;
    if buf.len() != len {
        return Err(UnexpectedEof.into());
    }
    Ok(buf)
}

/// Reads a cid from a stream of cbor encoded bytes.
pub fn read_link<R: Read + Seek>(r: &mut R) -> Result<Hash> {
    let ty = read_u8(r)?;
    if ty != 0x58 {
        return Err(UnknownTag(ty).into());
    }
    let len = read_u8(r)?;
    if len == 0 {
        return Err(LengthOutOfRange::new::<Hash>().into());
    }
    let bytes = read_bytes(r, len as usize)?;
    if bytes[0] != 0 {
        return Err(InvalidCidPrefix(bytes[0]).into());
    }

    // skip the first byte per
    // https://github.com/ipld/specs/blob/master/block-layer/codecs/dag-cbor.md#links
    let bytes = <[u8; 32]>::try_from(&bytes[1..])?;
    Ok(Hash::from(bytes))
}

/// Reads the len given a base.
pub fn read_len<R: Read + Seek>(r: &mut R, major: u8) -> Result<usize> {
    Ok(match major {
        0x00..=0x17 => major as usize,
        0x18 => read_u8(r)? as usize,
        0x19 => read_u16(r)? as usize,
        0x1a => read_u32(r)? as usize,
        0x1b => {
            let len = read_u64(r)?;
            if len > usize::max_value() as u64 {
                return Err(LengthOutOfRange::new::<usize>().into());
            }
            len as usize
        }
        major => return Err(UnexpectedCode::new::<usize>(major).into()),
    })
}

pub fn references<R: Read + Seek, E: Extend<Hash>>(r: &mut R, set: &mut E) -> Result<()> {
    let major = read_u8(r)?;
    match major {
        // Major type 0: an unsigned integer
        0x00..=0x17 => {}
        0x18 => {
            r.seek(SeekFrom::Current(1))?;
        }
        0x19 => {
            r.seek(SeekFrom::Current(2))?;
        }
        0x1a => {
            r.seek(SeekFrom::Current(4))?;
        }
        0x1b => {
            r.seek(SeekFrom::Current(8))?;
        }

        // Major type 1: a negative integer
        0x20..=0x37 => {}
        0x38 => {
            r.seek(SeekFrom::Current(1))?;
        }
        0x39 => {
            r.seek(SeekFrom::Current(2))?;
        }
        0x3a => {
            r.seek(SeekFrom::Current(4))?;
        }
        0x3b => {
            r.seek(SeekFrom::Current(8))?;
        }

        // Major type 2: a byte string
        0x40..=0x5b => {
            let len = read_len(r, major - 0x40)?;
            r.seek(SeekFrom::Current(len as _))?;
        }

        // Major type 3: a text string
        0x60..=0x7b => {
            let len = read_len(r, major - 0x60)?;
            r.seek(SeekFrom::Current(len as _))?;
        }

        // Major type 4: an array of data items
        0x80..=0x9b => {
            let len = read_len(r, major - 0x80)?;
            for _ in 0..len {
                references(r, set)?;
            }
        }

        // Major type 4: an array of data items (indefinite length)
        0x9f => loop {
            let major = read_u8(r)?;
            if major == 0xff {
                break;
            }
            r.seek(SeekFrom::Current(-1))?;
            references(r, set)?;
        },

        // Major type 5: a map of pairs of data items
        0xa0..=0xbb => {
            let len = read_len(r, major - 0xa0)?;
            for _ in 0..len {
                references(r, set)?;
                references(r, set)?;
            }
        }

        // Major type 5: a map of pairs of data items (indefinite length)
        0xbf => loop {
            let major = read_u8(r)?;
            if major == 0xff {
                break;
            }
            r.seek(SeekFrom::Current(-1))?;
            references(r, set)?;
            references(r, set)?;
        },

        // Major type 6: optional semantic tagging of other major types
        0xd8 => {
            let tag = read_u8(r)?;
            if tag == 42 {
                set.extend(std::iter::once(read_link(r)?));
            } else {
                references(r, set)?;
            }
        }

        // Major type 7: floating-point numbers and other simple data types that need no content
        0xf4..=0xf7 => {}
        0xf8 => {
            r.seek(SeekFrom::Current(1))?;
        }
        0xf9 => {
            r.seek(SeekFrom::Current(2))?;
        }
        0xfa => {
            r.seek(SeekFrom::Current(4))?;
        }
        0xfb => {
            r.seek(SeekFrom::Current(8))?;
        }
        major => return Err(UnexpectedCode::new::<Hash>(major).into()),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::references;

    fn bytes(s: &str) -> Vec<u8> {
        hex::decode(s.chars().filter(|c| !c.is_whitespace()).collect::<String>()).unwrap()
    }

    #[test]
    fn references1() {
        let data = bytes(
            r"
            6ffbd8e415444b5940d6fefacf64b922ad80b95debce812931745ad9b59b
            2565ea08b46db6da5052d6878c074d4f3e705d1a8456d1ae934b38b62e43
            6e413fbefb2284a5d628e2cf951722c04ff19ff217fcf0360fb8d27b55c0
            abe378984e0d07beeb964f9f4016408fa0c66b9bf445b53343be521290b9
            985e30d65c2116b852ab3414d65d6400dc4112ed278f83efc35e59a37b3e
            b62736dee6a752c331d78f176da7f1ad9bb5ed",
        );
        let mut links = Vec::new();
        references(&mut Cursor::new(&data), &mut links).unwrap();
        println!("{:?}", links);
    }
}
