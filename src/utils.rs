use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use HandshakeError::{FatalError, NotSupportedError};

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum HandshakeError {
    FatalError,
    NonFatalError,
    NotSupportedError,
    WrongMessageError,
}

pub trait ToBytes {
    fn to_bytes(&self, size: Option<usize>) -> Result<Vec<u8>, HandshakeError>;
}

impl ToBytes for String {
    fn to_bytes(&self, size: Option<usize>) -> Result<Vec<u8>, HandshakeError> {
        // currently only support strings with length that can fit in u8 (https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer)
        if size.is_none() && self.len() >= 0xFD {
            return Err(NotSupportedError);
        }

        let str_size = size.unwrap_or(self.len());
        if self.len() > str_size {
            return Err(FatalError);
        }

        let mut bytes = self.as_bytes().to_vec();
        let mut res = vec![];
        if size.is_none() {
            res.push(bytes.len() as u8);
        }
        res.append(&mut bytes);
        if str_size > self.len() {
            res.append(&mut vec![0u8; str_size - self.len()])
        }

        Ok(res)
    }
}

pub trait FromBytes<T> {
    fn from_bytes(bytes: &[u8]) -> Result<T, HandshakeError>;
}

impl FromBytes<String> for String {
    fn from_bytes(bytes: &[u8]) -> Result<String, HandshakeError> {
        let end = bytes.iter().position(|&b| b == 0x00u8);

        let bytes = &bytes[..end.unwrap_or(bytes.len())];

        String::from_utf8(bytes.to_vec()).or(Err(FatalError))
    }
}

pub trait ToLittleEndian {
    fn to_little_endian(self) -> Result<Vec<u8>, HandshakeError>;
}

impl ToLittleEndian for u64 {
    fn to_little_endian(self) -> Result<Vec<u8>, HandshakeError> {
        let mut bytes = vec![];
        bytes.write_u64::<LittleEndian>(self).or(Err(FatalError))?;

        Ok(bytes)
    }
}

impl ToLittleEndian for i32 {
    fn to_little_endian(self) -> Result<Vec<u8>, HandshakeError> {
        let mut bytes = vec![];
        bytes.write_i32::<LittleEndian>(self).or(Err(FatalError))?;

        Ok(bytes)
    }
}

impl ToLittleEndian for i64 {
    fn to_little_endian(self) -> Result<Vec<u8>, HandshakeError> {
        let mut bytes = vec![];
        bytes.write_i64::<LittleEndian>(self).or(Err(FatalError))?;

        Ok(bytes)
    }
}

pub trait ToBigEndian {
    fn to_big_endian(self) -> Result<Vec<u8>, HandshakeError>;
}

impl ToBigEndian for u16 {
    fn to_big_endian(self) -> Result<Vec<u8>, HandshakeError> {
        let mut bytes = vec![];
        bytes.write_u16::<BigEndian>(self).or(Err(FatalError))?;

        Ok(bytes)
    }

    // fn from_big_endian(bytes: Vec<u8>) -> Option<Self> {
    //     let mut rdr = Cursor::new(bytes);
    //
    //     rdr.read_u16::<BigEndian>().ok()
    // }
}

pub trait FromLittleEndian<T> {
    fn from_little_endian(bytes: &[u8]) -> Result<T, HandshakeError>;
}

impl FromLittleEndian<i32> for i32 {
    fn from_little_endian(bytes: &[u8]) -> Result<i32, HandshakeError> {
        let mut rdr = Cursor::new(bytes);

        rdr.read_i32::<LittleEndian>().or(Err(FatalError))
    }
}

impl FromLittleEndian<u64> for u64 {
    fn from_little_endian(bytes: &[u8]) -> Result<u64, HandshakeError> {
        let mut rdr = Cursor::new(bytes);

        rdr.read_u64::<LittleEndian>().or(Err(FatalError))
    }
}

impl FromLittleEndian<i64> for i64 {
    fn from_little_endian(bytes: &[u8]) -> Result<i64, HandshakeError> {
        let mut rdr = Cursor::new(bytes);

        rdr.read_i64::<LittleEndian>().or(Err(FatalError))
    }
}

impl FromLittleEndian<u16> for u16 {
    fn from_little_endian(bytes: &[u8]) -> Result<u16, HandshakeError> {
        let mut rdr = Cursor::new(bytes);

        rdr.read_u16::<LittleEndian>().or(Err(FatalError))
    }
}

pub trait FromBigEndian<T> {
    fn from_big_endian(bytes: &[u8]) -> Result<T, HandshakeError>;
}

impl FromBigEndian<u16> for u16 {
    fn from_big_endian(bytes: &[u8]) -> Result<u16, HandshakeError> {
        let mut rdr = Cursor::new(bytes);

        rdr.read_u16::<BigEndian>().or(Err(FatalError))
    }
}

// a function for testing
#[allow(dead_code)]
pub fn bytes_to_str(bytes: Vec<u8>) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(" ")
}
