use std::io::{Write, Read, BufRead};
use std::io;
use std::ptr;
use std::cmp;
use std::result;

use byteorder::{self, ByteOrder, LittleEndian, ReadBytesExt};

use self::SnappyError::*;

include!(concat!(env!("OUT_DIR"), "/tables.rs"));

const MAX_TAG_LEN: usize = 5;

pub trait SnappyWrite : Write {
    fn write_from_self(&mut self, offset: u32, len: u8) -> io::Result<()>;
    fn set_uncompressed_length(&mut self, length: u32);
}

#[derive(Debug)]
pub enum SnappyError {
    UnexpectedEOF,
    FormatError(&'static str),
    IoError(io::Error),
}

impl From<io::Error> for SnappyError {
    fn from(err: io::Error) -> Self {
        SnappyError::IoError(err)
    }
}

impl From<byteorder::Error> for SnappyError {
    fn from(err: byteorder::Error) -> Self {
        match err {
            byteorder::Error::UnexpectedEOF => SnappyError::UnexpectedEOF,
            byteorder::Error::Io(err) => SnappyError::IoError(err),
        }
    }
}

pub type Result<T> = result::Result<T, SnappyError>;

struct Decompressor<R> {
    reader: R,
}

macro_rules! read_new_buffer {
    ($me: expr) => (
        read_new_buffer!($me, return Ok(0));
    );
    ($me: expr, $on_eof: expr) => (
        match try!($me.reader.fill_buf()) {
            b if b.len() == 0 => {
                $on_eof
            },
            b => {
                (b.as_ptr(), b.as_ptr().offset(b.len() as isize))
            }
        }
    );
}

impl<R: BufRead> Decompressor<R> {
    fn new(reader: R) -> Decompressor<R> {
        Decompressor {
            reader: reader,
        }
    }

    fn decompress<W: SnappyWrite>(&mut self, writer: &mut W) -> Result<()> {
        let mut tag_buf = [0; MAX_TAG_LEN];

        loop {
            let (tag, tag_size, read) = {
                let buf = try!(self.reader.fill_buf());
                if buf.is_empty() {
                    return Ok(());
                }

                let tag = buf[0];
                let buf = &buf[1..];

                let tag_size = get_tag_size(tag);
                let read = cmp::min(tag_size - 1, buf.len());
                let buf = &buf[..read];

                for (src, dst) in buf.iter().zip(tag_buf.iter_mut()) {
                    *dst = *src;
                }

                (tag, tag_size, read)
            };
            self.reader.consume(1 + read);

            if tag_size - 1 != read {
                if try!(self.reader.read(&mut tag_buf[read..])) == 0 {
                    return Err(SnappyError::UnexpectedEOF);
                }
            }

            let tag_buf = &tag_buf[..tag_size];

            if tag & 0b11 == 0 {
                try!(self.decompress_literal(writer, tag, &tag_buf))
            } else {
                try!(self.decompress_copy(writer, tag, &tag_buf))
            }
        }
    }

    fn literal_len(&self, tag: u8, tag_buf: &[u8]) -> usize {
        // 2.1. Literals (00)
        //
        // Literals are uncompressed data stored directly in the byte stream.
        // The literal length is stored differently depending on the length
        // of the literal:
        //
        //  - For literals up to and including 60 bytes in length, the upper
        //    six bits of the tag byte contain (len-1). The literal follows
        //    immediately thereafter in the bytestream.
        //  - For longer literals, the (len-1) value is stored after the tag byte,
        //    little-endian. The upper six bits of the tag byte describe how
        //    many bytes are used for the length; 60, 61, 62 or 63 for
        //    1-4 bytes, respectively. The literal itself follows after the
        //    length.

        let len = match tag_buf.len() {
            1 => (tag >> 2) as usize,
            2 => tag_buf[0] as usize,
            3 => LittleEndian::read_u16(tag_buf) as usize,
            4 => (LittleEndian::read_u32(tag_buf) as usize) & 0x00FFFFFF,
            _ => LittleEndian::read_u32(tag_buf) as usize,
        };

        len + 1
    }

    fn decompress_literal<W: SnappyWrite>(&mut self,
                                          writer: &mut W,
                                          tag: u8,
                                          tag_buf: &[u8]) -> Result<()> {
        let len = self.literal_len(tag, tag_buf);
        self.copy_bytes(writer, len)
    }

    fn copy_offset_len(&self, tag: u8, tag_buf: &[u8]) -> (u32, u8) {
        // 2.2. Copies
        //
        // Copies are references back into previous decompressed data, telling
        // the decompressor to reuse data it has previously decoded.
        // They encode two values: The _offset_, saying how many bytes back
        // from the current position to read, and the _length_, how many bytes
        // to copy. Offsets of zero can be encoded, but are not legal;
        // similarly, it is possible to encode backreferences that would
        // go past the end of the block (offset > current decompressed position),
        // which is also nonsensical and thus not allowed.
        //
        // As in most LZ77-based compressors, the length can be larger than the offset,
        // yielding a form of run-length encoding (RLE). For instance,
        // "xababab" could be encoded as
        //
        //   <literal: "xab"> <copy: offset=2 length=4>
        //
        // Note that since the current Snappy compressor works in 32 kB
        // blocks and does not do matching across blocks, it will never produce
        // a bitstream with offsets larger than about 32768. However, the
        // decompressor should not rely on this, as it may change in the future.
        //
        // There are several different kinds of copy elements, depending on
        // the amount of bytes to be copied (length), and how far back the
        // data to be copied is (offset).

        if tag_buf.len() == 2 {
            // 2.2.1. Copy with 1-byte offset (01)
            //
            // These elements can encode lengths between [4..11] bytes and offsets
            // between [0..2047] bytes. (len-4) occupies three bits and is stored
            // in bits [2..4] of the tag byte. The offset occupies 11 bits, of which the
            // upper three are stored in the upper three bits ([5..7]) of the tag byte,
            // and the lower eight are stored in a byte following the tag byte.

            let len = 4 + ((tag & 0x1C) >> 2);
            let offset = (((tag & 0xE0) as u32) << 3) | tag_buf[0] as u32;
            (offset, len)
        } else if tag_buf.len() == 3 {
            // 2.2.2. Copy with 2-byte offset (10)
            //
            // These elements can encode lengths between [1..64] and offsets from
            // [0..65535]. (len-1) occupies six bits and is stored in the upper
            // six bits ([2..7]) of the tag byte. The offset is stored as a
            // little-endian 16-bit integer in the two bytes following the tag byte.

            let len = 1 + (tag >> 2);
            let offset = LittleEndian::read_u16(tag_buf) as u32;
            (offset, len)
        } else {
            // 2.2.3. Copy with 4-byte offset (11)
            //
            // These are like the copies with 2-byte offsets (see previous subsection),
            // except that the offset is stored as a 32-bit integer instead of a
            // 16-bit integer (and thus will occupy four bytes).

            let len = 1 + (tag >> 2);
            let offset = LittleEndian::read_u32(tag_buf) as u32;
            (offset, len)
        }
    }

    fn decompress_copy<W: SnappyWrite>(&self,
                                       writer: &mut W,
                                       tag: u8,
                                       tag_buf: &[u8]) -> Result<()> {
        let (offset, len) = self.copy_offset_len(tag, tag_buf);

        if offset == 0 {
            // zero-length copies can't be encoded, no need to check for them
            return Err(FormatError("zero-length offset"));
        }

        try!(writer.write_from_self(offset, len));
        Ok(())
    }

    fn copy_bytes<W: SnappyWrite>(&mut self, writer: &mut W, mut remaining: usize) -> Result<()> {
        while remaining != 0 {
            let len = {
                let buf = try!(self.reader.fill_buf());
                if buf.is_empty() {
                    return Err(SnappyError::UnexpectedEOF);
                }

                let len = cmp::min(remaining, buf.len());
                try!(writer.write_all(&buf[..len]));
                len
            };
            self.reader.consume(len);

            remaining -= len;
        }

        Ok(())
    }
}

pub fn decompress<R: BufRead, W: SnappyWrite>(reader: &mut R,
                                              writer: &mut W)
                                              -> Result<()> {
    let uncompressed_length = try!(read_uncompressed_length(reader));
    writer.set_uncompressed_length(uncompressed_length);
    let mut decompressor = Decompressor::new(reader);
    decompressor.decompress(writer)
}

fn read_uncompressed_length<R: BufRead>(reader: &mut R) -> Result<u32> {
    let mut result: u32 = 0;
    let mut shift = 0;
    let mut success = false;
    let mut read = 1;
    // This is a bit convoluted due to working around a borrowing issue with buf and
    // reader.consume().
    match try!(reader.fill_buf()) {
        buf if buf.len() == 0 => return Err(FormatError("premature EOF")),
        buf => {
            for c in buf.iter() {
                if shift >= 32 {
                    return Err(FormatError("uncompressed length exceeds u32::MAX"));
                }
                result |= ((c & 0x7F) as u32) << shift;
                if (c & 0x80) == 0 {
                    success = true;
                    break;
                }
                shift += 7;
                read += 1;
            }
        }
    }
    if success {
        reader.consume(read);
        Ok(result)
    } else {
        Err(FormatError("unterminated uncompressed length"))
    }
}

impl SnappyWrite for Vec<u8> {
    fn write_from_self(&mut self, offset: u32, len: u8) -> io::Result<()> {
        let start = self.len() - offset as usize;
        let space_left = self.capacity() - self.len();
        if len <= 16 && offset >= 8 && space_left >= 16 {
            // Fast path
            assert!((offset as usize) <= self.len());
            unsafe {
                let src = self.as_ptr().offset(start as isize) as *const u64;
                let dst = self.as_mut_ptr().offset(self.len() as isize) as *mut u64;
                ptr::write(dst, ptr::read(src));
                ptr::write(dst.offset(1), ptr::read(src.offset(1)));
                let new_len = self.len() + len as usize;
                self.set_len(new_len);
            }
        } else {
            for i in 0..len as usize {
                let c = self[start + i];
                self.push(c);
            }
        }
        debug_assert_eq!(&self[start..start + len as usize],
                         &self[self.len() - len as usize..]);
        Ok(())
    }

    fn set_uncompressed_length(&mut self, length: u32) {
        self.reserve_exact(length as usize);
    }
}


#[cfg(test)]
mod test {
    use std::io::Cursor;
    // TODO rustc warns about unused import, but can not compile with out it
    use super::{read_uncompressed_length, SnappyWrite};

    #[test]
    fn test_read_uncompressed_length_long() {
        let inp = [0xFE, 0xFF, 0x7F];
        assert_eq!(read_uncompressed_length(&mut Cursor::new(&inp[..])).unwrap(),
                   2097150);
    }

    #[test]
    fn test_read_uncompressed_length_short() {
        let inp = [64];
        assert_eq!(read_uncompressed_length(&mut Cursor::new(&inp[..])).unwrap(),
                   64);
    }

    #[test]
    fn test_vec_write_from_self() {
        let mut xs = vec![1, 2, 3, 4];
        xs.write_from_self(3, 2).unwrap();
        assert_eq!(&xs[..], &[1, 2, 3, 4, 2, 3]);
    }

    #[test]
    fn test_vec_write_from_self_long() {
        let mut xs = vec![1, 2, 3];
        xs.write_from_self(2, 4).unwrap();
        assert_eq!(&xs[..], &[1, 2, 3, 2, 3, 2, 3]);
    }

    #[test]
    fn test_vec_write_from_self_fast_path() {
        let mut xs = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        xs.reserve(30);
        xs.write_from_self(9, 4).unwrap();
        assert_eq!(&xs[..], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 2, 3, 4, 5]);
    }

    #[test]
    fn test_vec_write_from_self_fast_path_bug() {
        let n = 273;
        let mut xs = Vec::with_capacity(n + 30);
        for i in 0..n {
            xs.push((i % 100) as u8);
        }
        let offset = 207;
        let len = 10;
        let start = xs.len() - offset as usize;
        xs.write_from_self(offset, len).unwrap();

        assert_eq!(xs.len(), n + len as usize);
        assert_eq!(&xs[start..start + len as usize],
                   &xs[xs.len() - len as usize..]);
    }
}
