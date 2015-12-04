use std::io::{Write, BufRead};
use std::io;
use std::ptr;
use std::cmp;
use std::u16;
use std::u32;
use std::result;

use self::SnappyError::*;

include!(concat!(env!("OUT_DIR"), "/tables.rs"));

const MAX_TAG_LEN: usize = 5;

pub trait SnappyWrite : Write {
    fn write_from_self(&mut self, offset: u32, len: u8) -> io::Result<()>;
    fn set_uncompressed_length(&mut self, length: u32);
}

#[derive(Debug)]
pub enum SnappyError {
    FormatError(&'static str),
    IoError(io::Error),
}

impl From<io::Error> for SnappyError {
    fn from(err: io::Error) -> Self {
        SnappyError::IoError(err)
    }
}

pub type Result<T> = result::Result<T, SnappyError>;

struct Decompressor<R> {
    reader: R,
    tmp: [u8; MAX_TAG_LEN],
    buf: *const u8,
    buf_end: *const u8,
    read: usize,
}

macro_rules! try_advance_tag {
    ($me: expr) => (
        match $me.advance_tag() {
            Ok(0)        => return Ok(()),
            Ok(tag_size) => tag_size,
            Err(e)       => return Err(e)
        }
    )
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
            tmp: [0; MAX_TAG_LEN],
            buf: ptr::null(),
            buf_end: ptr::null(),
            read: 0,
        }
    }

    fn advance_tag(&mut self) -> Result<usize> {
        unsafe {
            let buf;
            let buf_end;
            let mut buf_len;
            if self.available() == 0 {
                self.reader.consume(self.read);
                let (b, be) = read_new_buffer!(self);
                buf = b;
                buf_end = be;
                buf_len = buf_end as usize - buf as usize;
                self.read = buf_len;
            } else {
                buf = self.buf;
                buf_end = self.buf_end;
                buf_len = self.available();
            };
            let tag = ptr::read(buf);
            let tag_size = get_tag_size(tag);
            if buf_len < tag_size {
                ptr::copy(buf, self.tmp.as_mut_ptr(), buf_len);
                self.reader.consume(self.read);
                self.read = 0;
                while buf_len < tag_size {
                    let (newbuf, newbuf_end) = read_new_buffer!(self,
                                                                return Err(FormatError("EOF whi\
                                                                                        le read\
                                                                                        ing tag")));
                    let newbuf_len = newbuf_end as usize - newbuf as usize;

                    // How many bytes should we read from the new buffer?
                    let to_read = cmp::min(tag_size - buf_len, newbuf_len);

                    ptr::copy_nonoverlapping(newbuf,
                                             self.tmp.as_mut_ptr().offset(buf_len as isize),
                                             to_read);
                    buf_len += to_read;
                    self.reader.consume(to_read);
                }
                self.buf = self.tmp.as_ptr();
                self.buf_end = self.buf.offset(tag_size as isize);
            } else if buf_len < MAX_TAG_LEN {
                ptr::copy(buf, self.tmp.as_mut_ptr(), buf_len);
                self.reader.consume(self.read);
                self.read = 0;
                self.buf = self.tmp.as_ptr();
                self.buf_end = self.buf.offset(buf_len as isize);
            } else {
                self.buf = buf;
                self.buf_end = buf_end;
            }
            Ok(tag_size)
        }
    }

    fn decompress<W: SnappyWrite>(&mut self, writer: &mut W) -> Result<()> {
        loop {
            let tag_size = try_advance_tag!(self);
            let tag = self.read_u8();
            if tag & 0x03 == 0 {
                try!(self.decompress_literal(writer, tag, tag_size))
            } else {
                try!(self.decompress_copy(writer, tag, tag_size))
            }
        }
    }

    fn decompress_literal<W: SnappyWrite>(&mut self, writer: &mut W, tag: u8, tag_size: usize) -> Result<()> {
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

        let literal_len = if tag_size == 1 {
            (tag >> 2) as u32
        } else if tag_size == 2 {
            self.read_u8() as u32
        } else if tag_size == 3 {
            self.read_u16_le() as u32
        } else if tag_size == 4 {
            self.read_u24_le()
        } else {
            self.read_u32_le()
        } + 1;

        self.copy_bytes(writer, literal_len as usize)
    }

    fn decompress_copy<W: SnappyWrite>(&mut self, writer: &mut W, tag: u8, tag_size: usize) -> Result<()> {
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

        let (copy_len, copy_offset) = if tag_size == 2 {
            // 2.2.1. Copy with 1-byte offset (01)
            //
            // These elements can encode lengths between [4..11] bytes and offsets
            // between [0..2047] bytes. (len-4) occupies three bits and is stored
            // in bits [2..4] of the tag byte. The offset occupies 11 bits, of which the
            // upper three are stored in the upper three bits ([5..7]) of the tag byte,
            // and the lower eight are stored in a byte following the tag byte.

            let len = 4 + ((tag & 0x1C) >> 2);
            let offset = (((tag & 0xE0) as u32) << 3) | self.read_u8() as u32;
            (len, offset)
        } else if tag_size == 3 {
            // 2.2.2. Copy with 2-byte offset (10)
            //
            // These elements can encode lengths between [1..64] and offsets from
            // [0..65535]. (len-1) occupies six bits and is stored in the upper
            // six bits ([2..7]) of the tag byte. The offset is stored as a
            // little-endian 16-bit integer in the two bytes following the tag byte.

            let len = 1 + (tag >> 2);
            let offset = self.read_u16_le() as u32;
            (len, offset)
        } else {
            // 2.2.3. Copy with 4-byte offset (11)
            //
            // These are like the copies with 2-byte offsets (see previous subsection),
            // except that the offset is stored as a 32-bit integer instead of a
            // 16-bit integer (and thus will occupy four bytes).

            let len = 1 + (tag >> 2);
            let offset = self.read_u32_le();
            (len, offset)
        };

        if copy_offset == 0 {
            // zero-length copies can't be encoded, no need to check for them
            return Err(FormatError("zero-length offset"));
        }

        try!(writer.write_from_self(copy_offset, copy_len));
        Ok(())
    }

    fn copy_bytes<W: SnappyWrite>(&mut self, writer: &mut W, mut remaining: usize) -> Result<()> {
        while self.available() < remaining {
            let available = self.available();
            try!(writer.write_all(self.read(available)));
            remaining -= available;
            self.reader.consume(self.read);
            match try!(self.reader.fill_buf()) {
                b if b.len() == 0 => {
                    return Err(FormatError("EOF while reading literal"));
                }
                b => {
                    self.buf = b.as_ptr();
                    self.buf_end = unsafe { b.as_ptr().offset(b.len() as isize) };
                    self.read = b.len();
                }
            }
        }
        try!(writer.write_all(self.read(remaining)));
        Ok(())
    }

    fn read(&mut self, n: usize) -> &[u8] {
        assert!(n as usize <= self.available());
        let r = unsafe { ::std::slice::from_raw_parts(self.buf, n) };
        self.advance(n);
        return r;
    }

    fn advance(&mut self, n: usize) {
        assert!(self.available() >= n);
        self.buf = unsafe { self.buf.offset(n as isize) };
    }

    fn available(&self) -> usize {
        self.buf_end as usize - self.buf as usize
    }

    fn _get_buf(&self) -> &[u8] {
        unsafe { ::std::slice::from_raw_parts(self.buf, self.available()) }
    }

    fn read_u8(&mut self) -> u8 {
        self.read(1)[0]
    }

    fn read_u16_le(&mut self) -> u16 {
        let p = self.read(2).as_ptr() as *const u16;
        let x = unsafe { ptr::read(p) };
        u16::from_le(x)
    }

    fn read_u24_le(&mut self) -> u32 {
        let p = self.read(3).as_ptr() as *const u32;
        let x = unsafe { ptr::read(p) };
        u32::from_le(x) & 0x00FFFFFF
    }

    fn read_u32_le(&mut self) -> u32 {
        let p = self.read(4).as_ptr() as *const u32;
        let x = unsafe { ptr::read(p) };
        u32::from_le(x)
    }
}

#[inline(never)]
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
    #[inline]
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
