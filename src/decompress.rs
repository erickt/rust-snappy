//! 1. Preamble
//!
//! The stream starts with the uncompressed length (up to a maximum of 2^32 - 1),
//! stored as a little-endian varint. Varints consist of a series of bytes,
//! where the lower 7 bits are data and the upper bit is set iff there are
//! more bytes to be read. In other words, an uncompressed length of 64 would
//! be stored as 0x40, and an uncompressed length of 2097150 (0x1FFFFE)
//! would be stored as 0xFE 0xFF 0x7F.
//!
//!
//! 2. The compressed stream itself
//!
//! There are two types of elements in a Snappy stream: Literals and
//! copies (backreferences). There is no restriction on the order of elements,
//! except that the stream naturally cannot start with a copy. (Having
//! two literals in a row is never optimal from a compression point of
//! view, but nevertheless fully permitted.) Each element starts with a tag byte,
//! and the lower two bits of this tag byte signal what type of element will
//! follow:
//!
//!   00: Literal
//!   01: Copy with 1-byte offset
//!   10: Copy with 2-byte offset
//!   11: Copy with 4-byte offset
//!
//! The interpretation of the upper six bits are element-dependent.
//!
//!
//! 2.1. Literals (00)
//!
//! Literals are uncompressed data stored directly in the byte stream.
//! The literal length is stored differently depending on the length
//! of the literal:
//!
//!  - For literals up to and including 60 bytes in length, the upper
//!    six bits of the tag byte contain (len-1). The literal follows
//!    immediately thereafter in the bytestream.
//!  - For longer literals, the (len-1) value is stored after the tag byte,
//!    little-endian. The upper six bits of the tag byte describe how
//!    many bytes are used for the length; 60, 61, 62 or 63 for
//!    1-4 bytes, respectively. The literal itself follows after the
//!    length.
//!
//!
//! 2.2. Copies
//!
//! Copies are references back into previous decompressed data, telling
//! the decompressor to reuse data it has previously decoded.
//! They encode two values: The _offset_, saying how many bytes back
//! from the current position to read, and the _length_, how many bytes
//! to copy. Offsets of zero can be encoded, but are not legal;
//! similarly, it is possible to encode backreferences that would
//! go past the end of the block (offset > current decompressed position),
//! which is also nonsensical and thus not allowed.
//!
//! As in most LZ77-based compressors, the length can be larger than the offset,
//! yielding a form of run-length encoding (RLE). For instance,
//! "xababab" could be encoded as
//!
//!   <literal: "xab"> <copy: offset=2 length=4>
//!
//! Note that since the current Snappy compressor works in 32 kB
//! blocks and does not do matching across blocks, it will never produce
//! a bitstream with offsets larger than about 32768. However, the
//! decompressor should not rely on this, as it may change in the future.
//!
//! There are several different kinds of copy elements, depending on
//! the amount of bytes to be copied (length), and how far back the
//! data to be copied is (offset).
//!
//!
//! 2.2.1. Copy with 1-byte offset (01)
//!
//! These elements can encode lengths between [4..11] bytes and offsets
//! between [0..2047] bytes. (len-4) occupies three bits and is stored
//! in bits [2..4] of the tag byte. The offset occupies 11 bits, of which the
//! upper three are stored in the upper three bits ([5..7]) of the tag byte,
//! and the lower eight are stored in a byte following the tag byte.
//!
//!
//! 2.2.2. Copy with 2-byte offset (10)
//!
//! These elements can encode lengths between [1..64] and offsets from
//! [0..65535]. (len-1) occupies six bits and is stored in the upper
//! six bits ([2..7]) of the tag byte. The offset is stored as a
//! little-endian 16-bit integer in the two bytes following the tag byte.
//!
//!
//! 2.2.3. Copy with 4-byte offset (11)
//!
//! These are like the copies with 2-byte offsets (see previous subsection),
//! except that the offset is stored as a 32-bit integer instead of a
//! 16-bit integer (and thus will occupy four bytes).

use std::cmp;
use std::io::{Write, Read, BufRead};
use std::io;
use std::ptr;
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
    ZeroLengthOffset,
    FormatError(&'static str),
    IoError(io::Error),
}

impl From<io::Error> for SnappyError {
    #[inline]
    fn from(err: io::Error) -> Self {
        SnappyError::IoError(err)
    }
}

impl From<byteorder::Error> for SnappyError {
    #[inline]
    fn from(err: byteorder::Error) -> Self {
        match err {
            byteorder::Error::UnexpectedEOF => SnappyError::UnexpectedEOF,
            byteorder::Error::Io(err) => SnappyError::IoError(err),
        }
    }
}

pub type Result<T> = result::Result<T, SnappyError>;

macro_rules! try_back_ref {
    ($e: expr) => {
        match $e {
            Ok(v) => v,
            Err(err) => { return LiteralResult::from(err); }
        }
    }
}

/*
#[inline(always)]
fn parse_tag_size<'a, W: SnappyWrite>(writer: &mut W,
                                      tag_byte: u8,
                                      tag_len: &[u8],
                                      buf: &'a [u8]) -> LiteralResult<'a> {
    match tag_byte & 0b11 {
        // 2.1. Literals (00)
        0b00 => {
            literal(writer, tag_byte, tag_len, buf)
        }

        // 2.2.1. Copy with 1-byte offset (01)
        0b01 => {
            let (offset, len) = copy_with_1_byte_offset(tag_byte, tag_len);
            try_back_ref!(write_back_reference(writer, offset, len));
            LiteralResult::Ok(buf)
        }

        // 2.2.2. Copy with 2-byte offset (10)
        0b10 => {
            let (offset, len) = copy_with_2_byte_offset(tag_byte, tag_len);
            try_back_ref!(write_back_reference(writer, offset, len));
            LiteralResult::Ok(buf)
        }

        // 2.2.3. Copy with 4-byte offset (11)
        _ => {
            let (offset, len) = copy_with_4_byte_offset(tag_byte, tag_len);
            try_back_ref!(write_back_reference(writer, offset, len));
            LiteralResult::Ok(buf)
        }
    }
}

#[inline(always)]
fn write_back_reference<W: SnappyWrite>(writer: &mut W,
                                        offset: u32,
                                        len: u8) -> Result<()> {
    if offset == 0 {
        // zero-length copies can't be encoded, no need to check for them
        return Err(SnappyError::ZeroLengthOffset);
    }

    try!(writer.write_from_self(offset, len));

    Ok(())
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

struct PartialTag {
    tag: [u8; MAX_TAG_LEN],
    tag_size: usize,
    read: usize,
}

impl PartialTag {
    fn remaining(&self) -> usize {
        self.tag_size - self.read
    }

    fn reset(&mut self, tag_size: usize) {
        self.tag_size = tag_size;
        self.read = 0;
    }

    fn tag(&self) -> (u8, &[u8]) {
        assert_eq!(self.tag_size, self.read);

        let tag_byte = self.tag[0];
        let tag_len = &self.tag[1..self.tag_size];

        (tag_byte, tag_len)
    }

    fn is_whole(&self) -> bool {
        self.tag_size == self.read
    }

    fn read(&mut self, buf: &[u8]) {
        let len = cmp::min(self.remaining(), buf.len());

        for i in 0 .. len {
            self.tag[self.read + i] = buf[i];
        }

        self.read += len;
    }
}
*/

fn literal_len(tag_byte: u8, tag_size: usize, tag_buf: &[u8; MAX_TAG_LEN]) -> usize {
    let len = match tag_size {
        1 => (tag_byte >> 2) as usize,
        2 => tag_buf[1] as usize,
        3 => LittleEndian::read_u16(&tag_buf[1..]) as usize,
        4 => (LittleEndian::read_u32(&tag_buf[1..]) as usize) & 0x00FFFFFF,
        _ => LittleEndian::read_u32(&tag_buf[1..]) as usize,
    };

    len + 1
}

/*
enum LiteralResult<'a> {
    Ok(&'a [u8]),
    Err(SnappyError),
    PartialLiteral(usize),
}

impl<'a> From<io::Error> for LiteralResult<'a> {
    fn from(err: io::Error) -> Self {
        Self::from(SnappyError::from(err))
    }
}

impl<'a> From<SnappyError> for LiteralResult<'a> {
    fn from(err: SnappyError) -> Self {
        LiteralResult::Err(err)
    }
}

fn literal<'a, W: SnappyWrite>(writer: &mut W,
                               tag_byte: u8,
                               tag_len: &[u8],
                               buf: &'a [u8]) -> LiteralResult<'a> {
    let len = literal_len(tag_byte, tag_len);

    if len <= buf.len() {
        let (lhs, rhs) = buf.split_at(len);

        match writer.write_all(lhs) {
            Ok(()) => LiteralResult::Ok(rhs),
            Err(err) => LiteralResult::Err(SnappyError::from(err)),
        }
    } else {
        match writer.write_all(buf) {
            Ok(()) => LiteralResult::PartialLiteral(len - buf.len()),
            Err(err) => LiteralResult::Err(SnappyError::from(err)),
        }
    }
}
*/

fn copy_with_1_byte_offset(tag_byte: u8, tag: &[u8; MAX_TAG_LEN]) -> (u32, u8) {
    let len = 4 + ((tag_byte & 0b0001_1100) >> 2);
    let offset = (((tag_byte & 0b1110_0000) as u32) << 3) | tag[1] as u32;

    (offset, len)
}

fn copy_with_2_byte_offset(tag_byte: u8, tag: &[u8; MAX_TAG_LEN]) -> (u32, u8) {
    let len = 1 + (tag_byte >> 2);
    let offset = LittleEndian::read_u16(&tag[1..]) as u32;

    (offset, len)
}

fn copy_with_4_byte_offset(tag_byte: u8, tag: &[u8; MAX_TAG_LEN]) -> (u32, u8) {
    let len = 1 + (tag_byte >> 2);
    let offset = LittleEndian::read_u32(&tag[1..]) as u32;

    (offset, len)
}

/*
fn decompress_tag<W: SnappyWrite>(context: &mut Context<W>,
                                  mut buf: &[u8]) -> Result<State> {
    loop {
        // 2. Grab the first byte, which is the tag byte that describes the element.
        let tag_byte = buf[0];

        // The element tag itself is variable sized, and it's size is encoded in the tag byte.
        let tag_size = get_tag_size(tag_byte);

        // We need to parse out the next `tag_size` bytes in order to determine the size of this
        // block, but we might not actually have enough bytes available in our buffer. So we'll
        // make a fast and slow path. The fast path reuses `self.buf`, and the slow path will cache
        // the partially read tag so it can be merged with the next chunk of bytes.
        
        if buf.len() < tag_size {
            //println!("read_tag: partial_tag: {} {}", tag_size, buf.len());
            context.partial_tag.reset(tag_size);
            context.partial_tag.read(buf);

            return Ok(State::PartialTag);
        }
        
        let (tag_len, rhs) = buf.split_at(tag_size);
        buf = rhs;

        let result = match tag_byte & 0b11 {
            // 2.1. Literals (00)
            0b00 => {
                literal(&mut context.writer, tag_byte, tag_len, buf)
            }

            // 2.2.1. Copy with 1-byte offset (01)
            0b01 => {
                let (offset, len) = copy_with_1_byte_offset(tag_byte, tag_len);
                try!(write_back_reference(&mut context.writer, offset, len));
                LiteralResult::Ok(buf)
            }

            // 2.2.2. Copy with 2-byte offset (10)
            0b10 => {
                let (offset, len) = copy_with_2_byte_offset(tag_byte, tag_len);
                try!(write_back_reference(&mut context.writer, offset, len));
                LiteralResult::Ok(buf)
            }

            // 2.2.3. Copy with 4-byte offset (11)
            _ => {
                let (offset, len) = copy_with_4_byte_offset(tag_byte, tag_len);
                try!(write_back_reference(&mut context.writer, offset, len));
                LiteralResult::Ok(buf)
            }
        };

        //let result = parse_tag_size(&mut context.writer, tag_byte, tag_len, buf);

        buf = match result {
            LiteralResult::Ok(buf) => buf,
            LiteralResult::Err(err) => {
                return Err(SnappyError::from(err));
            }
            LiteralResult::PartialLiteral(remaining) => {
                return Ok(State::PartialLiteral(remaining));
            }
        };

        if buf.is_empty() {
            return Ok(State::Empty);
        }
    }
}

fn decompress_partial_tag<W: SnappyWrite>(context: &mut Context<W>, buf: &[u8]) -> Result<State> {
    {
        let Context { ref mut writer, ref mut partial_tag } = *context;
        partial_tag.read(buf);

        if partial_tag.is_whole() {
            return Ok(State::PartialTag);
        }

        let (tag_byte, tag_len) = partial_tag.tag();

        match parse_tag_size(writer, tag_byte, tag_len, buf) {
            LiteralResult::Ok(buf) => {
                if buf.is_empty() {
                    return Ok(State::Empty);
                }
            }

            LiteralResult::PartialLiteral(remaining) => {
                return Ok(State::PartialLiteral(remaining));
            }

            LiteralResult::Err(err) => {
                return Err(err);
            }
        }
    }

    decompress_tag(context, buf)
}

fn decompress_partial_literal<W: SnappyWrite>(context: &mut Context<W>,
                                              buf: &[u8],
                                              remaining: usize) -> Result<State>
{
    let len = cmp::min(remaining, buf.len());
    let (lhs, rhs) = buf.split_at(len);

    try!(context.writer.write_all(lhs));

    if len < remaining {
        Ok(State::PartialLiteral(remaining - len))
    } else if buf.is_empty() {
        Ok(State::Empty)
    } else {
        decompress_tag(context, rhs)
    }
}

#[derive(Copy, Clone)]
enum State {
    Empty,
    PartialTag,
    PartialLiteral(usize),
}
*/

enum State {
    ParseTag,
    ParseTagSize,
    ParsePartialTagSize,
    ParsePartialLiteral,
}

/*
struct Context<W> {
    writer: W,
    partial_tag: PartialTag,
}
*/

struct BytesDecompressor<W: SnappyWrite> {
    writer: W,
    state: State,
    tag_size: usize,
    tag_buf: [u8; MAX_TAG_LEN],
    read: usize,
}

impl<W: SnappyWrite> BytesDecompressor<W> {
    fn decompress(&mut self, mut buf: &[u8]) -> Result<()> {
        loop {
            //println!("----");
            //println!("inner: {:?}", buf);
            
            match self.state {
                State::ParseTag => {
                    if buf.is_empty() {
                        return Err(SnappyError::UnexpectedEOF);
                    }

                    buf = try!(self.parse_tag(buf));
                }
                State::ParseTagSize => {
                    buf = try!(self.parse_tag_size(buf));
                }
                State::ParsePartialTagSize => {
                    if buf.is_empty() {
                        return Err(SnappyError::UnexpectedEOF);
                    }

                    buf = self.parse_partial_tag_size(buf);
                }
                State::ParsePartialLiteral => {
                    if buf.is_empty() {
                        return Err(SnappyError::UnexpectedEOF);
                    }

                    buf = try!(self.parse_partial_literal(buf));
                }
            };

            if buf.is_empty() {
                return Ok(());
            }
        }
    }

    #[inline(always)]
    fn parse_tag<'a>(&mut self, buf: &'a [u8]) -> Result<&'a [u8]> {
        //println!("ParseTag");

        // 2. Grab the first byte, which is the tag byte that describes the
        //    element.
        let tag_byte = buf[0];

        // The element tag itself is variable sized, and it's size is encoded in
        // the tag byte.
        self.tag_size = get_tag_size(tag_byte);

        // We need to parse out the next `tag_size` bytes in order to determine the
        // size of this block, but we might not actually have enough bytes
        // available in our buffer. So we'll make a fast and slow path. The fast
        // path reuses `self.buf`, and the slow path will cache the partially read
        // tag so it can be merged with the next chunk of bytes.

        //println!("ParseTag1: {} {}", self.tag_byte, self.tag_size);

        self.read = cmp::min(buf.len(), self.tag_size);

        for i in 0 .. self.read {
            self.tag_buf[i] = buf[i];
        }

        if self.read != self.tag_size {
            self.state = State::ParsePartialTagSize;

            Ok(&[])
        } else {
            //self.state = State::ParseTagSize;

            let buf = &buf[self.tag_size..];
            self.parse_tag_size(buf)
        }
    }

    #[inline(always)]
    fn parse_tag_size<'a>(&mut self, mut buf: &'a [u8]) -> Result<&'a [u8]> {
        let tag_byte = self.tag_buf[0];

        match tag_byte & 0b11 {
            // 2.1. Literals (00)
            0b00 => {
                let len = literal_len(tag_byte, self.tag_size, &self.tag_buf);

                let remaining = try!(self.parse_literal(len, buf));

                if remaining == 0 {
                    buf = &buf[len..];
                    self.read = 0;
                    self.state = State::ParseTag;
                } else {
                    buf = &[];
                    self.read = remaining;
                    self.state = State::ParsePartialLiteral;
                }
            }

            // 2.2.1. Copy with 1-byte offset (01)
            0b01 => {
                let (offset, len) = copy_with_1_byte_offset(tag_byte, &self.tag_buf);
                try!(self.parse_back_ref(offset, len));

                self.state = State::ParseTag;
            }

            // 2.2.2. Copy with 2-byte offset (10)
            0b10 => {
                let (offset, len) = copy_with_2_byte_offset(tag_byte, &self.tag_buf);
                try!(self.parse_back_ref(offset, len));

                self.state = State::ParseTag;
            }

            // 2.2.3. Copy with 4-byte offset (11)
            _ => {
                let (offset, len) = copy_with_4_byte_offset(tag_byte, &self.tag_buf);
                try!(self.parse_back_ref(offset, len));

                self.state = State::ParseTag;
            }
        }

        Ok(buf)
    }

    #[inline(always)]
    fn parse_literal(&mut self, len: usize, buf: &[u8]) -> io::Result<usize> {
        let read_len = cmp::min(len, buf.len());

        try!(self.writer.write_all(&buf[..read_len]));

        Ok(len - read_len)
    }

    #[inline(always)]
    fn parse_back_ref(&mut self, offset: u32, len: u8) -> Result<()> {
        if offset == 0 {
            // zero-length copies can't be encoded, no need to check for them
            return Err(SnappyError::ZeroLengthOffset);
        }

        try!(self.writer.write_from_self(offset, len));
        Ok(())
    }

    #[inline(always)]
    fn parse_partial_tag_size<'a>(&mut self, buf: &'a [u8]) -> &'a [u8] {
        let remaining = self.tag_size - self.read;
        let len = cmp::min(remaining, buf.len());

        {
            let tag_buf = &mut self.tag_buf[self.read..self.tag_size];

            for (dst, src) in tag_buf.iter_mut().zip(buf.iter()) {
                *dst = *src;
            }
        }

        if remaining == len {
            self.state = State::ParseTagSize;
            &buf[len..]
        } else {
            self.read += len;
            self.state = State::ParsePartialTagSize;
            &[]
        }
    }

    #[inline(always)]
    fn parse_partial_literal<'a>(&mut self, buf: &'a [u8]) -> Result<&'a [u8]> {
        //println!("ParsePartialLiteral: {} {:?}", len, buf);
        
        if buf.is_empty() {
            return Err(SnappyError::UnexpectedEOF);
        }

        let read = self.read;
        self.read = try!(self.parse_literal(read, buf));

        if self.read == 0 {
            self.state = State::ParseTag;
            Ok(&buf[self.read..])
        } else {
            self.state = State::ParsePartialLiteral;
            Ok(&[])
        }
    }
}

struct Decompressor<R> {
    reader: R,
}

impl<R: BufRead> Decompressor<R> {
    fn new(reader: R) -> Decompressor<R> {
        Decompressor {
            reader: reader,
        }
    }

    fn decompress<W: SnappyWrite>(&mut self, writer: &mut W) -> Result<()> {
        let mut decompressor = BytesDecompressor {
            writer: writer,
            state: State::ParseTag,
            tag_size: 0,
            tag_buf: [0; MAX_TAG_LEN],
            read: 0,
        };

        loop {
            let buf_len = {
                let buf = try!(self.reader.fill_buf());
                if buf.is_empty() {
                    return Ok(());
                }

                try!(decompressor.decompress(buf));

                buf.len()
            };

            //println!("original_buf_len: {}", original_buf_len);

            self.reader.consume(buf_len);
        }
    }



    /*
    fn decompress2<W: SnappyWrite>(&mut self, writer: &mut W) -> Result<()> {
        let mut context = Context {
            writer: writer,
            partial_tag: PartialTag {
                tag: [0; MAX_TAG_LEN],
                tag_size: 0,
                read: 0,
            },
        };

        loop {
            let buf_len = {
                let buf = try!(self.reader.fill_buf());
                if buf.is_empty() {
                    return Ok(());
                }

                match self.state {
                    State::Empty => {
                        self.state = try!(decompress_tag(&mut context, buf));
                    }
                    State::PartialTag => {
                        self.state = try!(decompress_partial_tag(&mut context, buf));
                    }
                    State::PartialLiteral(remaining) => {
                        self.state = try!(decompress_partial_literal(&mut context, buf, remaining));
                    }
                }

                buf.len()
            };

            self.reader.consume(buf_len);
        }
    }
    */

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

impl<'a, W> SnappyWrite for &'a mut W where W: SnappyWrite {
    fn write_from_self(&mut self, offset: u32, len: u8) -> io::Result<()> {
        (**self).write_from_self(offset, len)
    }

    fn set_uncompressed_length(&mut self, length: u32) {
        (**self).set_uncompressed_length(length)
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
