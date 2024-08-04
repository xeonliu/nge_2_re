use core::num;
use std::str::from_utf8;

use nom::bytes::complete::take_while1;
use nom::bytes::streaming::tag;
use nom::bytes::streaming::take;
use nom::combinator::{flat_map, map, map_res};
use nom::error::{Error, ErrorKind};
use nom::multi::{count, length_data, many0, many_m_n};
use nom::number::complete::be_u16;
use nom::number::streaming::le_u64;
use nom::number::streaming::{le_u16, le_u32};
use nom::sequence::{pair, terminated, tuple};
use nom::{Err, IResult, Needed};

pub struct Hgar {
    header_: Header,
    offset_table_: Vec<u32>,
    unknowns_: Option<Vec<u64>>,
    long_name_table_: Option<LongNameTable>,
    files_: Vec<FileContent>,
}

pub struct Header {
    version: u16,
    number: u16,
}

pub struct LongNameTable {
    num_name_pair: Vec<(u32, Vec<u8>)>,
}

pub struct FileContent {
    short_name_: String,
    encoded_identifier_: u32,
    content_: Vec<u8>,
    // Logically, Decoded Content.
}

pub fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    map(
        tuple((tag("HGAR"), le_u16, le_u16)),
        |(_, version, number)| Header { version, number },
    )(input)
}

pub fn parse_offsets(intput: &[u8], number: u16) -> IResult<&[u8], Vec<u32>> {
    count(le_u32, number.into())(intput)
}

pub fn parse_unknows(input: &[u8], number: u16) -> IResult<&[u8], Vec<u64>> {
    count(le_u64, number.into())(input)
}

pub fn parse_longname_pair(input: &[u8], number: u16) -> IResult<&[u8], (u32, Vec<u8>)> {
    // Read until null terminator, but align to 32 bits.
    let (remain, index) = le_u32(input)?;

    let mut i = 0;
    while i < input.len() && remain[i] != 0 {
        i += 1;
    }

    // Align to 4 bytes.

    i = i + (4 - i % 4);

    Ok((&remain[i..], (index, input[..i].to_vec())))
}

pub fn parse_entry(file: &[u8], offset: u32) -> IResult<&[u8], FileContent> {
    let input = &file[offset..];
    let (remain, short_name) = take(0xC)(input)?;
    let (remain, encoded_id) = le_u32(remain)?;
    let (remain, file_size) = le_u32(remain)?;
    let (remain, content) = take(file_size)(remain)?;
    Ok((
        remain,
        FileContent {
            short_name_: short_name,
            encoded_identifier_: encoded_id,
            content_: content.clone(),
        },
    ))
}
