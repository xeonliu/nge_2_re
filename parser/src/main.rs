use core::num;
use std::str::from_utf8;

use nom::bytes::streaming::tag;
use nom::bytes::streaming::take;
use nom::combinator::{flat_map, map, map_res};
use nom::error::{Error, ErrorKind};
use nom::multi::{count, length_data, many0, many_m_n};
use nom::number::complete::be_u16;
use nom::number::streaming::{le_u16, le_u32};
use nom::sequence::{pair, terminated, tuple};
use nom::{Err, IResult, Needed};

#[derive(Clone, Debug, PartialEq, Eq)]
enum Version {
    V1,
    V3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    version: Version,
    number: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffsetTable {
    offset: Vec<u32>,
}

pub fn header(input: &[u8]) -> IResult<&[u8], Header> {
    map(
        tuple((tag("HGAR"), le_u16, le_u16)),
        |(_, version, number)| {
            let version = match version {
                1 => Version::V1,
                3 => Version::V3,
                _ => panic!("Invalid version"),
            };
            Header { version, number }
        },
    )(input)
}

pub fn offset_table(input: &[u8], number: u16) -> IResult<&[u8], OffsetTable> {
    map(count(le_u32, number.into()), |offset| OffsetTable {
        offset,
    })(input)
}

#[derive(Debug)]
pub struct FileHeader<'a> {
    short_name: &'a str,
    encoded_identifier: u32,
    file_size: u32,
}

#[derive(Debug)]
pub struct FileData<'a> {
    data: &'a [u8],
}

pub fn file_header(input: &[u8]) -> IResult<&[u8], FileHeader> {
    let mut tpl = tuple((take::<usize, &[u8], Error<&[u8]>>(12usize), le_u32, le_u32));
    let (remain, (str, id, size)) = tpl(input).unwrap();
    Ok((
        remain,
        FileHeader {
            short_name: std::str::from_utf8(str).expect("Invalid UTF-8 Encoding!"),
            encoded_identifier: id,
            file_size: size,
        },
    ))
}

pub fn main() {
}

#[test]
fn hgar_header_test(){
    const HGAR: &[u8] = include_bytes!("../../game/PSP_GAME/USRDIR/btdemo/angel.har");
    // "HGAR", u16, u16
    let (remain, header) = header(&HGAR).unwrap();
    println!("{:?}", header);
    let (remain, table) = offset_table(remain, header.number).unwrap();
    println!("{:?}", table);
}

#[test]
fn file_header_test() {
    let data = include_bytes!("../../game/PSP_GAME/USRDIR/btdemo/angel.har");
    let (remain, file_header) = file_header(&data[9524..]).unwrap();
    println!("{file_header:?}")
}
