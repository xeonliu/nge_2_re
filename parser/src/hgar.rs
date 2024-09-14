// use core::num;
// use std::str::from_utf8;

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress};
use nom::number::streaming::le_u32;
use std::{error::Error, fs::File, os::raw, vec};
// use nom::bytes::complete::take_while1;
// use nom::bytes::streaming::tag;
// use nom::bytes::streaming::take;
// use nom::combinator::{flat_map, map, map_res};
// use nom::error::{Error, ErrorKind};
// use nom::multi::{count, length_data, many0, many_m_n};
// use nom::number::complete::be_u16;
// use nom::number::streaming::le_u64;
// use nom::number::streaming::{le_u16, le_u32};
// use nom::sequence::{pair, terminated, tuple};
// use nom::{Err, IResult, Needed};

struct Header {
    version: u16,
    number: u16,
    offsets: Vec<u32>,
}

impl Header {
    fn new(input: &[u8]) {
        todo!()
    }
}

struct LongNameEntry {
    unknown: u32,
    name: String,
}

struct FileContent {
    name: String,
    // is_compressed & identifier determines the encoded_identifier?
    // Not implemented here.
    encoded_identifier: u32, // Can it be None? I don't understand.
    content: Vec<u8>,
}

// Parse Compressed Content
// 2 byte: Decompressed Content Size
// Others: Compressed Content

// How to decompress?
// 1. zlib.decompress(content, -15)
// 2. align to 4 byte
fn decompress(compressed_bin: &[u8]) -> Result<Vec<u8>, Box<dyn Error + '_>> {
    // get decompressed content size
    let (remain, size) = le_u32::<&[u8], ()>(compressed_bin)?;
    println!("{:?}", size);
    let mut raw_bin: Vec<u8> = vec![0; size as usize];
    let status = Decompress::new(false) // Do not contain a zlib header
        .decompress(remain, &mut raw_bin, FlushDecompress::Finish)?;
    println!("{:?}", status);

    // align to 4 byte with tailing zeros
    let aligned_len = 4 * ((raw_bin.len() + 3) / 4);

    // TODO: why resize only when decompressing ???
    assert_eq!(aligned_len, size as usize);
    raw_bin.resize(aligned_len, 0);
    return Ok(raw_bin);
}

// How to compress?
// 1. Calculate the decompressed size
// 2. zlib.compress()[2:-4]
// Skip 2 byte header and four byte checksum at end (Can be set using other params.)
fn compress(uncompressed_bin: &[u8]) -> Result<Vec<u8>, Box<dyn Error + '_>> {
    // Type Conversion? try_into();
    let size: u32 = uncompressed_bin
        .len()
        .try_into()
        .expect("Size out of range");

    let mut compressed_bin: Vec<u8> = vec![0; size as usize];
    let mut compressor = Compress::new(Compression::best(), false);
    println!("total input: {}", compressor.total_in());
    let result = compressor.compress(
        &uncompressed_bin,
        &mut compressed_bin,
        FlushCompress::Finish,
    )?;
    println!(
        "total output: {}, result {:?}",
        compressor.total_out(),
        result
    );
    compressed_bin.resize(compressor.total_out() as usize, 0);

    let mut result = Vec::with_capacity(4 + compressed_bin.len());
    result.extend_from_slice(&(size as u32).to_le_bytes());
    result.extend_from_slice(&compressed_bin);

    Ok(result)

    // Compressed Size doesn't match?
}

// Test here. Whether Compressed content is the same with the original one?
mod compression_test {
    use super::decompress;

    use super::compress;

    const compressed_file: &[u8] =
        include_bytes!("../../game/PSP_GAME/USRDIR/btdemo/angel.har.HGARPACK/01_eva3#id6876.hpt");
    const decompressed_file: &[u8] = include_bytes!(
        "../../game/PSP_GAME/USRDIR/btdemo/angel.har.HGARPACK/01_eva3#id6876.hpt.DECOMPRESSED"
    );

    #[test]
    fn test_decompress() {
        let result = decompress(compressed_file).unwrap();

        println!("{:?}", result.len());
        println!("{:?}", decompressed_file.len());
        assert_eq!(decompressed_file, result);
    }

    #[test]
    fn test_compress() {
        let result = compress(decompressed_file).unwrap();

        let de_res = decompress(&result).unwrap();

        assert_eq!(de_res.len(), decompressed_file.len());

        // Size Do not Match.
        // assert_eq!(compressed_file.len(), result.len());
    }
}

impl FileContent {
    fn parse(input: &[u8]) -> Self {
        todo!();
    }

    fn is_compressed(&self) -> bool {
        (self.encoded_identifier >> 31) == 1
    }

    fn replace_with_raw(&mut self, raw_content: &[u8]) {
        if self.is_compressed() {
            // Toggle off the Compression Flag??
            self.encoded_identifier &= 0x7FFFFFFF;
        }
        // TODO: Compress when required?
        self.content = raw_content.into();
    }
}

// Two kinds of HGAR file

enum HGAR {
    V1(HgarV1),
    V3(HgarV3),
}

struct HgarV1 {
    header: Header,
    files: Vec<FileContent>,
}

struct HgarV3 {
    header: Header,
    unknowns: Vec<u64>,
    long_names: Vec<LongNameEntry>,
    files: Vec<FileContent>,
}

trait Hgar {
    fn replace(&mut self, short_name: String, content: &[u8]);
    // fn encrypt(content: &[u8]) -> Vec<u8>;
    // fn export();
    // fn export_info();
}

impl Hgar for HgarV1 {
    fn replace(&mut self, short_name: String, content: &[u8]) {
        todo!();
    }
}

impl Hgar for HgarV3 {
    fn replace(&mut self, short_name: String, content: &[u8]) {
        todo!();
    }
}

// No need to explicitly create a struct...
struct HGARFactory;

impl HGARFactory {
    // Create an instance of a HGAR file using binary input
    fn parse(input: &[u8]) -> Box<dyn Hgar> {
        // Parse the header
        todo!();
    }
}

fn encoded_identifier(limit: u32) {}

#[test]
fn test_replace() -> Result<(), Box<dyn Error>> {
    // Input HGAR File
    let mut file = HGARFactory::parse(&vec![1, 2, 3]);
    file.replace("string".into(), &vec![123]);

    return Ok(());
}

// pub fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
//     map(
//         tuple((tag("HGAR"), le_u16, le_u16)),
//         |(_, version, number)| Header { version, number },
//     )(input)
// }

// pub fn parse_offsets(intput: &[u8], number: u16) -> IResult<&[u8], Vec<u32>> {
//     count(le_u32, number.into())(intput)
// }

// pub fn parse_unknows(input: &[u8], number: u16) -> IResult<&[u8], Vec<u64>> {
//     count(le_u64, number.into())(input)
// }

// pub fn parse_longname_pair(input: &[u8], number: u16) -> IResult<&[u8], (u32, Vec<u8>)> {
//     // Read until null terminator, but align to 32 bits.
//     let (remain, index) = le_u32(input)?;

//     let mut i = 0;
//     while i < input.len() && remain[i] != 0 {
//         i += 1;
//     }

//     // Align to 4 bytes.

//     i = i + (4 - i % 4);

//     Ok((&remain[i..], (index, input[..i].to_vec())))
// }

// pub fn parse_entry(file: &[u8], offset: u32) -> IResult<&[u8], FileContent> {
//     let input = &file[offset..];
//     let (remain, short_name) = take(0xC)(input)?;
//     let (remain, encoded_id) = le_u32(remain)?;
//     let (remain, file_size) = le_u32(remain)?;
//     let (remain, content) = take(file_size)(remain)?;
//     Ok((
//         remain,
//         FileContent {
//             short_name_: short_name,
//             encoded_identifier_: encoded_id,
//             content_: content.clone(),
//         },
//     ))
// }
