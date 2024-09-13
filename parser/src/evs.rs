use encoding_rs::SHIFT_JIS;
use std::error::Error;

use nom::bytes::streaming::{tag, take};
use nom::error::{ErrorKind, ParseError};
use nom::multi::count;
use nom::number::streaming::{le_u16, le_u32};
use nom::sequence::tuple;
use nom::{IResult, Parser};

#[derive(Debug)]
struct Header {
    number: u32,
    offsets: Vec<u32>,
}

enum ErrorType {
    Error,
}

impl Header {
    fn new(input: &[u8]) -> Result<Self, Box<dyn Error + '_>> {
        let (remain, header) = Self::parse_header(input)?;
        Ok(header)
    }

    fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
        let (remain, number) = le_u32(input)?;
        let (_, offsets) = count(le_u32, number as usize)(remain)?;
        Ok((input, Header { number, offsets }))
    }

    fn to_hex(&self) -> Vec<u8> {
        let number_hex = Vec::from(self.number.to_le_bytes());
        let mut index_offsets: Vec<Vec<u8>> = self
            .offsets
            .iter()
            .map(|x| Vec::from(x.to_le_bytes()))
            .collect();
        let mut index_offsets: Vec<u8> = index_offsets.into_iter().flatten().collect();
        number_hex
            .into_iter()
            .chain(index_offsets.into_iter())
            .collect()
    }
}

#[test]
fn test_header() -> Result<(), Box<dyn Error>> {
    const EVS_FILE: &[u8] =
        include_bytes!("../../game/PSP_GAME/USRDIR/event/tev0101.har.HGARPACK/tev0101#id39.evs");
    // Error Type Needs Type Linting.
    // Trait Restriction
    let (remain, _) = tag::<&str, &[u8], (&[u8], ErrorKind)>(".EVS")(EVS_FILE)?;
    let header = Header::new(remain)?;
    let hex = header.to_hex();
    println!("{header:?}");
    println!("{hex:?}");
    return Ok(());
}

#[derive(Debug)]
struct Entry {
    entry_type: u16,
    size: u16,
    params: Option<Vec<u32>>,
    content: Option<String>,
}

#[derive(Debug)]
enum EVSError {
    NomError(ErrorKind),
    ParamSizeUnknown,
}

impl ParseError<&[u8]> for EVSError {
    fn from_error_kind(input: &[u8], kind: ErrorKind) -> Self {
        EVSError::NomError(kind)
    }

    fn append(input: &[u8], kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl Entry {
    fn get_number_of_parameters(entry_type: u16) -> IResult<(), u16, EVSError> {
        let param_size_json_content = include_str!("./evs/param_size.json");
        let data: Vec<Option<u16>> =
            serde_json::from_str(param_size_json_content).expect("Format Err");
        return match entry_type {
            0..=0xff => {
                if let Some(size) = data[entry_type as usize] {
                    Ok(((), size))
                } else {
                    Err(nom::Err::Error(EVSError::ParamSizeUnknown))
                }
            }
            _ => Err(nom::Err::Error(EVSError::ParamSizeUnknown)),
        };
    }

    // Third Param: Self-defined Error Type
    fn new(input: &[u8]) -> IResult<&[u8], Entry, EVSError> {
        // Get Entry Type and Size
        let (remain, (entry_type, entry_size)) = tuple((le_u16, le_u16))(input)?;

        // How to turn Result type into IResult? Using map_res!
        // However, I didn't use it here anyway.
        let (_, param_num) = Entry::get_number_of_parameters(entry_type)?;

        let (remain, params) = match param_num {
            0 => (remain, None),
            _ => {
                let (remain, params): (&[u8], Vec<u32>) =
                    count(le_u32, param_num as usize)(remain)?;
                (remain, Some(params))
            }
        };

        // Contents are the remaining bytes;
        let remaining_bytes = (entry_size - param_num * 4) as usize;

        let content: Option<String> = match remaining_bytes {
            0 => None,
            _ => {
                // Turn the remaining bytes into UTF-8 Str.
                let (remain, content_bin) = take(remaining_bytes)(remain)?;
                let (decoded_str, _, _) = SHIFT_JIS.decode(content_bin);
                Some(String::from(decoded_str.strip_suffix('\0').unwrap()))
            }
        };

        Ok((
            remain,
            Entry {
                entry_type,
                size: entry_size,
                params,
                content,
            },
        ))
    }
}

#[derive(Debug)]
struct EVS {
    header: Header,
    entries: Vec<Entry>,
}

//
// impl EVS {
//     fn new(input: &[u8]) -> Self {
//         // Parse Tag
//         let (remain, _) = tag(".EVS")(input).unwrap();
//
//         let header = Header::new(remain);
//         let mut entries = Vec::new();
//         // Build all the entries
//         for offset in header.offsets {
//
//         }
//
//         EVS {
//             header,
//             entries
//         }
//     }
//     pub fn open(&mut self, filepath: &String) {
//         let file: Vec<u8> = fs::read(filepath).unwrap();
//         self.build_from_bin(&file);
//     }
//
//     pub fn build_from_bin(&mut self, input:& [u8]) {
//         let (remain, header) = parse_header(input).unwrap();
//         for i in header.offsets {
//             let i = i as usize;
//             let (_, entry) = parse_entry(&input[i..]).unwrap();
//             self.entries.push(entry);
//         }
//     }
//
//     // pub fn generate_header() -> Header {
//     //
//     // }
//
// }
//
// #[test]
// fn test_evs_read(){
//     let mut evs = EVS{ entries: vec![] };
//     const evs_file: &[u8] = include_bytes!("../../game/PSP_GAME/USRDIR/event/tev0101.har.HGARPACK/tev0101#id39.evs");
//     evs.build_from_bin(evs_file);
//     println!("{evs:?}");
// }
//
//
// pub fn parse_entry(input: &[u8]) -> IResult<&[u8], Entry> {
//     let (remain, entry_type) = le_u16(input)?;
//     let (remain, entry_size) = le_u16(remain)?;
//     let param_num = get_number_of_parameters(entry_type).expect("Unknown number of parameters.");
//     let (remain, params) = count(le_u32, param_num as usize)(remain)?;
//
//     let parameter_size: u16 = param_num * (size_of::<u32>() as u16);
//     let remaining_bytes = entry_size - parameter_size;
//     if remaining_bytes < 0 {
//         return fail(input);
//     }
//
//     return match count(le_u8, remaining_bytes as usize)(remain) {
//         Ok((remain, content_bin)) => {
//             let (decoded_str, _, _) = SHIFT_JIS.decode(&content_bin);
//             let decoded_str = decoded_str.strip_suffix('\0');
//             Ok((
//                 remain,
//                 Entry {
//                     entry_type,
//                     size: entry_size,
//                     params,
//                     content: decoded_str.map(|s| s.to_string()),
//                 },
//             ))
//         }
//         Err(e) => Err(e),
//     }
// }
//
// #[test]
// fn test_entry() {
//     const EVS_FILE: &[u8] =
//         include_bytes!("../../game/PSP_GAME/USRDIR/event/tev0101.har.HGARPACK/tev0101#id39.evs");
//     let (remain, ent) = parse_entry(&EVS_FILE[0x03d8..]).unwrap();
//     println!("{ent:?}");
// }
//

//
// // Role must have a map between number and Facial Expressions.
// enum FunctionSayCharacter {
//     NoOne,
//     Shinji,
//     Asuka,
//     Rei,
//     Misato,
//     Gendo,
//     Fuyutsuki,
//     Ritsuko,
//     Maya,
//     Hyuga,
//     Aoba,
//     Kaji,
//     Hikari,
//     Toji,
//     Kensuke,
//     Kaworu,
//     PenPen,
//     MaleNERVStaff,
//     FemaleNERVStaff,
//     StoreClerk,
// }
//
// enum FacialExpression {
//     RegularUniformContent,
//     RegularUniformAngry,
//     RegularUniformSad,
//     RegularUniformHappy,
//     RegularUniformSerious,
//     RegularUniformBlushing,
//     RegularUniformConcerned,
//     RegularUniformTakenAback,
//     regular_uniform_upset,
//     plug_suit_content,
//     plug_suit_serious,
//     memory_sad,
//     black_shadow,
//     blue_sky_shadow,
//     red_sky_shadow,
//     water_shadow,
//     art_one_shadow,
//     art_two_shadow,
//     art_three_shadow,
//     dress_content,
//     dress_happy,
//     dress_upset,
//     nude,
//     memory_content,
// }
//
// enum Param {
//     Speaker(FunctionSayCharacter),
//     Expression(FacialExpression),
//     Unknown(u32),
// }
