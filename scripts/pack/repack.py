from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Tuple, Dict
import struct
import logging
import shutil
import subprocess
import argparse

SECTOR_SIZE = 0x800  # 2048 bytes

logger = logging.getLogger("repackUMD")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
logger.addHandler(handler)


@dataclass
class ISOFileEntry:
    realpath: Path        # path on disk (work folder)
    isopath: str          # path inside ISO, like '/PSP_GAME/SYSDIR/EBOOT.BIN'
    dir_record_pos: int   # byte offset in the ISO where the directory record starts
    original_extent_lba: int
    original_size: int
    new_extent_lba: Optional[int] = None
    new_size: Optional[int] = None


def read_uint32_le_at(f, pos: int) -> int:
    f.seek(pos)
    return struct.unpack("<I", f.read(4))[0]


def write_uint32_le_at(f, pos: int, value: int) -> None:
    f.seek(pos)
    f.write(struct.pack("<I", value))


def write_uint32_be_at(f, pos: int, value: int) -> None:
    f.seek(pos)
    f.write(struct.pack(">I", value))


def read_primary_volume_root(fin) -> Tuple[int, int]:
    """
    Read Root Directory Record location and length from PVD.
    Offsets used in original: 0x809e (rootlba), 0x80a6 (rootlength).
    Those are relative to file start.
    """
    root_lba = read_uint32_le_at(fin, 0x809e)
    root_length = read_uint32_le_at(fin, 0x80a6)
    logger.debug(f"root_lba={root_lba}, root_length={root_length}")
    return root_lba, root_length


def iter_directory_records(data: bytes):
    """
    Iterate directory records contained in a directory data block (bytes).
    Yields tuples (record_offset_within_data, record_bytes).
    ISO9660 Directory Record layout:
      byte 0: length (1)
      byte 1: ext attr length (1)
      byte 2..5: extent location (LE, 4)
      byte 10..13: data length (LE, 4)
      byte 32: file identifier length (1)
      byte 33..: file identifier (len bytes)
    """
    i = 0
    n = len(data)
    while i < n:
        if n - i < 1:
            break
        length = data[i]
        if length == 0:
            # padding to sector boundary; move to next sector boundary
            next_sector = ((i // SECTOR_SIZE) + 1) * SECTOR_SIZE
            if next_sector <= i:
                break
            i = next_sector
            continue
        record = data[i:i + length]
        yield i, record
        i += length


def parse_dir_record(record: bytes) -> dict:
    """
    Parse fields from a directory record bytes and return a dict with:
      - length, extent_lba, data_length, flags, file_identifier (string), record_len, file_id_len
    """
    length = record[0]
    if length == 0:
        return {}
    extent_lba = struct.unpack_from("<I", record, 2)[0]
    data_length = struct.unpack_from("<I", record, 10)[0]
    flags = record[25]
    file_id_len = record[32]
    fid_start = 33
    fid = record[fid_start:fid_start + file_id_len]
    # decode name, strip version suffix like ';1'
    try:
        name = fid.decode("utf-8", errors="ignore")
    except Exception:
        name = fid.decode("latin1", errors="ignore")
    # directory name often includes ';1' or trailing 0
    name = name.rstrip("\x00")
    return {
        "length": length,
        "extent_lba": extent_lba,
        "data_length": data_length,
        "flags": flags,
        "file_id_len": file_id_len,
        "file_id_raw": fid,
        "name": name
    }


def normalize_component(comp: str) -> str:
    # ISO9660 typically stores uppercase and version suffix e.g. "EBOOT.BIN;1"
    # We'll compare case-insensitive and strip version part.
    comp = comp.strip("/")
    comp_upper = comp.upper()
    if ";" in comp_upper:
        comp_upper = comp_upper.split(";")[0]
    return comp_upper


def find_dir_record_offset_for_path(fin, path_components: List[str], root_lba: int, root_length: int) -> Optional[int]:
    """
    Given a list of path components (['PSP_GAME','SYSDIR','EBOOT.BIN']), traverse ISO directories
    starting from root_lba and find the byte offset (in file) of the directory record for the final component.
    Returns absolute byte offset (file offset) or None if not found.
    """
    # start at root
    current_extent = root_lba
    current_size = root_length
    for idx, comp in enumerate(path_components):
        target = normalize_component(comp)
        # read the directory data
        fin.seek(current_extent * SECTOR_SIZE)
        directory_data = fin.read(current_size)
        found = False
        for rec_off_within, rec in iter_directory_records(directory_data):
            parsed = parse_dir_record(rec)
            if not parsed:
                continue
            name = parsed["name"]
            # handle special '.' and '..'
            if name in ("\x00", "\x01"):
                continue
            # normalize record name for compare
            rec_name = name.upper()
            # strip version ';1' and any trailing ';..'
            if ";" in rec_name:
                rec_name_base = rec_name.split(";")[0]
            else:
                rec_name_base = rec_name
            # For directory entries, ISO may store ';1' after name.
            if rec_name_base == target:
                # compute absolute position of this record in the file
                # record byte offset within file = current_extent*SECTOR_SIZE + rec_off_within
                abs_pos = current_extent * SECTOR_SIZE + rec_off_within
                # If this is not the final component and it's a directory -> descend
                is_dir = (parsed["flags"] & 0x02) != 0
                if idx == len(path_components) - 1:
                    return abs_pos
                else:
                    if not is_dir:
                        return None
                    # update current_extent/current_size to this directory's extent & size
                    current_extent = parsed["extent_lba"]
                    current_size = parsed["data_length"]
                    found = True
                    break
        if not found and idx < len(path_components) - 1:
            # not found intermediate directory
            return None
    return None


def collect_work_files(workfolder: Path) -> List[ISOFileEntry]:
    files: List[ISOFileEntry] = []
    for p in sorted(workfolder.rglob("*")):
        if p.is_file():
            # iso path: make it '/'-prefixed and use forward slashes
            rel = "/" + str(p.relative_to(workfolder)).replace("\\", "/")
            files.append(ISOFileEntry(realpath=p, isopath=rel, dir_record_pos=0,
                                      original_extent_lba=0, original_size=0))
    return files


def repack_umd(umdfile: Path, umdpatch: Path, workfolder: Path, patchfile: str = "", sectorpadding: int = 1) -> None:
    """
    Modern, readable reimplementation of repackUMD.
    """
    logger.info("Repacking ISO/UMD: %s -> %s", umdfile, umdpatch)
    workfolder = Path(workfolder)
    files = collect_work_files(workfolder)
    if not files:
        logger.error("No files found in workfolder: %s", workfolder)
        return

    with umdfile.open("rb") as fin:
        root_lba, root_length = read_primary_volume_root(fin)

        # For each file in workfolder, find its directory record and original size/LBA
        for entry in files:
            comps = [c for c in entry.isopath.split("/") if c]
            pos = find_dir_record_offset_for_path(fin, comps, root_lba, root_length)
            if pos is None:
                logger.error("File %s not found in ISO", entry.isopath)
                raise FileNotFoundError(f"{entry.isopath} not found in ISO")
            entry.dir_record_pos = pos
            entry.original_extent_lba = read_uint32_le_at(fin, pos + 2)
            entry.original_size = read_uint32_le_at(fin, pos + 0x0A)
            logger.debug(f"Found {entry.isopath}: dir_rec_pos=0x{pos:x}, lba={entry.original_extent_lba}, size={entry.original_size}")

    # Sort by original file LBA to keep order and minimize movement
    files.sort(key=lambda e: e.original_extent_lba)

    # Create output patch file
    with umdpatch.open("r+b" if umdpatch.exists() else "wb+") as fout, umdfile.open("rb") as fin:
        # Copy everything up to the first file content LBA
        first_content_offset = files[0].original_extent_lba * SECTOR_SIZE
        fin.seek(0)
        # write header and everything before content area
        fout.write(fin.read(first_content_offset))

        # For each file, write file contents and update directory record in the output file
        for entry in files:
            # ensure we don't write earlier than original LBA unless necessary
            cur_lba = fout.tell() // SECTOR_SIZE
            if cur_lba < entry.original_extent_lba:
                # seek to original LBA (pad with zeros)
                fout.seek(entry.original_extent_lba * SECTOR_SIZE)
            new_offset = fout.tell()
            logger.debug(f"Writing {entry.isopath} at offset {new_offset} (sector {new_offset // SECTOR_SIZE})")
            # write file bytes
            with entry.realpath.open("rb") as sf:
                shutil.copyfileobj(sf, fout)
            new_size = fout.tell() - new_offset
            # pad to sectorpadding boundary
            pad_sector = sectorpadding * SECTOR_SIZE
            next_boundary = ((fout.tell() // pad_sector) + 1) * pad_sector
            if next_boundary > fout.tell():
                fout.seek(next_boundary - 1)
                fout.write(b"\x00")
            # update entry
            entry.new_extent_lba = new_offset // SECTOR_SIZE
            entry.new_size = new_size
            # Update directory record in the output file:
            # write extent LBA (LE) at dir_record_pos + 2
            write_uint32_le_at(fout, entry.dir_record_pos + 2, entry.new_extent_lba)
            # write data length (LE) at dir_record_pos + 0x0A
            write_uint32_le_at(fout, entry.dir_record_pos + 0x0A, entry.new_size)
            # write data length (BE) at dir_record_pos + 0x0E
            write_uint32_be_at(fout, entry.dir_record_pos + 0x0E, entry.new_size)
            logger.debug(f"Updated dir record @0x{entry.dir_record_pos:x} -> lba={entry.new_extent_lba}, size={entry.new_size}")

        # If new file is smaller than original, pad one zero at end of original size to match original file length
        fin.seek(0, 2)
        original_total_size = fin.tell()
        fout.seek(0, 2)
        new_total_size = fout.tell()
        if new_total_size < original_total_size:
            logger.debug("Patching end of file to match original size (pad one zero byte).")
            fout.seek(original_total_size - 1)
            fout.write(b"\x00")

        # Update Primary Volume Descriptor: Volume Space Size (in sectors) LE at 0x8050 and BE at 0x8054
        final_sectors = fout.tell() // SECTOR_SIZE
        write_uint32_le_at(fout, 0x8050, final_sectors)
        write_uint32_be_at(fout, 0x8054, final_sectors)
        logger.info("Updated PVD volume space size to %d sectors", final_sectors)

    logger.info("Repack done: %s", umdpatch)

    # Optionally create xdelta patch (requires xdelta3)
    if patchfile:
        try:
            logger.info("Creating xdelta patch: %s", patchfile)
            subprocess.run(["xdelta3", "-e", "-s", str(umdfile), str(umdpatch), patchfile], check=True)
            logger.info("xdelta patch created: %s", patchfile)
        except FileNotFoundError:
            logger.warning("xdelta3 not found. Install xdelta3 to enable patch creation.")
        except subprocess.CalledProcessError as e:
            logger.error("xdelta3 failed: %s", e)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Repack a PSP UMD/ISO file by injecting modified files from a working folder.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "input_iso",
        type=Path,
        help="Path to the original UMD/ISO image",
    )

    parser.add_argument(
        "output_iso",
        type=Path,
        help="Path to the output patched ISO image",
    )

    parser.add_argument(
        "workfolder",
        type=Path,
        help="Directory containing files to be injected (mirrors ISO internal structure).",
    )

    parser.add_argument(
        "--xdelta",
        metavar="PATCH_FILE",
        default="",
        help="Optional: generate an xdelta patch file (requires xdelta3).",
    )

    parser.add_argument(
        "--sector-padding",
        type=int,
        default=1,
        help="Padding multiple of sector size (2048 bytes). Default is 1 sector.",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging output.",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.getLogger("repackUMD").setLevel(logging.DEBUG)

    repack_umd(
        umdfile=args.input_iso,
        umdpatch=args.output_iso,
        workfolder=args.workfolder,
        patchfile=args.xdelta,
        sectorpadding=args.sector_padding,
    )


if __name__ == "__main__":
    main()
    
