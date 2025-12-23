from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Set
import struct
import logging
import shutil
import subprocess
import argparse
import datetime
import math
import sys

SECTOR_SIZE = 0x800  # 2048 bytes

logger = logging.getLogger("repackUMD")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)


@dataclass
class ISOFileEntry:
    realpath: Path
    isopath: str
    is_new: bool = False
    parent_path: str = ""
    filename: str = ""
    dir_record_pos: int = 0
    original_extent_lba: int = 0
    original_size: int = 0
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


def get_7byte_datetime():
    now = datetime.datetime.now()
    return struct.pack(
        "BBBBBBB",
        now.year - 1900,
        now.month,
        now.day,
        now.hour,
        now.minute,
        now.second,
        0,
    )


def build_directory_record(
    name: str, lba: int, size: int, is_dir: bool = False
) -> bytes:
    name_bytes = name.encode("utf-8", "ignore")
    if not is_dir and b";" not in name_bytes:
        name_bytes += b";1"
    length_name = len(name_bytes)
    record_length = 33 + length_name
    if record_length % 2 != 0:
        record_length += 1
        pad_byte = b"\x00"
    flags = 0x02 if is_dir else 0x00
    date_bytes = get_7byte_datetime()
    rec = bytearray(record_length)
    rec[0] = record_length
    rec[1] = 0
    struct.pack_into("<I", rec, 2, lba)
    struct.pack_into(">I", rec, 6, lba)
    struct.pack_into("<I", rec, 10, size)
    struct.pack_into(">I", rec, 14, size)
    rec[18:25] = date_bytes
    rec[25] = flags
    rec[26] = 0
    rec[27] = 0
    struct.pack_into("<H", rec, 28, 1)
    struct.pack_into(">H", rec, 30, 1)
    rec[32] = length_name
    rec[33 : 33 + length_name] = name_bytes
    return bytes(rec)


def iter_directory_records(data: bytes):
    i = 0
    n = len(data)
    while i < n:
        # Minimum record length is 33 bytes (header) + 1 byte (min name len) = 34
        # But we only check remaining buffer size against the length byte read
        if n - i < 1:
            break
        length = data[i]

        # Length 0 means padding until the end of the sector
        if length == 0:
            current_sector_offset = i % SECTOR_SIZE
            bytes_to_skip = SECTOR_SIZE - current_sector_offset
            i += bytes_to_skip
            continue

        if i + length > n:
            break  # Safety break if record goes out of buffer

        yield i, data[i : i + length]
        i += length


def parse_dir_record(record: bytes) -> dict:
    length = record[0]
    if length == 0:
        return {}
    extent_lba = struct.unpack_from("<I", record, 2)[0]
    data_length = struct.unpack_from("<I", record, 10)[0]
    flags = record[25]
    file_id_len = record[32]
    fid = record[33 : 33 + file_id_len]

    # --- FIX: Handle ISO9660 Special Directories Correctly ---
    if fid == b"\x00":
        name = "."
    elif fid == b"\x01":
        name = ".."
    else:
        try:
            name = fid.decode("utf-8", errors="ignore").split(";")[0]
        except:
            name = fid.decode("latin1", errors="ignore").split(";")[0]

    return {
        "length": length,
        "extent_lba": extent_lba,
        "data_length": data_length,
        "flags": flags,
        "name": name.strip("\x00"),
    }


def normalize_path(path: str) -> str:
    # return path.replace("\\", "/").strip("/").upper()
    return path


def collect_work_files(workfolder: Path) -> List[ISOFileEntry]:
    files = []
    for p in sorted(workfolder.rglob("*")):
        if p.is_file() and not p.name.startswith("."):
            rel = normalize_path(str(p.relative_to(workfolder)))
            if "/" in rel:
                parent, fname = rel.rsplit("/", 1)
            else:
                parent, fname = "", rel
            files.append(
                ISOFileEntry(
                    realpath=p, isopath=rel, parent_path=parent, filename=fname
                )
            )
    return files


def scan_iso_structure(fin, root_lba, root_length) -> Dict[str, dict]:
    dir_map = {}
    # Use visited set to prevent infinite recursion if ISO is malformed
    visited_lbas = set()

    def scan_dir(lba, size, current_path):
        if lba in visited_lbas:
            return
        visited_lbas.add(lba)

        fin.seek(lba * SECTOR_SIZE)
        try:
            data = fin.read(size)
        except Exception as e:
            logger.error(f"Read error at LBA {lba}: {e}")
            return

        dir_map[current_path] = {"lba": lba, "size": size}

        for _, rec in iter_directory_records(data):
            info = parse_dir_record(rec)
            if not info:
                continue
            name = info["name"]

            # Explicitly skip . and ..
            if name in (".", "..", "\x00"):
                continue

            if info["flags"] & 0x02:
                child_path = (current_path + "/" + name).strip("/")
                if child_path not in dir_map:
                    scan_dir(info["extent_lba"], info["data_length"], child_path)

    scan_dir(root_lba, root_length, "")
    return dir_map


# -----------------------------------------------------------------------------
# Dump / Debug Function (Corrected)
# -----------------------------------------------------------------------------
def dump_iso_structure(iso_path: Path):
    if not iso_path.exists():
        logger.error(f"ISO file not found: {iso_path}")
        return

    print(
        f"{'Type':<4} | {'LBA (Hex)':<9} | {'Size (Dec)':<10} | {'Entry Offset (Hex)':<18} | {'Path'}"
    )
    print("-" * 120)

    with iso_path.open("rb") as fin:
        try:
            root_lba = read_uint32_le_at(fin, 0x809E)
            root_length = read_uint32_le_at(fin, 0x80A6)

            # Use stack: (lba, size, path_prefix)
            stack = [(root_lba, root_length, "")]
            visited = set()  # Prevent infinite loops

            print(
                f"{'DIR':<4} | {root_lba:<9X} | {root_length:<10} | {'0x809C (PVD Root)':<18} | / (ROOT)"
            )

            while stack:
                curr_lba, curr_size, curr_path = stack.pop()  # DFS traversal

                if curr_lba in visited:
                    continue
                visited.add(curr_lba)

                fin.seek(curr_lba * SECTOR_SIZE)
                data = fin.read(curr_size)

                subdirs = []

                for rel_offset, rec in iter_directory_records(data):
                    info = parse_dir_record(rec)
                    if not info:
                        continue
                    name = info["name"]

                    # Skip current/parent markers
                    if name in (".", "..", "\x00"):
                        continue

                    full_path = f"{curr_path}/{name}" if curr_path else name

                    is_dir = (info["flags"] & 0x02) != 0
                    abs_record_offset = (curr_lba * SECTOR_SIZE) + rel_offset

                    type_str = "DIR" if is_dir else "FILE"
                    print(
                        f"{type_str:<4} | {info['extent_lba']:<9X} | {info['data_length']:<10} | 0x{abs_record_offset:<16X} | /{full_path}"
                    )

                    if is_dir:
                        subdirs.append(
                            (info["extent_lba"], info["data_length"], full_path)
                        )

                # Push subdirs to stack (reversed to maintain order in DFS)
                for sd in reversed(subdirs):
                    stack.append(sd)

        except Exception as e:
            logger.error(f"Error dumping ISO: {e}")
            import traceback

            traceback.print_exc()


def repack_umd(
    umdfile: Path,
    umdpatch: Path,
    workfolder: Path,
    patchfile: str = "",
    sectorpadding: int = 1,
) -> None:
    logger.info("Repacking ISO: %s -> %s", umdfile, umdpatch)
    files = collect_work_files(workfolder)

    with umdfile.open("rb") as fin:
        # Standard PVD Root Record location:
        # Sector 16 (0x8000) + 156 bytes = 0x809C.
        # LBA is at 0x809C + 2 = 0x809E
        root_lba = read_uint32_le_at(fin, 0x809E)
        root_length = read_uint32_le_at(fin, 0x80A6)

        logger.info("Scanning ISO structure...")
        dir_map = scan_iso_structure(fin, root_lba, root_length)

        files_to_replace = []
        files_to_add = []

        def find_file_in_iso(path_str):
            parts = path_str.split("/")
            parent = "/".join(parts[:-1])
            fname = parts[-1]
            if parent not in dir_map:
                return None
            p_info = dir_map[parent]
            fin.seek(p_info["lba"] * SECTOR_SIZE)
            data = fin.read(p_info["size"])
            for offset, rec in iter_directory_records(data):
                info = parse_dir_record(rec)
                if info and info["name"] == fname:
                    return info, offset + (p_info["lba"] * SECTOR_SIZE)
            return None

        logger.info("Classifying files...")
        for entry in files:
            res = find_file_in_iso(entry.isopath)
            if res:
                info, abs_offset = res
                entry.dir_record_pos = abs_offset
                entry.original_extent_lba = info["extent_lba"]
                entry.original_size = info["data_length"]
                files_to_replace.append(entry)
            else:
                entry.is_new = True
                if entry.parent_path not in dir_map:
                    logger.warning(
                        f"Skip {entry.isopath}: Parent dir not found in ISO. (Adding new directories not supported)"
                    )
                    continue
                files_to_add.append(entry)

        files_to_replace.sort(key=lambda e: e.original_extent_lba)

        with umdpatch.open("wb+") as fout:
            logger.info("Cloning ISO...")
            fin.seek(0)
            shutil.copyfileobj(fin, fout)

            # --- PHASE 1: Replace Existing Files ---
            logger.info(f"Overwriting {len(files_to_replace)} existing files...")
            for entry in files_to_replace:
                # Seek to original LBA
                fout.seek(entry.original_extent_lba * SECTOR_SIZE)
                start_ofs = fout.tell()
                with entry.realpath.open("rb") as fsrc:
                    shutil.copyfileobj(fsrc, fout)
                end_ofs = fout.tell()
                entry.new_size = end_ofs - start_ofs

                allocated_size = (
                    math.ceil(entry.original_size / SECTOR_SIZE) * SECTOR_SIZE
                )
                if entry.new_size > allocated_size:
                    fout.seek(0, 2)
                    curr = fout.tell()
                    pad = (SECTOR_SIZE - (curr % SECTOR_SIZE)) % SECTOR_SIZE
                    if pad:
                        fout.write(b"\x00" * pad)
                    entry.new_extent_lba = fout.tell() // SECTOR_SIZE
                    with entry.realpath.open("rb") as fsrc:
                        shutil.copyfileobj(fsrc, fout)
                    logger.info(f"File grew (moved): {entry.isopath}")
                else:
                    entry.new_extent_lba = entry.original_extent_lba
                    pad_len = allocated_size - entry.new_size
                    if pad_len > 0:
                        fout.write(b"\x00" * pad_len)

                write_uint32_le_at(fout, entry.dir_record_pos + 2, entry.new_extent_lba)
                write_uint32_be_at(
                    fout, entry.dir_record_pos + 6, entry.new_extent_lba
                )  # Fixed: write BE LBA too
                write_uint32_le_at(fout, entry.dir_record_pos + 10, entry.new_size)
                write_uint32_be_at(fout, entry.dir_record_pos + 14, entry.new_size)

            # --- PHASE 2: Append New Files ---
            logger.info(f"Appending {len(files_to_add)} new files...")
            parent_updates: Dict[str, List[ISOFileEntry]] = {}

            fout.seek(0, 2)
            for entry in files_to_add:
                curr = fout.tell()
                pad = (SECTOR_SIZE - (curr % SECTOR_SIZE)) % SECTOR_SIZE
                if pad:
                    fout.write(b"\x00" * pad)
                entry.new_extent_lba = fout.tell() // SECTOR_SIZE
                with entry.realpath.open("rb") as fsrc:
                    shutil.copyfileobj(fsrc, fout)
                entry.new_size = fout.tell() - (entry.new_extent_lba * SECTOR_SIZE)
                if entry.parent_path not in parent_updates:
                    parent_updates[entry.parent_path] = []
                parent_updates[entry.parent_path].append(entry)

            # --- PHASE 3: Update Directories ---
            dir_status: Dict[str, Dict] = {}

            # Process deepest directories first to bubble up changes
            affected_dirs = set(parent_updates.keys())
            expanded_dirs = set()
            for d in affected_dirs:
                parts = d.split("/")
                for i in range(len(parts) + 1):
                    expanded_dirs.add("/".join(parts[:i]))

            sorted_dirs = sorted(
                list(expanded_dirs), key=lambda x: len(x.split("/")), reverse=True
            )

            for dpath in sorted_dirs:
                if dpath not in dir_map:
                    continue

                old_lba = dir_map[dpath]["lba"]
                old_size = dir_map[dpath]["size"]

                fout.seek(old_lba * SECTOR_SIZE)
                dir_data = bytearray(fout.read(old_size))

                has_changes = False

                # A. Update pointers for children that moved (either files or subdirs we just moved)
                for off, rec in iter_directory_records(dir_data):
                    info = parse_dir_record(rec)
                    if not info:
                        continue
                    name = info["name"]
                    child_path = (dpath + "/" + name).strip("/")

                    updated_lba = None
                    updated_size = None

                    # Check if this child is a directory we moved in previous loop iterations
                    if child_path in dir_status:
                        updated_lba = dir_status[child_path]["lba"]
                        updated_size = dir_status[child_path]["size"]

                    # Check if this child is a file we replaced and moved
                    # (This is inefficient search, but safe for now)
                    # For optimization, one could build a map of moved files beforehand
                    else:
                        for replaced_file in files_to_replace:
                            if (
                                replaced_file.isopath == child_path
                                and replaced_file.new_extent_lba
                                != replaced_file.original_extent_lba
                            ):
                                updated_lba = replaced_file.new_extent_lba
                                updated_size = replaced_file.new_size
                                break

                    if updated_lba is not None:
                        struct.pack_into("<I", dir_data, off + 2, updated_lba)
                        struct.pack_into(">I", dir_data, off + 6, updated_lba)
                        struct.pack_into("<I", dir_data, off + 10, updated_size)
                        struct.pack_into(">I", dir_data, off + 14, updated_size)
                        has_changes = True

                # B. Add new file records
                files_to_add_here = parent_updates.get(dpath, [])
                new_records_bytes = bytearray()
                for nf in files_to_add_here:
                    new_records_bytes.extend(
                        build_directory_record(
                            nf.filename, nf.new_extent_lba, nf.new_size, False
                        )
                    )

                # Check for space (simple slack check)
                last_sector_used = old_size % SECTOR_SIZE
                slack = SECTOR_SIZE - last_sector_used if last_sector_used > 0 else 0

                can_fit_in_place = False
                if files_to_add_here:
                    if len(new_records_bytes) <= slack:
                        can_fit_in_place = True
                    else:
                        can_fit_in_place = False
                else:
                    can_fit_in_place = (
                        True  # No new files, fit in place if we just updated pointers
                    )

                if can_fit_in_place:
                    fout.seek(old_lba * SECTOR_SIZE)
                    fout.write(dir_data)
                    if new_records_bytes:
                        fout.seek(old_lba * SECTOR_SIZE + old_size)
                        fout.write(new_records_bytes)
                        new_total_size = old_size + len(new_records_bytes)
                        dir_status[dpath] = {"lba": old_lba, "size": new_total_size}
                    elif has_changes:
                        dir_status[dpath] = {"lba": old_lba, "size": old_size}
                else:
                    # Move Directory
                    # To move, we need to rebuild the sectors properly
                    all_records = []
                    for _, r in iter_directory_records(dir_data):
                        all_records.append(r)
                    for nf in files_to_add_here:
                        all_records.append(
                            build_directory_record(
                                nf.filename, nf.new_extent_lba, nf.new_size, False
                            )
                        )

                    repacked_sectors = bytearray()
                    curr_sect = bytearray(SECTOR_SIZE)
                    ptr = 0

                    for rec in all_records:
                        # If record crosses sector boundary, padding current and start new
                        if ptr + len(rec) > SECTOR_SIZE:
                            # Remaining bytes in curr_sect are already 0 initialized
                            repacked_sectors.extend(curr_sect)
                            curr_sect = bytearray(SECTOR_SIZE)
                            ptr = 0

                        curr_sect[ptr : ptr + len(rec)] = rec
                        ptr += len(rec)

                    repacked_sectors.extend(curr_sect)  # Add last sector

                    fout.seek(0, 2)
                    curr = fout.tell()
                    pad = (SECTOR_SIZE - (curr % SECTOR_SIZE)) % SECTOR_SIZE
                    if pad:
                        fout.write(b"\x00" * pad)

                    new_lba = fout.tell() // SECTOR_SIZE
                    fout.write(repacked_sectors)
                    new_size = len(repacked_sectors)

                    dir_status[dpath] = {"lba": new_lba, "size": new_size}
                    logger.info(
                        f"Directory moved: /{dpath} (Size: {old_size} -> {new_size})"
                    )

            # --- PHASE 4: PVD Update ---
            if "" in dir_status:
                root_info = dir_status[""]
                rlba = root_info["lba"]
                rsize = root_info["size"]
                write_uint32_le_at(fout, 0x809E, rlba)
                write_uint32_be_at(fout, 0x80A2, rlba)
                write_uint32_le_at(fout, 0x80A6, rsize)
                write_uint32_be_at(fout, 0x80AA, rsize)
                logger.info("Updated PVD Root Record.")

            # Update Volume Size (Size in blocks)
            fout.seek(0, 2)
            final_sectors = (fout.tell() + SECTOR_SIZE - 1) // SECTOR_SIZE
            write_uint32_le_at(fout, 0x8050, final_sectors)
            write_uint32_be_at(fout, 0x8054, final_sectors)
            logger.info("Done.")

    if patchfile:
        try:
            logger.info("Generating xdelta patch...")
            subprocess.run(
                ["xdelta3", "-e", "-s", str(umdfile), str(umdpatch), patchfile],
                check=True,
            )
        except Exception as e:
            logger.warning(f"Failed to create xdelta patch: {e}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Repack PSP ISO with file addition support."
    )
    parser.add_argument("input_iso", type=Path, help="Path to original ISO")
    parser.add_argument("output_iso", type=Path, nargs="?", help="Path to patched ISO")
    parser.add_argument(
        "workfolder", type=Path, nargs="?", help="Folder with replacement files"
    )

    parser.add_argument(
        "--dump",
        action="store_true",
        help="Dump ISO structure (LBA, Entry Offset) for debugging",
    )
    parser.add_argument("--xdelta", default="", help="Optional xdelta patch output")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.dump:
        dump_iso_structure(args.input_iso)
        return

    if not args.output_iso or not args.workfolder:
        parser.error("output_iso and workfolder are required when not using --dump")

    repack_umd(args.input_iso, args.output_iso, args.workfolder, args.xdelta)


if __name__ == "__main__":
    main()
