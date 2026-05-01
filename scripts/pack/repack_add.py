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
PSP_FILE_SYS_USE = bytes.fromhex("000000000d555841000000000000")
PSP_DIR_SYS_USE = bytes.fromhex("000000008d555841000000000000")

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


def read_uint32_be_at(f, pos: int) -> int:
    f.seek(pos)
    return struct.unpack(">I", f.read(4))[0]


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
    name: str,
    lba: int,
    size: int,
    is_dir: bool = False,
    sys_use: bytes = b"",
) -> bytes:
    if not sys_use:
        sys_use = default_sys_use_for_record(is_dir)
    name_bytes = name.encode("utf-8", "ignore")
    length_name = len(name_bytes)
    name_pad = 0 if (length_name % 2 == 1) else 1
    record_length = 33 + length_name + name_pad + len(sys_use)
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
    sys_use_start = 33 + length_name + name_pad
    if sys_use:
        rec[sys_use_start : sys_use_start + len(sys_use)] = sys_use
    return bytes(rec)


def default_sys_use_for_record(is_dir: bool) -> bytes:
    return PSP_DIR_SYS_USE if is_dir else PSP_FILE_SYS_USE


def patch_directory_record_extent_and_size(record: bytes, lba: int, size: int) -> bytes:
    patched = bytearray(record)
    struct.pack_into("<I", patched, 2, lba)
    struct.pack_into(">I", patched, 6, lba)
    struct.pack_into("<I", patched, 10, size)
    struct.pack_into(">I", patched, 14, size)
    return bytes(patched)


def patch_directory_record_date(record: bytes, date_bytes: bytes) -> bytes:
    patched = bytearray(record)
    patched[18:25] = date_bytes
    return bytes(patched)


def patch_directory_record_sys_use(record: bytes, sys_use: bytes) -> bytes:
    file_id_len = record[32]
    name_pad = 0 if (file_id_len % 2 == 1) else 1
    sys_use_start = 33 + file_id_len + name_pad
    sys_use_end = record[0]
    old_len = sys_use_end - sys_use_start
    if old_len != len(sys_use):
        return record
    patched = bytearray(record)
    patched[sys_use_start:sys_use_end] = sys_use
    return bytes(patched)


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


def parse_dir_record_full(record: bytes) -> dict:
    length = record[0]
    if length == 0:
        return {}
    rec_end = min(len(record), length)
    extent_lba = struct.unpack_from("<I", record, 2)[0]
    data_length = struct.unpack_from("<I", record, 10)[0]
    flags = record[25]
    file_id_len = record[32]
    fid = record[33 : 33 + file_id_len]
    name_pad = 0 if (file_id_len % 2 == 1) else 1
    sys_use_start = 33 + file_id_len + name_pad
    sys_use = record[sys_use_start:rec_end] if sys_use_start < rec_end else b""

    if fid == b"\x00":
        name = "."
    elif fid == b"\x01":
        name = ".."
    else:
        try:
            name = fid.decode("utf-8", errors="ignore").split(";")[0]
        except Exception:
            name = fid.decode("latin1", errors="ignore").split(";")[0]

    return {
        "length": length,
        "extent_lba": extent_lba,
        "data_length": data_length,
        "flags": flags,
        "name": name.strip("\x00"),
        "name_bytes": fid,
        "date_bytes": bytes(record[18:25]),
        "sys_use": sys_use,
    }


def parse_dir_record(record: bytes) -> dict:
    info = parse_dir_record_full(record)
    if not info:
        return {}
    return {
        "length": info["length"],
        "extent_lba": info["extent_lba"],
        "data_length": info["data_length"],
        "flags": info["flags"],
        "name": info["name"],
    }


def split_file_identifier(fid: bytes) -> tuple[bytes, bytes, int]:
    base = fid
    version = 0

    if b";" in fid:
        candidate_base, candidate_version = fid.rsplit(b";", 1)
        if candidate_version.isdigit():
            base = candidate_base
            version = int(candidate_version)

    if b"." in base:
        file_name, file_ext = base.rsplit(b".", 1)
    else:
        file_name, file_ext = base, b""

    return file_name, file_ext, version


def directory_record_sort_key(record: bytes):
    info = parse_dir_record_full(record)
    file_name, file_ext, version = split_file_identifier(info["name_bytes"])
    return file_name, file_ext, -version, info["name_bytes"]


def sort_directory_records(records: List[bytes]) -> List[bytes]:
    dot_record = None
    dotdot_record = None
    others = []

    for rec in records:
        info = parse_dir_record_full(rec)
        if not info:
            continue
        if info["name_bytes"] == b"\x00":
            dot_record = rec
        elif info["name_bytes"] == b"\x01":
            dotdot_record = rec
        else:
            others.append(rec)

    others.sort(key=directory_record_sort_key)

    ordered = []
    if dot_record is not None:
        ordered.append(dot_record)
    if dotdot_record is not None:
        ordered.append(dotdot_record)
    ordered.extend(others)
    return ordered


def pack_directory_records(records: List[bytes], total_size: int) -> bytes:
    repacked = bytearray()
    curr_sect = bytearray(SECTOR_SIZE)
    ptr = 0

    for rec in records:
        if ptr + len(rec) > SECTOR_SIZE:
            repacked.extend(curr_sect)
            curr_sect = bytearray(SECTOR_SIZE)
            ptr = 0
        curr_sect[ptr : ptr + len(rec)] = rec
        ptr += len(rec)

    repacked.extend(curr_sect)

    if len(repacked) > total_size:
        raise ValueError(
            f"Directory repack overflow: need {len(repacked)} bytes, only {total_size} available"
        )

    if len(repacked) < total_size:
        repacked.extend(b"\x00" * (total_size - len(repacked)))

    return bytes(repacked)


def zero_unused_sectors(finout, root_lba: int, root_length: int) -> int:
    final_sectors = read_uint32_le_at(finout, 0x8050)
    used = bytearray(final_sectors)

    def mark_range(lba: int, size: int) -> None:
        count = (size + SECTOR_SIZE - 1) // SECTOR_SIZE
        for idx in range(lba, min(lba + count, final_sectors)):
            used[idx] = 1

    for lba in range(min(22, final_sectors)):
        used[lba] = 1

    visited_lbas: Set[int] = set()

    def scan_dir(lba: int, size: int) -> None:
        if lba in visited_lbas:
            return
        visited_lbas.add(lba)
        mark_range(lba, size)

        finout.seek(lba * SECTOR_SIZE)
        data = finout.read(size)
        for _, rec in iter_directory_records(data):
            info = parse_dir_record_full(rec)
            if not info:
                continue
            if info["name"] in (".", ".."):
                continue
            mark_range(info["extent_lba"], info["data_length"])
            if info["flags"] & 0x02:
                scan_dir(info["extent_lba"], info["data_length"])

    scan_dir(root_lba, root_length)

    zeroed = 0
    gap_start = None
    for lba in range(final_sectors):
        if used[lba]:
            if gap_start is not None:
                gap_len = lba - gap_start
                finout.seek(gap_start * SECTOR_SIZE)
                finout.write(b"\x00" * (gap_len * SECTOR_SIZE))
                zeroed += gap_len
                gap_start = None
            continue
        if gap_start is None:
            gap_start = lba

    if gap_start is not None:
        gap_len = final_sectors - gap_start
        finout.seek(gap_start * SECTOR_SIZE)
        finout.write(b"\x00" * (gap_len * SECTOR_SIZE))
        zeroed += gap_len

    return zeroed


def patch_dot_records(
    dir_buf: bytearray,
    self_lba: int,
    self_size: int,
    parent_lba: int,
    parent_size: int,
) -> None:
    for off, rec in iter_directory_records(dir_buf):
        info = parse_dir_record_full(rec)
        if not info:
            continue
        if info["name_bytes"] == b"\x00":
            struct.pack_into("<I", dir_buf, off + 2, self_lba)
            struct.pack_into(">I", dir_buf, off + 6, self_lba)
            struct.pack_into("<I", dir_buf, off + 10, self_size)
            struct.pack_into(">I", dir_buf, off + 14, self_size)
        elif info["name_bytes"] == b"\x01":
            struct.pack_into("<I", dir_buf, off + 2, parent_lba)
            struct.pack_into(">I", dir_buf, off + 6, parent_lba)
            struct.pack_into("<I", dir_buf, off + 10, parent_size)
            struct.pack_into(">I", dir_buf, off + 14, parent_size)


def get_path_table_info(fin) -> dict:
    return {
        "size": read_uint32_le_at(fin, 0x8084),
        "little": [
            read_uint32_le_at(fin, 0x808C),
            read_uint32_le_at(fin, 0x8090),
        ],
        "big": [
            read_uint32_be_at(fin, 0x8094),
            read_uint32_be_at(fin, 0x8098),
        ],
    }


def iter_path_table_records(data: bytes, byteorder: str):
    offset = 0
    entries = []
    unpack_u16 = "<H" if byteorder == "little" else ">H"
    unpack_u32 = "<I" if byteorder == "little" else ">I"

    while offset + 8 <= len(data):
        name_len = data[offset]
        if name_len == 0:
            break

        extent_lba = struct.unpack_from(unpack_u32, data, offset + 2)[0]
        parent_dir_num = struct.unpack_from(unpack_u16, data, offset + 6)[0]
        name_bytes = data[offset + 8 : offset + 8 + name_len]
        record_len = 8 + name_len + (name_len % 2)

        if name_bytes == b"\x00":
            path = ""
        else:
            name = name_bytes.decode("latin1", errors="ignore")
            parent_path = ""
            if parent_dir_num > 0:
                parent_path = entries[parent_dir_num - 1]["path"]
            path = f"{parent_path}/{name}".strip("/")

        entry = {
            "offset": offset,
            "extent_lba": extent_lba,
            "parent_dir_num": parent_dir_num,
            "name_bytes": name_bytes,
            "path": path,
        }
        entries.append(entry)
        yield entry
        offset += record_len


def patch_path_tables(fout, path_table_info: dict, dir_status: Dict[str, Dict]) -> None:
    for byteorder, lbas in (
        ("little", path_table_info["little"]),
        ("big", path_table_info["big"]),
    ):
        pack_u32 = "<I" if byteorder == "little" else ">I"
        for lba in lbas:
            if lba == 0:
                continue

            fout.seek(lba * SECTOR_SIZE)
            table_data = bytearray(fout.read(path_table_info["size"]))

            for entry in iter_path_table_records(table_data, byteorder):
                if entry["path"] not in dir_status:
                    continue
                struct.pack_into(
                    pack_u32,
                    table_data,
                    entry["offset"] + 2,
                    dir_status[entry["path"]]["lba"],
                )

            fout.seek(lba * SECTOR_SIZE)
            fout.write(table_data)


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


def repair_existing_iso(input_iso: Path, output_iso: Path) -> None:
    logger.info("Repairing ISO: %s -> %s", input_iso, output_iso)

    with input_iso.open("rb") as fin, output_iso.open("wb+") as fout:
        fin.seek(0)
        shutil.copyfileobj(fin, fout)

        root_lba = read_uint32_le_at(fout, 0x809E)
        root_length = read_uint32_le_at(fout, 0x80A6)
        dir_map = scan_iso_structure(fout, root_lba, root_length)

        dot_dates: Dict[str, bytes] = {}
        for dpath, info in dir_map.items():
            fout.seek(info["lba"] * SECTOR_SIZE)
            dir_data = fout.read(info["size"])
            for _, rec in iter_directory_records(dir_data):
                rec_info = parse_dir_record_full(rec)
                if rec_info and rec_info["name"] == ".":
                    dot_dates[dpath] = rec_info["date_bytes"]
                    break

        repaired_dirs = 0
        for dpath, info in dir_map.items():
            fout.seek(info["lba"] * SECTOR_SIZE)
            dir_data = fout.read(info["size"])
            original_records = [rec for _, rec in iter_directory_records(dir_data)]
            updated_records = []
            record_changed = False

            for rec in original_records:
                rec_info = parse_dir_record_full(rec)
                if not rec_info or rec_info["name"] in (".", ".."):
                    updated_records.append(rec)
                    continue

                is_dir = (rec_info["flags"] & 0x02) != 0
                child_path = (dpath + "/" + rec_info["name"]).strip("/")
                new_rec = rec

                if is_dir and child_path in dot_dates:
                    child_dot_date = dot_dates[child_path]
                    if rec_info["date_bytes"] != child_dot_date:
                        new_rec = patch_directory_record_date(new_rec, child_dot_date)

                if (
                    not is_dir
                    and rec_info["sys_use"] == PSP_DIR_SYS_USE
                ):
                    patched = patch_directory_record_sys_use(
                        new_rec, PSP_FILE_SYS_USE
                    )
                    if patched != new_rec:
                        new_rec = patched

                if new_rec != rec:
                    record_changed = True
                updated_records.append(new_rec)

            sorted_records = sort_directory_records(updated_records)
            order_changed = sorted_records != original_records

            if not record_changed and not order_changed:
                continue

            new_dir_data = pack_directory_records(sorted_records, info["size"])
            fout.seek(info["lba"] * SECTOR_SIZE)
            fout.write(new_dir_data)
            repaired_dirs += 1
            logger.info("Repaired directory: /%s", dpath)

        zeroed = zero_unused_sectors(fout, root_lba, root_length)
        logger.info("Zeroed unused sectors: %d", zeroed)
        logger.info("Repair complete. Directories changed: %d", repaired_dirs)


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
        path_table_info = get_path_table_info(fin)

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
        replaced_file_map = {
            replaced_file.isopath: (
                replaced_file.new_extent_lba,
                replaced_file.new_size,
            )
            for replaced_file in files_to_replace
        }

        with umdpatch.open("wb+") as fout:
            logger.info("Cloning ISO...")
            fin.seek(0)
            shutil.copyfileobj(fin, fout)

            # --- PHASE 1: Replace Existing Files ---
            logger.info(f"Overwriting {len(files_to_replace)} existing files...")
            for entry in files_to_replace:
                allocated_size = (
                    math.ceil(entry.original_size / SECTOR_SIZE) * SECTOR_SIZE
                )
                entry.new_size = entry.realpath.stat().st_size

                if entry.new_size > allocated_size:
                    fout.seek(0, 2)
                    curr = fout.tell()
                    pad = (SECTOR_SIZE - (curr % SECTOR_SIZE)) % SECTOR_SIZE
                    if pad:
                        fout.write(b"\x00" * pad)
                    entry.new_extent_lba = fout.tell() // SECTOR_SIZE
                    with entry.realpath.open("rb") as fsrc:
                        shutil.copyfileobj(fsrc, fout)
                    fout.seek(entry.original_extent_lba * SECTOR_SIZE)
                    fout.write(b"\x00" * allocated_size)
                    logger.info(f"File grew (moved): {entry.isopath}")
                else:
                    fout.seek(entry.original_extent_lba * SECTOR_SIZE)
                    start_ofs = fout.tell()
                    with entry.realpath.open("rb") as fsrc:
                        shutil.copyfileobj(fsrc, fout)
                    end_ofs = fout.tell()
                    entry.new_size = end_ofs - start_ofs
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

            replaced_file_map = {
                replaced_file.isopath: (
                    replaced_file.new_extent_lba,
                    replaced_file.new_size,
                )
                for replaced_file in files_to_replace
                if replaced_file.new_extent_lba is not None
                and replaced_file.new_size is not None
            }

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

                # A. Process existing records and update pointers, maintaining original order
                # B. Preserve order: iterate through original records, update them, and collect new records
                updated_records = []
                files_to_add_here = parent_updates.get(dpath, [])
                new_files_added = set()

                for off, rec in iter_directory_records(dir_data):
                    info = parse_dir_record_full(rec)
                    if not info:
                        continue
                    name = info["name"]
                    child_path = (dpath + "/" + name).strip("/")

                    if name in (".", ".."):
                        updated_records.append(rec)
                        continue

                    updated_lba = None
                    updated_size = None

                    # Check if this child is a directory we moved in previous loop iterations
                    if child_path in dir_status:
                        updated_lba = dir_status[child_path]["lba"]
                        updated_size = dir_status[child_path]["size"]

                    # Check if this child is a file we replaced and moved
                    elif child_path in replaced_file_map:
                        updated_lba, updated_size = replaced_file_map[child_path]

                    # Update the record in-place or rebuild it
                    if updated_lba is not None:
                        # Preserve timestamp, flags, XA data and only patch extent/size.
                        new_rec = patch_directory_record_extent_and_size(
                            rec, updated_lba, updated_size
                        )
                        updated_records.append(new_rec)
                        has_changes = True
                    else:
                        # Keep original record unchanged
                        updated_records.append(rec)

                # Append new file records at the end (preserving original file order)
                for nf in files_to_add_here:
                    updated_records.append(
                        build_directory_record(
                            nf.filename,
                            nf.new_extent_lba,
                            nf.new_size,
                            False,
                            PSP_FILE_SYS_USE,
                        )
                    )

                updated_records = sort_directory_records(updated_records)

                # Rebuild sectors properly respecting sector boundaries
                repacked_sectors = bytearray()
                curr_sect = bytearray(SECTOR_SIZE)
                ptr = 0

                for rec in updated_records:
                    # If record would cross sector boundary, pad current sector and start new
                    if ptr + len(rec) > SECTOR_SIZE:
                        repacked_sectors.extend(curr_sect)
                        curr_sect = bytearray(SECTOR_SIZE)
                        ptr = 0
                    curr_sect[ptr : ptr + len(rec)] = rec
                    ptr += len(rec)

                repacked_sectors.extend(curr_sect)
                new_total_size = len(repacked_sectors)
                old_num_sectors = (old_size + SECTOR_SIZE - 1) // SECTOR_SIZE
                new_num_sectors = len(repacked_sectors) // SECTOR_SIZE
                
                can_fit_in_place = (new_num_sectors <= old_num_sectors)

                if can_fit_in_place:
                    fout.seek(old_lba * SECTOR_SIZE)
                    fout.write(repacked_sectors)
                    dir_status[dpath] = {"lba": old_lba, "size": new_total_size}
                    if len(files_to_add_here) > 0 or has_changes:
                        logger.info(
                            f"Directory updated in-place: /{dpath} (LBA: {old_lba}, Size: {old_size}->{new_total_size}, New files: {len(files_to_add_here)})"
                        )
                else:
                    # Move Directory - append at end of ISO
                    fout.seek(0, 2)
                    curr = fout.tell()
                    pad = (SECTOR_SIZE - (curr % SECTOR_SIZE)) % SECTOR_SIZE
                    if pad:
                        fout.write(b"\x00" * pad)

                    new_lba = fout.tell() // SECTOR_SIZE
                    fout.write(repacked_sectors)

                    dir_status[dpath] = {"lba": new_lba, "size": new_total_size}
                    logger.info(
                        f"Directory moved: /{dpath} (LBA: {old_lba}->{new_lba}, Size: {old_size}->{new_total_size}, New files: {len(files_to_add_here)})"
                    )

            # --- PHASE 3.5: Patch dot entries with final parent info ---
            for dpath, info in dir_status.items():
                self_lba = info["lba"]
                self_size = info["size"]
                if dpath == "":
                    parent_lba = self_lba
                    parent_size = self_size
                else:
                    parent_path = "/".join(dpath.split("/")[:-1])
                    if parent_path in dir_status:
                        parent_lba = dir_status[parent_path]["lba"]
                        parent_size = dir_status[parent_path]["size"]
                    else:
                        parent_lba = dir_map[parent_path]["lba"]
                        parent_size = dir_map[parent_path]["size"]

                fout.seek(self_lba * SECTOR_SIZE)
                buf = bytearray(fout.read(self_size))
                patch_dot_records(buf, self_lba, self_size, parent_lba, parent_size)
                fout.seek(self_lba * SECTOR_SIZE)
                fout.write(buf)

            if dir_status:
                patch_path_tables(fout, path_table_info, dir_status)
                logger.info("Updated path tables.")

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
            pad = (SECTOR_SIZE - (fout.tell() % SECTOR_SIZE)) % SECTOR_SIZE
            if pad:
                fout.write(b"\x00" * pad)
            final_sectors = (fout.tell() + SECTOR_SIZE - 1) // SECTOR_SIZE
            write_uint32_le_at(fout, 0x8050, final_sectors)
            write_uint32_be_at(fout, 0x8054, final_sectors)
            final_root_lba = root_lba
            final_root_length = root_length
            if "" in dir_status:
                final_root_lba = dir_status[""]["lba"]
                final_root_length = dir_status[""]["size"]
            zeroed = zero_unused_sectors(fout, final_root_lba, final_root_length)
            logger.info("Zeroed unused sectors: %d", zeroed)
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
    parser.add_argument(
        "--repair-existing",
        action="store_true",
        help="Rewrite existing ISO directory records to fix old generator output",
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

    if args.repair_existing:
        if not args.output_iso:
            parser.error("output_iso is required with --repair-existing")
        repair_existing_iso(args.input_iso, args.output_iso)
        return

    if not args.output_iso or not args.workfolder:
        parser.error("output_iso and workfolder are required when not using --dump")

    repack_umd(args.input_iso, args.output_iso, args.workfolder, args.xdelta)


if __name__ == "__main__":
    main()
