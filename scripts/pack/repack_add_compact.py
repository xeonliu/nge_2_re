from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import struct
import logging
import shutil
import subprocess
import argparse

SECTOR_SIZE = 0x800  # 2048 bytes

# https://problemkaputt.de/psx-spx.htm#CDROMISOFileandDirectoryDescriptors
CD_XA_ATTR_FILE = 0x0D55
CD_XA_ATTR_DIR = 0x8D55

logger = logging.getLogger("repackUMDCompact")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)


@dataclass
class FileNode:
    path: str
    parent_path: str
    name: str
    name_bytes: bytes
    sys_use: bytes
    original_lba: int
    original_size: int
    replacement_path: Optional[Path] = None
    new_lba: Optional[int] = None
    new_size: Optional[int] = None


@dataclass
class DirEntry:
    name: str
    name_bytes: bytes
    is_dir: bool
    sys_use: bytes
    original_record: bytes


@dataclass
class DirNode:
    path: str
    parent_path: str
    name_bytes: bytes
    original_lba: int
    original_size: int
    self_record: Optional[bytes] = None
    parent_record: Optional[bytes] = None
    entries: List[DirEntry] = field(default_factory=list)
    new_files: List[FileNode] = field(default_factory=list)
    new_lba: Optional[int] = None
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


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def must_int(value: Optional[int], label: str) -> int:
    if value is None:
        raise RuntimeError(f"{label} is not assigned")
    return value


def iter_directory_records(data: bytes):
    i = 0
    n = len(data)
    while i < n:
        if n - i < 1:
            break
        length = data[i]
        if length == 0:
            current_sector_offset = i % SECTOR_SIZE
            bytes_to_skip = SECTOR_SIZE - current_sector_offset
            i += bytes_to_skip
            continue
        if i + length > n:
            break
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
        "sys_use": sys_use,
    }


def build_directory_record_from_id(
    file_id: bytes,
    lba: int,
    size: int,
    is_dir: bool,
    sys_use: bytes,
) -> bytes:
    length_name = len(file_id)
    name_pad = 0 if (length_name % 2 == 1) else 1
    record_length = 33 + length_name + name_pad + len(sys_use)
    flags = 0x02 if is_dir else 0x00

    rec = bytearray(record_length)
    rec[0] = record_length
    rec[1] = 0
    struct.pack_into("<I", rec, 2, lba)
    struct.pack_into(">I", rec, 6, lba)
    struct.pack_into("<I", rec, 10, size)
    struct.pack_into(">I", rec, 14, size)

    # Keep deterministic timestamp bytes to reduce accidental churn.
    rec[18:25] = b"\x00\x01\x01\x00\x00\x00\x00"
    rec[25] = flags
    rec[26] = 0
    rec[27] = 0
    struct.pack_into("<H", rec, 28, 1)
    struct.pack_into(">H", rec, 30, 1)
    rec[32] = length_name
    rec[33 : 33 + length_name] = file_id

    if sys_use:
        sys_use_start = 33 + length_name + name_pad
        rec[sys_use_start : sys_use_start + len(sys_use)] = sys_use

    return bytes(rec)


def build_cd_xa_system_use(is_dir: bool, file_number: int = 0) -> bytes:
    """Build the 14-byte CD-XA System Use area used by PSP UMD ISO records."""
    if not 0 <= file_number <= 0xFF:
        raise ValueError(f"file_number must fit in one byte: {file_number}")

    attr = CD_XA_ATTR_DIR if is_dir else CD_XA_ATTR_FILE
    return (
        struct.pack(">H", 0)  # Owner ID Group
        + struct.pack(">H", 0)  # Owner ID User
        + struct.pack(">H", attr)
        + b"XA"
        + bytes([file_number])
        + b"\x00" * 5
    )


def patch_directory_record(record: bytes, lba: int, size: int) -> bytes:
    """Return a copy of an existing directory record with only extent/size changed."""
    rec = bytearray(record)
    struct.pack_into("<I", rec, 2, lba)
    struct.pack_into(">I", rec, 6, lba)
    struct.pack_into("<I", rec, 10, size)
    struct.pack_into(">I", rec, 14, size)
    return bytes(rec)


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip("/")


def collect_work_files(workfolder: Path) -> List[Path]:
    files: List[Path] = []
    for p in sorted(workfolder.rglob("*")):
        if p.is_file() and not p.name.startswith("."):
            files.append(p)
    return files


def scan_iso_tree(fin, root_lba: int, root_size: int) -> Tuple[Dict[str, DirNode], Dict[str, FileNode], int]:
    dirs: Dict[str, DirNode] = {}
    files: Dict[str, FileNode] = {}
    visited: set[int] = set()
    min_data_lba = root_lba

    def scan_dir(path: str, lba: int, size: int, parent_path: str, name_bytes: bytes):
        nonlocal min_data_lba
        if lba in visited:
            return
        visited.add(lba)
        min_data_lba = min(min_data_lba, lba)

        fin.seek(lba * SECTOR_SIZE)
        data = fin.read(size)
        dnode = DirNode(
            path=path,
            parent_path=parent_path,
            name_bytes=name_bytes,
            original_lba=lba,
            original_size=size,
        )
        dirs[path] = dnode

        for _, rec in iter_directory_records(data):
            info = parse_dir_record_full(rec)
            if not info:
                continue
            name = info["name"]
            name_bytes = info["name_bytes"]
            flags = info["flags"]

            if name == ".":
                dnode.self_record = bytes(rec)
                continue
            if name == "..":
                dnode.parent_record = bytes(rec)
                continue

            child_path = (path + "/" + name).strip("/")
            is_dir = (flags & 0x02) != 0
            dnode.entries.append(
                DirEntry(
                    name=name,
                    name_bytes=name_bytes,
                    is_dir=is_dir,
                    sys_use=info["sys_use"],
                    original_record=bytes(rec),
                )
            )

            if is_dir:
                scan_dir(
                    child_path,
                    info["extent_lba"],
                    info["data_length"],
                    path,
                    name_bytes,
                )
            else:
                min_data_lba = min(min_data_lba, info["extent_lba"])
                files[child_path] = FileNode(
                    path=child_path,
                    parent_path=path,
                    name=name,
                    name_bytes=name_bytes,
                    sys_use=info["sys_use"],
                    original_lba=info["extent_lba"],
                    original_size=info["data_length"],
                )

    scan_dir("", root_lba, root_size, "", b"\x00")
    return dirs, files, min_data_lba


def build_dir_blob(dnode: DirNode, dirs: Dict[str, DirNode], files: Dict[str, FileNode]) -> bytes:
    records: List[bytes] = []

    self_lba = must_int(dnode.new_lba, f"dir lba for {dnode.path}")
    self_size = must_int(dnode.new_size, f"dir size for {dnode.path}")

    if dnode.path == "":
        parent_lba = self_lba
        parent_size = self_size
    else:
        parent_node = dirs[dnode.parent_path]
        parent_lba = must_int(parent_node.new_lba, f"parent lba for {dnode.path}")
        parent_size = must_int(parent_node.new_size, f"parent size for {dnode.path}")

    records.append(
        patch_directory_record(
            dnode.self_record,
            self_lba,
            self_size,
        )
        if dnode.self_record
        else build_directory_record_from_id(b"\x00", self_lba, self_size, True, b"")
    )
    records.append(
        patch_directory_record(
            dnode.parent_record,
            parent_lba,
            parent_size,
        )
        if dnode.parent_record
        else build_directory_record_from_id(b"\x01", parent_lba, parent_size, True, b"")
    )

    for ent in dnode.entries:
        child_path = (dnode.path + "/" + ent.name).strip("/")
        if ent.is_dir:
            child_dir = dirs[child_path]
            records.append(
                patch_directory_record(
                    ent.original_record,
                    must_int(child_dir.new_lba, f"child dir lba for {child_path}"),
                    must_int(child_dir.new_size, f"child dir size for {child_path}"),
                )
            )
        else:
            child_file = files[child_path]
            records.append(
                patch_directory_record(
                    ent.original_record,
                    must_int(child_file.new_lba, f"file lba for {child_path}"),
                    must_int(child_file.new_size, f"file size for {child_path}"),
                )
            )

    for nf in dnode.new_files:
        records.append(
            build_directory_record_from_id(
                nf.name_bytes,
                must_int(nf.new_lba, f"new file lba for {nf.path}"),
                must_int(nf.new_size, f"new file size for {nf.path}"),
                False,
                nf.sys_use,
            )
        )

    out = bytearray()
    current_sector = bytearray(SECTOR_SIZE)
    ptr = 0
    for rec in records:
        if ptr + len(rec) > SECTOR_SIZE:
            out.extend(current_sector)
            current_sector = bytearray(SECTOR_SIZE)
            ptr = 0
        current_sector[ptr : ptr + len(rec)] = rec
        ptr += len(rec)
    out.extend(current_sector)
    return bytes(out)


def calc_dir_size_for_tree(
    path: str,
    dirs: Dict[str, DirNode],
    files: Dict[str, FileNode],
    cache: Dict[str, int],
) -> int:
    if path in cache:
        return cache[path]

    dnode = dirs[path]
    # Start with dot and dotdot entries. Preserve original record lengths because
    # PSP/UMD images commonly carry XA data in the System Use area.
    rec_lengths = [
        len(dnode.self_record) if dnode.self_record else 34,
        len(dnode.parent_record) if dnode.parent_record else 34,
    ]

    for ent in dnode.entries:
        rec_lengths.append(len(ent.original_record))

    for nf in dnode.new_files:
        name_len = len(nf.name_bytes)
        name_pad = 0 if (name_len % 2 == 1) else 1
        rec_lengths.append(33 + name_len + name_pad + len(nf.sys_use))

    used = 0
    sectors = 1
    for rec_len in rec_lengths:
        if used + rec_len > SECTOR_SIZE:
            sectors += 1
            used = 0
        used += rec_len

    size = sectors * SECTOR_SIZE
    cache[path] = size
    return size


def collect_dirs_by_depth(dirs: Dict[str, DirNode], reverse: bool) -> List[str]:
    return sorted(
        dirs.keys(),
        key=lambda p: len([x for x in p.split("/") if x]),
        reverse=reverse,
    )


def build_path_table_bytes(dirs: Dict[str, DirNode], big_endian: bool) -> bytes:
    """Build ISO9660 path table bytes from current directory LBAs."""
    dir_order = list(dirs.keys())
    dir_index: Dict[str, int] = {path: idx for idx, path in enumerate(dir_order, start=1)}

    out = bytearray()
    for path in dir_order:
        dnode = dirs[path]
        name_bytes = b"\x00" if path == "" else dnode.name_bytes
        name_len = len(name_bytes)
        if name_len > 0xFF:
            raise RuntimeError(f"Directory identifier too long for path table: {path}")

        parent_index = 1 if path == "" else dir_index[dnode.parent_path]
        extent_lba = must_int(dnode.new_lba, f"dir lba for {path}")

        out.append(name_len)
        out.append(0)
        if big_endian:
            out.extend(struct.pack(">I", extent_lba))
            out.extend(struct.pack(">H", parent_index))
        else:
            out.extend(struct.pack("<I", extent_lba))
            out.extend(struct.pack("<H", parent_index))
        out.extend(name_bytes)
        if name_len % 2 == 1:
            out.append(0)

    return bytes(out)


def write_path_tables(fout, dirs: Dict[str, DirNode]) -> None:
    """Rebuild and write ISO9660 path tables in PVD reserved areas."""
    pvd_off = 16 * SECTOR_SIZE

    path_table_size_old = read_uint32_le_at(fout, pvd_off + 132)
    l_path_lba = read_uint32_le_at(fout, pvd_off + 140)
    l_opt_path_lba = read_uint32_le_at(fout, pvd_off + 144)
    m_path_lba = read_uint32_be_at(fout, pvd_off + 148)
    m_opt_path_lba = read_uint32_be_at(fout, pvd_off + 152)

    l_table = build_path_table_bytes(dirs, big_endian=False)
    m_table = build_path_table_bytes(dirs, big_endian=True)
    if len(l_table) != len(m_table):
        raise RuntimeError("Internal error: LE/BE path table sizes differ")

    path_table_size_new = len(l_table)
    if path_table_size_new > path_table_size_old:
        raise RuntimeError(
            "Rebuilt path table does not fit in original reserved area: "
            f"new={path_table_size_new}, old={path_table_size_old}"
        )

    def write_table_at_lba(lba: int, data: bytes) -> None:
        if lba == 0:
            return
        fout.seek(lba * SECTOR_SIZE)
        fout.write(data)
        remaining = path_table_size_old - len(data)
        if remaining > 0:
            fout.write(b"\x00" * remaining)

    write_table_at_lba(l_path_lba, l_table)
    write_table_at_lba(l_opt_path_lba, l_table)
    write_table_at_lba(m_path_lba, m_table)
    write_table_at_lba(m_opt_path_lba, m_table)

    write_uint32_le_at(fout, pvd_off + 132, path_table_size_new)
    write_uint32_be_at(fout, pvd_off + 136, path_table_size_new)


def repack_umd_compact(
    umdfile: Path,
    umdpatch: Path,
    workfolder: Path,
    patchfile: str = "",
) -> None:
    logger.info("Repacking ISO in compact mode: %s -> %s", umdfile, umdpatch)

    work_files = collect_work_files(workfolder)
    work_map: Dict[str, Path] = {}
    for p in work_files:
        rel = normalize_path(str(p.relative_to(workfolder)))
        work_map[rel] = p

    with umdfile.open("rb") as fin:
        root_lba = read_uint32_le_at(fin, 0x809E)
        root_size = read_uint32_le_at(fin, 0x80A6)

        dirs, files, min_data_lba = scan_iso_tree(fin, root_lba, root_size)

        for fpath, fnode in files.items():
            if fpath in work_map:
                fnode.replacement_path = work_map[fpath]

        # Add new files under existing directories.
        for rel, real in work_map.items():
            if rel in files:
                continue
            if "/" in rel:
                parent_path, name = rel.rsplit("/", 1)
            else:
                parent_path, name = "", rel
            if parent_path not in dirs:
                logger.warning(
                    "Skip %s: parent directory not found in ISO (new directories are not supported)",
                    rel,
                )
                continue

            pd = dirs[parent_path]

            # Reuse CD-XA System Use bytes from the existing ISO when possible,
            # so new records follow the same metadata/layout conventions as
            # their parent directory or sibling entries.
            new_file_sys_use = next(
                (
                    existing.sys_use
                    for existing in files.values()
                    if existing.parent_path == parent_path and existing.sys_use
                ),
                getattr(pd, "sys_use", None),
            )
            if not new_file_sys_use:
                new_file_sys_use = build_cd_xa_system_use(is_dir=False)

            nfile = FileNode(
                path=rel,
                parent_path=parent_path,
                name=name,
                name_bytes=name.encode("utf-8", errors="ignore"),
                sys_use=new_file_sys_use,
                original_lba=0,
                original_size=0,
                replacement_path=real,
            )
            files[rel] = nfile
            pd.new_files.append(nfile)

        layout_start_lba = min_data_lba
        logger.info("Compact layout start LBA: %d", layout_start_lba)

        with umdpatch.open("wb+") as fout:
            header_bytes = layout_start_lba * SECTOR_SIZE
            fin.seek(0)
            remaining = header_bytes
            while remaining > 0:
                chunk = fin.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise RuntimeError("Unexpected EOF while copying ISO header")
                fout.write(chunk)
                remaining -= len(chunk)
            fout.truncate(header_bytes)
            fout.seek(header_bytes)

            # Write all file payloads contiguously.
            all_files = sorted(
                files.values(),
                key=lambda n: (
                    n.original_lba if n.original_lba > 0 else (1 << 30),
                    n.path,
                ),
            )

            for fnode in all_files:
                fout.seek(align_up(fout.tell(), SECTOR_SIZE))
                fnode.new_lba = fout.tell() // SECTOR_SIZE
                if fnode.replacement_path:
                    with fnode.replacement_path.open("rb") as fp:
                        shutil.copyfileobj(fp, fout)
                else:
                    fin.seek(fnode.original_lba * SECTOR_SIZE)
                    remaining = fnode.original_size
                    while remaining > 0:
                        chunk = fin.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise RuntimeError(f"Unexpected EOF while copying {fnode.path}")
                        fout.write(chunk)
                        remaining -= len(chunk)

                fnode.new_size = fout.tell() - (fnode.new_lba * SECTOR_SIZE)

            # Pre-calc directory sizes bottom-up.
            size_cache: Dict[str, int] = {}
            for dpath in collect_dirs_by_depth(dirs, reverse=True):
                dnode = dirs[dpath]
                dnode.new_size = calc_dir_size_for_tree(dpath, dirs, files, size_cache)

            # Phase A: allocate all directory LBAs first.
            dir_write_order = collect_dirs_by_depth(dirs, reverse=True)
            dir_write_cursor = align_up(fout.tell(), SECTOR_SIZE)
            for dpath in dir_write_order:
                dnode = dirs[dpath]
                dnode.new_lba = dir_write_cursor // SECTOR_SIZE
                dir_write_cursor += must_int(dnode.new_size, f"dir size for {dpath}")
                dir_write_cursor = align_up(dir_write_cursor, SECTOR_SIZE)

            # Phase B: write directories after all addresses are known.
            fout.seek(align_up(fout.tell(), SECTOR_SIZE))
            for dpath in collect_dirs_by_depth(dirs, reverse=True):
                dnode = dirs[dpath]
                expected_offset = must_int(dnode.new_lba, f"dir lba for {dpath}") * SECTOR_SIZE
                if fout.tell() != expected_offset:
                    fout.seek(expected_offset)
                blob = build_dir_blob(dnode, dirs, files)
                dnode.new_size = len(blob)
                fout.write(blob)

            # Keep path tables consistent after relocating directories.
            write_path_tables(fout, dirs)

            # Root directory record in PVD.
            root_node = dirs[""]
            write_uint32_le_at(fout, 0x809E, must_int(root_node.new_lba, "root lba"))
            write_uint32_be_at(fout, 0x80A2, must_int(root_node.new_lba, "root lba"))
            write_uint32_le_at(fout, 0x80A6, must_int(root_node.new_size, "root size"))
            write_uint32_be_at(fout, 0x80AA, must_int(root_node.new_size, "root size"))

            fout.seek(0, 2)
            padded_end = align_up(fout.tell(), SECTOR_SIZE)
            if padded_end > fout.tell():
                fout.write(b"\x00" * (padded_end - fout.tell()))

            final_sectors = fout.tell() // SECTOR_SIZE
            write_uint32_le_at(fout, 0x8050, final_sectors)
            write_uint32_be_at(fout, 0x8054, final_sectors)

            logger.info(
                "Done. Final sectors: %d (size: %.2f MiB)",
                final_sectors,
                (final_sectors * SECTOR_SIZE) / (1024 * 1024),
            )

    if patchfile:
        try:
            logger.info("Generating xdelta patch...")
            subprocess.run(
                ["xdelta3", "-e", "-s", str(umdfile), str(umdpatch), patchfile],
                check=True,
            )
        except Exception as e:
            logger.warning("Failed to create xdelta patch: %s", e)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Repack PSP ISO with compact layout and file addition support."
    )
    parser.add_argument("input_iso", type=Path, help="Path to original ISO")
    parser.add_argument("output_iso", type=Path, help="Path to compact repacked ISO")
    parser.add_argument("workfolder", type=Path, help="Folder with replacement/new files")
    parser.add_argument("--xdelta", default="", help="Optional xdelta patch output")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    repack_umd_compact(args.input_iso, args.output_iso, args.workfolder, args.xdelta)


if __name__ == "__main__":
    main()
