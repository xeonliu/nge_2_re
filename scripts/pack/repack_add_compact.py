from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import struct
import logging
import shutil
import subprocess
import argparse

SECTOR_SIZE = 0x800  # 2048 bytes

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


@dataclass
class DirNode:
    path: str
    parent_path: str
    original_lba: int
    original_size: int
    entries: List[DirEntry] = field(default_factory=list)
    new_files: List[FileNode] = field(default_factory=list)
    new_lba: Optional[int] = None
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


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip("/")


def collect_work_files(workfolder: Path) -> List[Path]:
    files: List[Path] = []
    for p in sorted(workfolder.rglob("*")):
        if p.is_file() and not p.name.startswith("."):
            files.append(p)
    return files


def find_sys_use_template(dir_data: bytes) -> bytes:
    for _, rec in iter_directory_records(dir_data):
        info = parse_dir_record_full(rec)
        if not info:
            continue
        if info["name"] in (".", ".."):
            continue
        if info["sys_use"]:
            return info["sys_use"]
    return b""


def scan_iso_tree(fin, root_lba: int, root_size: int) -> Tuple[Dict[str, DirNode], Dict[str, FileNode], int]:
    dirs: Dict[str, DirNode] = {}
    files: Dict[str, FileNode] = {}
    visited: set[int] = set()
    min_data_lba = root_lba

    def scan_dir(path: str, lba: int, size: int, parent_path: str):
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

            if name in (".", ".."):
                continue

            child_path = (path + "/" + name).strip("/")
            is_dir = (flags & 0x02) != 0
            dnode.entries.append(
                DirEntry(
                    name=name,
                    name_bytes=name_bytes,
                    is_dir=is_dir,
                    sys_use=info["sys_use"],
                )
            )

            if is_dir:
                scan_dir(child_path, info["extent_lba"], info["data_length"], path)
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

    scan_dir("", root_lba, root_size, "")
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
        build_directory_record_from_id(
            b"\x00",
            self_lba,
            self_size,
            True,
            b"",
        )
    )
    records.append(
        build_directory_record_from_id(
            b"\x01",
            parent_lba,
            parent_size,
            True,
            b"",
        )
    )

    for ent in dnode.entries:
        child_path = (dnode.path + "/" + ent.name).strip("/")
        if ent.is_dir:
            child_dir = dirs[child_path]
            records.append(
                build_directory_record_from_id(
                    ent.name_bytes,
                    must_int(child_dir.new_lba, f"child dir lba for {child_path}"),
                    must_int(child_dir.new_size, f"child dir size for {child_path}"),
                    True,
                    ent.sys_use,
                )
            )
        else:
            child_file = files[child_path]
            records.append(
                build_directory_record_from_id(
                    ent.name_bytes,
                    must_int(child_file.new_lba, f"file lba for {child_path}"),
                    must_int(child_file.new_size, f"file size for {child_path}"),
                    False,
                    ent.sys_use,
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
    # Start with dot and dotdot entries.
    rec_lengths = [34, 34]

    for ent in dnode.entries:
        name_len = len(ent.name_bytes)
        name_pad = 0 if (name_len % 2 == 1) else 1
        rec_lengths.append(33 + name_len + name_pad + len(ent.sys_use))

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

            # Borrow sys_use style from first existing non-dot record in that directory.
            pd = dirs[parent_path]
            fin.seek(pd.original_lba * SECTOR_SIZE)
            ddata = fin.read(pd.original_size)
            sys_use_template = find_sys_use_template(ddata)

            nfile = FileNode(
                path=rel,
                parent_path=parent_path,
                name=name,
                name_bytes=name.encode("utf-8", errors="ignore"),
                sys_use=sys_use_template,
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
            shutil.copyfileobj(fin, fout, length=header_bytes)
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
