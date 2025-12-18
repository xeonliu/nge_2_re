#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from pathlib import Path
import pycdlib


def unpack_iso9660(
    iso_path: Path, out_dir: Path, *, strip_version: bool = True
) -> None:
    """
    Extract all files from an ISO9660 image using pycdlib.

    Parameters
    ----------
    iso_path : Path
        Input ISO file.
    out_dir : Path
        Output folder for extracted files.
    strip_version : bool
        Remove the ISO9660 version suffix ";1" from filenames.
    """
    if not iso_path.exists():
        raise FileNotFoundError(f"ISO file not found: {iso_path}")

    out_dir.mkdir(parents=True, exist_ok=True)

    iso = pycdlib.PyCdlib()
    iso.open(str(iso_path))

    for dirname, _, files in iso.walk(iso_path="/"):
        # dirname: e.g. "/PSP_GAME/SYSDIR"
        # drop leading "/" for local path building
        relative = dirname.lstrip("/")
        current_dir = out_dir / relative
        current_dir.mkdir(parents=True, exist_ok=True)

        for file in files:
            filename = file
            if strip_version:
                filename = filename.replace(";1", "")

            output_file = current_dir / filename

            print(f"Extracting: {relative}/{filename}")

            # Extract file
            with output_file.open("wb") as f:
                iso.get_file_from_iso_fp(f, iso_path=f"{dirname}/{file}")

    iso.close()


def build_cli():
    parser = argparse.ArgumentParser(description="Extract files from an ISO9660 image.")

    parser.add_argument("iso", type=Path, help="Path to the input ISO file.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Directory to output extracted files.",
    )
    parser.add_argument(
        "--keep-version",
        action="store_true",
        help="Keep ISO9660 filename version suffix (e.g., ';1').",
    )

    return parser


def main():
    parser = build_cli()
    args = parser.parse_args()

    try:
        unpack_iso9660(
            iso_path=args.iso, out_dir=args.output, strip_version=not args.keep_version
        )
    except Exception as e:
        print(f"Error: {e}")
        raise SystemExit(1)

    print("Extraction complete.")


if __name__ == "__main__":
    main()
