from pathlib import Path
import argparse


def write_c_array(input_path: Path, output_path: Path, symbol: str):
    data = input_path.read_bytes()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="ascii", newline="\n") as f:
        f.write(f"unsigned char {symbol}[] = {{\n")
        for pos in range(0, len(data), 12):
            chunk = data[pos : pos + 12]
            values = ", ".join(f"0x{byte:02x}" for byte in chunk)
            suffix = "," if pos + 12 < len(data) else ""
            f.write(f"  {values}{suffix}\n")
        f.write("};\n")
        f.write(f"unsigned int {symbol}_len = {len(data)};\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert a binary file to a C array.")
    parser.add_argument("--symbol", required=True, help="C symbol name for the array.")
    parser.add_argument("input", type=Path, help="Input binary file.")
    parser.add_argument("output", type=Path, help="Output C source file.")
    args = parser.parse_args()

    write_c_array(args.input, args.output, args.symbol)
