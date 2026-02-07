#!/usr/bin/env python3

"""
Batch OCR via an OpenAI-compatible /v1/chat/completions endpoint with vision support.
- Supports file or folder input (recursive).
- Saves results incrementally to JSONL (filename -> extracted text or error).
- Resumes from existing output file to avoid reprocessing.
"""

import argparse
import base64
import json
import mimetypes
import os
import sys
import time
from pathlib import Path
from typing import Iterable, List, Dict, Optional

import requests

DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_BATCH_SIZE = 8
DEFAULT_TIMEOUT = 60
SUPPORTED_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff"}


def iter_images(path: Path, recursive: bool) -> Iterable[Path]:
    if path.is_file():
        if path.suffix.lower() in SUPPORTED_EXTS:
            yield path
        return
    if not path.is_dir():
        return
    globber = path.rglob if recursive else path.glob
    for p in sorted(globber("**/*" if recursive else "*")):
        if p.is_file() and p.suffix.lower() in SUPPORTED_EXTS:
            yield p


def load_done(output_file: Path) -> Dict[str, Dict]:
    done: Dict[str, Dict] = {}
    if not output_file.exists():
        return done
    with output_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                done[record.get("file", "")] = record
            except Exception:
                continue
    return done


def encode_image(path: Path) -> str:
    mime, _ = mimetypes.guess_type(str(path))
    if not mime:
        mime = "application/octet-stream"
    data = path.read_bytes()
    b64 = base64.b64encode(data).decode()
    return f"data:{mime};base64,{b64}"


def call_api(
    *,
    base_url: str,
    api_key: str,
    model: str,
    image_data_url: str,
    prompt: str,
    timeout: int,
) -> str:
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "temperature": 0,
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {"type": "image_url", "image_url": {"url": image_data_url}},
                ],
            }
        ],
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


def process_batch(
    files: List[Path],
    *,
    root: Path,
    base_url: str,
    api_key: str,
    model: str,
    prompt: str,
    timeout: int,
    retries: int,
    backoff: float,
    output_file: Path,
    done: Dict[str, Dict],
    verbose: bool,
) -> None:
    with output_file.open("a", encoding="utf-8") as out:
        for src in files:
            rel = str(src.relative_to(root))
            if rel in done:
                if verbose:
                    print(f"[skip] {rel} (already processed)")
                continue
            if verbose:
                print(f"[send] {rel}")
            image_url = encode_image(src)
            error: Optional[str] = None
            text: Optional[str] = None
            for attempt in range(1, retries + 1):
                try:
                    text = call_api(
                        base_url=base_url,
                        api_key=api_key,
                        model=model,
                        image_data_url=image_url,
                        prompt=prompt,
                        timeout=timeout,
                    )
                    break
                except Exception as e:
                    error = str(e)
                    if verbose:
                        print(f"  attempt {attempt}/{retries} failed: {error}")
                    if attempt < retries:
                        time.sleep(backoff * attempt)
            record = {"file": rel, "text": text, "error": error}
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            out.flush()


def chunked(seq: List[Path], size: int) -> Iterable[List[Path]]:
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def main() -> int:
    parser = argparse.ArgumentParser(description="Batch image OCR via OpenAI-compatible vision endpoint")
    parser.add_argument("input", help="Input file or directory")
    parser.add_argument("output", help="Output JSONL file (will append/resume)")
    parser.add_argument("--base-url", default="https://api.openai.com/v1", help="OpenAI-compatible base URL")
    parser.add_argument("--api-key", default=None, help="API key (default: env OPENAI_API_KEY)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Model name (default: {DEFAULT_MODEL})")
    parser.add_argument("--prompt", default="Extract all visible text from this image. Return plain text only. If some are too blur, ignore them and return null. HELPER files should return null", help="Prompt sent to the model")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="How many images to send per batch (sequentially)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout in seconds")
    parser.add_argument("--retries", type=int, default=3, help="Retry count per image")
    parser.add_argument("--backoff", type=float, default=2.0, help="Backoff multiplier (seconds)")
    parser.add_argument("--no-recursive", action="store_true", help="Do not recurse into subdirectories")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logs")
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("Error: API key not provided (set --api-key or OPENAI_API_KEY)", file=sys.stderr)
        return 1

    root = Path(args.input)
    recursive = not args.no_recursive
    files = list(iter_images(root, recursive=recursive))
    if not files:
        print(f"No supported images found under {root}", file=sys.stderr)
        return 1

    output_file = Path(args.output)
    done = load_done(output_file)

    if args.verbose:
        print(f"Found {len(files)} image(s), {len(done)} already done")
        print(f"Writing to {output_file} (JSONL)\n")

    for batch in chunked(files, max(1, args.batch_size)):
        process_batch(
            batch,
            root=root,
            base_url=args.base_url,
            api_key=api_key,
            model=args.model,
            prompt=args.prompt,
            timeout=args.timeout,
            retries=args.retries,
            backoff=args.backoff,
            output_file=output_file,
            done=done,
            verbose=args.verbose,
        )

    if args.verbose:
        print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
