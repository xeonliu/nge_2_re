def add_comment_to_string(string_id: int, content: str, auth: str) -> bool:
    """Add a comment to a string in Paratranz."""
    url = "https://paratranz.cn/api/comments"
    headers = {"Authorization": auth}
    data = {"type": "text", "tid": string_id, "content": content, "images": []}
    try:
        response = requests.post(url, headers=headers, json=data, timeout=10)
        response.raise_for_status()
        print(f"      └─ Added comment for {string_id}")
        return True
    except requests.RequestException as e:
        print(f"      └─ Failed to add comment for {string_id}: {e}")
        return False
#!/usr/bin/env python3
"""
Mark strings from report.json as untranslated in Paratranz API.
Reads report.json files and marks them as stage 0 (untranslated).
"""

import requests
import json
import argparse
import time
from pathlib import Path

project_id = 10882


def search_by_original(original_text: str, auth: str) -> list:
    """Search for a string by its original text."""
    url = f"https://paratranz.cn/api/projects/{project_id}/strings"
    headers = {"Authorization": auth}
    params = {"text": original_text}
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        # print(data)
        return data.get("results", [])
    except requests.RequestException as e:
        print(f"Error searching for '{original_text[:50]}...': {e}")
        return []


def mark_as_untranslated(string_id: int, auth: str) -> bool:
    """Mark a string as untranslated (stage 0)."""
    url = f"https://paratranz.cn/api/projects/{project_id}/strings/{string_id}"
    headers = {"Authorization": auth}
    data = {"stage": 0}
    
    try:
        response = requests.put(url, headers=headers, json=data, timeout=10)
        response.raise_for_status()
        return True
    except requests.RequestException as e:
        print(f"Error marking string {string_id} as untranslated: {e}")
        return False


def process_report(report_path: str, auth: str, dry_run: bool = False) -> dict:
    """
    Process a report.json file and mark all entries as untranslated.
    
    Args:
        report_path: Path to report.json file
        auth: Authorization token for Paratranz API
        dry_run: If True, only show what would be done without making changes
    
    Returns:
        Dictionary with statistics
    """
    stats = {
        "total": 0,
        "marked": 0,
        "failed": 0,
        "not_found": 0
    }
    
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            entries = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error reading {report_path}: {e}")
        return stats
    
    print(f"\nProcessing {len(entries)} entries from {Path(report_path).name}")
    print("=" * 60)
    
    for idx, entry in enumerate(entries, 1):
        stats["total"] += 1
        original = entry.get("original", "")
        error = entry.get("error", None)

        original = original.replace('\n', '\\n').replace('\r', '\\r')

        if not original:
            print(f"[{idx}/{len(entries)}] Skipping empty original text")
            continue

        # Search for the string
        results = search_by_original(original, auth)

        if not results:
            print(f"[{idx}/{len(entries)}] NOT FOUND: {original[:50]}...")
            stats["not_found"] += 1
            time.sleep(0.3)
            continue

        # Mark the first result as untranslated
        string_id = results[0]["id"]

        if dry_run:
            print(f"[{idx}/{len(entries)}] [DRY RUN] Would mark {string_id}: {original[:50]}...")
            stats["marked"] += 1
        else:
            if mark_as_untranslated(string_id, auth):
                print(f"[{idx}/{len(entries)}] ✓ Marked {string_id}: {original[:50]}...")
                stats["marked"] += 1
                if error:
                    add_comment_to_string(string_id, error, auth)
            else:
                print(f"[{idx}/{len(entries)}] ✗ Failed to mark {string_id}: {original[:50]}...")
                stats["failed"] += 1

        # Rate limiting
        time.sleep(0.5)
    
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Mark strings from report.json as untranslated in Paratranz"
    )
    parser.add_argument(
        "report",
        help="Path to report.json file or directory containing report.json files"
    )
    parser.add_argument(
        "-t", "--token",
        required=False,
        help="Paratranz API authorization token (or set AUTH_KEY env var)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Process all report.json files in build/ directory"
    )
    
    args = parser.parse_args()

    import os
    token = args.token or os.environ.get("AUTH_KEY")
    if not token:
        print("Error: Please provide --token or set AUTH_KEY environment variable.")
        return

    reports = []

    if args.all:
        # Find all report.json files in build directory
        build_dir = Path(__file__).parent.parent.parent / "build"
        reports = sorted(build_dir.glob("*_report.json"))
        if not reports:
            print(f"No report.json files found in {build_dir}")
            return
    else:
        report_path = Path(args.report)
        if report_path.is_dir():
            # Find all report.json files in the directory
            reports = sorted(report_path.glob("*_report.json"))
            if not reports:
                print(f"No report.json files found in {report_path}")
                return
        else:
            reports = [report_path]

    print(f"\nFound {len(reports)} report file(s) to process")
    if args.dry_run:
        print("[DRY RUN MODE] - No changes will be made\n")

    total_stats = {
        "total": 0,
        "marked": 0,
        "failed": 0,
        "not_found": 0
    }

    for report_path in reports:
        stats = process_report(str(report_path), token, args.dry_run)

        # Accumulate stats
        for key in total_stats:
            total_stats[key] += stats[key]

        print(f"Stats for {report_path.name}:")
        print(f"  Total: {stats['total']}")
        print(f"  Marked: {stats['marked']}")
        print(f"  Failed: {stats['failed']}")
        print(f"  Not Found: {stats['not_found']}")

    print("\n" + "=" * 60)
    print("OVERALL STATISTICS")
    print("=" * 60)
    print(f"Total entries: {total_stats['total']}")
    print(f"Successfully marked: {total_stats['marked']}")
    print(f"Failed: {total_stats['failed']}")
    print(f"Not found: {total_stats['not_found']}")


if __name__ == "__main__":
    main()
