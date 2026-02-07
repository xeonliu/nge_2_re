"""
Generate metadata for patch builds.

This script collects:
1. Git commit hashes for the main repo and submodules
2. Translation statistics from ParaTranz API
3. Generates a JSON metadata file
4. Creates a 480x272 image displaying the metadata
"""

import json
import os
import subprocess
import sys
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

import requests


def get_git_commit(repo_path: str = ".") -> str:
    """Get the current git commit hash."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return "unknown"


def get_submodule_commits() -> Dict[str, str]:
    """Get commit hashes for all submodules."""
    submodules = {}
    try:
        result = subprocess.run(
            ["git", "submodule", "status"],
            capture_output=True,
            text=True,
            check=True,
        )
        for line in result.stdout.strip().split("\n"):
            if line:
                # Format: " <commit> <path> (<description>)" or "-<commit> <path>"
                parts = line.strip().split()
                if len(parts) >= 2:
                    commit = parts[0].lstrip("-").lstrip("+")
                    path = parts[1]
                    submodules[path] = commit
    except subprocess.CalledProcessError:
        pass
    return submodules


def get_paratranz_stats(
    project_id: int = 10882, auth_key: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Get translation statistics from ParaTranz API."""
    if not auth_key:
        print("Warning: No AUTH_KEY provided, skipping ParaTranz stats")
        return None

    try:
        # Get project info
        url = f"https://paratranz.cn/api/projects/{project_id}"
        headers = {"Authorization": auth_key}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        project_data = response.json()

        # Get artifact info (latest build)
        artifacts_url = f"https://paratranz.cn/api/projects/{project_id}/artifacts"
        artifacts_response = requests.get(artifacts_url, headers=headers, timeout=10)
        artifacts_response.raise_for_status()
        artifacts_data = artifacts_response.json()

        # Combine data
        stats = {}
        if artifacts_data and len(artifacts_data) > 0:
            latest_artifact = artifacts_data[0]
            stats = {
                "id": latest_artifact.get("id"),
                "createdAt": latest_artifact.get("createdAt"),
                "project": project_id,
                "total": latest_artifact.get("total", 0),
                "translated": latest_artifact.get("translated", 0),
                "disputed": latest_artifact.get("disputed", 0),
                "checked": latest_artifact.get("checked", 0),
                "reviewed": latest_artifact.get("reviewed", 0),
                "hidden": latest_artifact.get("hidden", 0),
                "size": latest_artifact.get("size", 0),
                "duration": latest_artifact.get("duration", 0),
            }
        else:
            # Fallback to project data
            stats = {
                "project": project_id,
                "name": project_data.get("name", ""),
                "total": project_data.get("total", 0),
                "translated": project_data.get("translated", 0),
                "disputed": project_data.get("disputed", 0),
                "reviewed": project_data.get("reviewed", 0),
            }

        return stats
    except Exception as e:
        print(f"Warning: Failed to get ParaTranz stats: {e}")
        return None


def generate_metadata(
    output_path: str, auth_key: Optional[str] = None
) -> Dict[str, Any]:
    """Generate complete metadata."""
    metadata = {
        "generated_at": datetime.now().isoformat(),
        "git": {
            "main_commit": get_git_commit(),
            "submodules": get_submodule_commits(),
        },
        "translation": get_paratranz_stats(auth_key=auth_key),
    }

    # Save to JSON
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)

    print(f"Metadata saved to: {output_path}")
    return metadata


def generate_metadata_image(metadata: Dict[str, Any], output_path: str):
    """Generate a 480x272 image displaying metadata."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        print("Warning: Pillow not installed, skipping image generation")
        return

    # Create image
    width, height = 480, 272
    background_color = (30, 30, 40)
    text_color = (255, 255, 255)
    accent_color = (100, 180, 255)

    img = Image.new("RGB", (width, height), background_color)
    draw = ImageDraw.Draw(img)

    # Try to use a default font, fallback to default if not available
    try:
        # Try to load a font with decent size
        font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 20)
        font_medium = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
        font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 12)
    except:
        # Fallback to default font
        font_large = ImageFont.load_default()
        font_medium = ImageFont.load_default()
        font_small = ImageFont.load_default()

    y = 10

    # Title
    title = "NGE2 汉化补丁构建信息"
    draw.text((10, y), title, fill=accent_color, font=font_large)
    y += 30

    # Commit info
    main_commit = metadata["git"]["main_commit"][:8]
    draw.text((10, y), f"主仓库: {main_commit}", fill=text_color, font=font_medium)
    y += 20

    # Submodules
    for path, commit in metadata["git"]["submodules"].items():
        draw.text(
            (10, y), f"  {path}: {commit[:8]}", fill=text_color, font=font_small
        )
        y += 18

    # Translation stats
    if metadata.get("translation"):
        y += 5
        draw.text((10, y), "翻译统计", fill=accent_color, font=font_medium)
        y += 20

        trans = metadata["translation"]
        total = trans.get("total", 0)
        translated = trans.get("translated", 0)
        disputed = trans.get("disputed", 0)
        reviewed = trans.get("reviewed", 0)

        if total > 0:
            percent = (translated / total) * 100
            draw.text(
                (10, y),
                f"词条总数: {total}",
                fill=text_color,
                font=font_small,
            )
            y += 18
            draw.text(
                (10, y),
                f"已翻译: {translated} / {percent:.2f}%",
                fill=text_color,
                font=font_small,
            )
            y += 18
            draw.text(
                (10, y), f"有疑问: {disputed}", fill=text_color, font=font_small
            )
            y += 18
            if reviewed > 0:
                review_percent = (reviewed / total) * 100
                draw.text(
                    (10, y),
                    f"已审核: {reviewed} / {review_percent:.2f}%",
                    fill=text_color,
                    font=font_small,
                )
                y += 18

        # Build time if available
        if "createdAt" in trans:
            created_at = trans["createdAt"]
            # Parse ISO format
            try:
                dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                time_str = dt.strftime("%Y-%m-%d %H:%M")
                draw.text(
                    (10, y), f"生成时间: {time_str}", fill=text_color, font=font_small
                )
                y += 18
            except:
                pass

        # File size if available
        if "size" in trans and trans["size"] > 0:
            size_mb = trans["size"] / (1024 * 1024)
            draw.text(
                (10, y), f"文件大小: {size_mb:.2f} MB", fill=text_color, font=font_small
            )
            y += 18

    # Generation timestamp
    gen_time = metadata["generated_at"]
    try:
        dt = datetime.fromisoformat(gen_time)
        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
    except:
        time_str = gen_time

    # Bottom info
    draw.text(
        (10, height - 20), f"生成于: {time_str}", fill=(150, 150, 150), font=font_small
    )

    # Save image
    img.save(output_path)
    print(f"Metadata image saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate patch metadata")
    parser.add_argument(
        "--output",
        default="build/metadata.json",
        help="Output JSON file path",
    )
    parser.add_argument(
        "--image",
        default="build/metadata.png",
        help="Output image file path",
    )
    parser.add_argument(
        "--auth-key",
        help="ParaTranz auth key (or use AUTH_KEY env var)",
    )

    args = parser.parse_args()

    # Get auth key from args or environment
    auth_key = args.auth_key or os.getenv("AUTH_KEY")

    # Ensure output directory exists
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.image).parent.mkdir(parents=True, exist_ok=True)

    # Generate metadata
    metadata = generate_metadata(args.output, auth_key=auth_key)

    # Generate image
    generate_metadata_image(metadata, args.image)

    print("\nMetadata generation complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
