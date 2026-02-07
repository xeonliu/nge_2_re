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

        # Combine data - artifacts API returns a single object or a list
        stats = {}
        latest_artifact = None
        
        if isinstance(artifacts_data, dict):
            # If it's a dict, use it directly
            latest_artifact = artifacts_data
        elif isinstance(artifacts_data, list) and len(artifacts_data) > 0:
            # If it's a list, get the first item
            latest_artifact = artifacts_data[0]
        
        if latest_artifact:
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
    """Generate a 480x272 image displaying metadata with text in bottom-right corner with semi-transparent background."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        print("Warning: Pillow not installed, skipping image generation")
        return

    # Create image with RGBA for transparency
    width, height = 480, 272
    background_color = (30, 30, 40, 0)  # Transparent
    text_color = (255, 255, 255)
    accent_color = (100, 180, 255)
    box_color = (30, 30, 40, 200)  # Semi-transparent background box

    img = Image.new("RGBA", (width, height), background_color)
    draw = ImageDraw.Draw(img)

    # Try to use a default font, fallback to default if not available
    try:
        # Try common font paths across different systems with CJK support
        font_paths = [
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",  # Noto Sans CJK
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",  # Fallback
            "/System/Library/Fonts/Helvetica.ttc",  # macOS
            "C:\\Windows\\Fonts\\SimSun.ttc",  # Windows
        ]
        font_large = None
        for font_path in font_paths:
            try:
                font_large = ImageFont.truetype(font_path, 20)
                break
            except (OSError, IOError):
                continue
        
        if font_large is None:
            # If no font found, use default
            raise OSError("No truetype fonts found")
            
        # Load other font sizes from the same font
        font_medium = ImageFont.truetype(font_large.path, 14)
        font_small = ImageFont.truetype(font_large.path, 12)
    except (OSError, IOError):
        # Fallback to default font
        font_large = ImageFont.load_default()
        font_medium = ImageFont.load_default()
        font_small = ImageFont.load_default()

    # First pass: collect all text lines to be drawn
    lines = []
    
    # Title
    lines.append(("NGE2 汉化补丁构建信息", font_large, accent_color))

    # Commit info
    main_commit = metadata["git"]["main_commit"][:8]
    lines.append((f"主仓库: {main_commit}", font_medium, text_color))

    # Submodules
    for path, commit in metadata["git"]["submodules"].items():
        lines.append((f"  {path}: {commit[:8]}", font_small, text_color))

    # Translation stats
    if metadata.get("translation"):
        lines.append(("翻译统计", font_medium, accent_color))

        trans = metadata["translation"]
        total = trans.get("total", 0)
        translated = trans.get("translated", 0)
        disputed = trans.get("disputed", 0)
        reviewed = trans.get("reviewed", 0)

        if total > 0:
            lines.append((f"词条总数 {total}", font_small, text_color))
            translated_percent = (translated / total) * 100
            lines.append((f"已翻译条数 {translated} / {translated_percent:.2f}%", font_small, text_color))
            lines.append((f"有疑问条数 {disputed}", font_small, text_color))
            
            if reviewed > 0:
                review_percent = (reviewed / total) * 100
                lines.append((f"已审核条数 {reviewed} / {review_percent:.2f}%", font_small, text_color))
            else:
                lines.append((f"已审核条数 0 / 0.00%", font_small, text_color))

        # Build time if available
        if "createdAt" in trans:
            created_at = trans["createdAt"]
            try:
                dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                time_str = dt.strftime("%Y-%m-%d %H:%M")
                lines.append((f"生成时间: {time_str}", font_small, text_color))
            except (ValueError, AttributeError):
                pass

        # File size if available
        if "size" in trans and trans["size"] > 0:
            size_mb = trans["size"] / (1024 * 1024)
            lines.append((f"文件大小: {size_mb:.2f} MB", font_small, text_color))

    # Generation timestamp
    gen_time = metadata["generated_at"]
    try:
        dt = datetime.fromisoformat(gen_time)
        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, AttributeError):
        time_str = gen_time
    lines.append((f"生成于: {time_str}", font_small, (150, 150, 150)))

    # Calculate dimensions based on actual text bounds
    line_heights = []
    max_width = 0
    
    for text, font, _ in lines:
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        line_heights.append(text_height)
        max_width = max(max_width, text_width)

    # Calculate total height with spacing between lines
    line_spacing = 4  # Extra spacing between lines
    total_text_height = sum(line_heights) + len(lines) * line_spacing - line_spacing

    # Add padding
    padding = 10
    box_width = max_width + padding * 2
    box_height = total_text_height + padding * 2

    # Position in bottom-right corner
    box_right = width - 5
    box_bottom = height - 5
    box_left = box_right - box_width
    box_top = box_bottom - box_height

    # Draw semi-transparent background box
    draw.rectangle([box_left, box_top, box_right, box_bottom], fill=box_color)

    # Draw text lines
    y = box_top + padding
    for (text, font, color), line_height in zip(lines, line_heights):
        draw.text((box_left + padding, y), text, fill=color, font=font)
        y += line_height + line_spacing

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
