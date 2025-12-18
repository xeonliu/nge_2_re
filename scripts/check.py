"""
Translation Quality Checker for NGE2 Re-translation Project

This script validates translation files by checking:
- Special character consistency (format specifiers like %s, %d, $s, etc.)
- Encoding compatibility with EVA SJIS
- Length constraints for EBOOT translations
- Content paging limits for EVS translations

Usage:
    python check.py <translation_file> <report_file> <type>

    type: 'eboot' or 'evs'
"""

import re
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

from app.parser.tools.common import to_eva_sjis
from app.parser.tools.evs import CONTENT_BYTE_LIMIT

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def find_special_characters(s: str) -> Dict[str, int]:
    """
    Find all format specifiers and special characters in a string.

    Matches patterns like:
    - %s, %d, %f, %x, %X, %o, %e, %E, %g, %G (C-style format specifiers)
    - $s, $d, $f, etc. (script-style variables)

    Args:
        s: Input string to search

    Returns:
        Dictionary mapping each found specifier to its occurrence count

    Example:
        >>> find_special_characters("Player %s has %d items")
        {'%s': 1, '%d': 1}
    """
    # Pattern for C-style format specifiers: %s, %d, %2d, etc.
    pattern = r"%[0-9]*[a-zA-Z]+"
    # Pattern for script-style variables: $s, $d, $1s, etc.
    pattern += r"|\$[0-9]*[a-zA-Z]+"
    # Pattern for SJIS full-width characters (digits and letters)
    pattern += r"|［０-９Ａ-Ｚａ-ｚ］"

    matches = re.findall(pattern, s)

    # Count occurrences of each specifier
    result = {}
    for match in matches:
        result[match] = result.get(match, 0) + 1
    return result


def match_exist_in_string(matches: Dict[str, int], string: str) -> None:
    """
    Verify that all format specifiers in the original string exist in the translation
    with the same count.

    Args:
        matches: Dictionary of specifiers and their counts from the original string
        string: Translation string to validate

    Raises:
        ValueError: If any specifier is missing or has a different count

    Example:
        Original has {'%s': 2, '%d': 1}
        Translation must also have exactly 2 '%s' and 1 '%d'
    """
    matches_in_str = find_special_characters(string)

    # Verify each specifier exists with the correct count
    for key, value in matches.items():
        if key not in matches_in_str or matches_in_str[key] != value:
            raise ValueError(
                f"Format specifier mismatch: '{key}' appears {value} time(s) in original "
                f"but {matches_in_str.get(key, 0)} time(s) in translation"
            )


def special_character_error(source: str, translation: str) -> None:
    """
    Validate that format specifiers are preserved correctly in translation.

    This ensures that all format specifiers (e.g., %s, %d, $1s) in the original
    text appear with the same count in the translation. This is critical for
    runtime string formatting to work correctly.

    Args:
        source: Original Japanese text
        translation: Translated text

    Raises:
        ValueError: If format specifiers don't match between source and translation
    """
    matches = find_special_characters(source)
    match_exist_in_string(matches, translation)


def eboot_length_error(source: str, translation: str) -> None:
    """
    Check EBOOT translation length constraints.

    EBOOT has strict memory constraints for string replacements. Translations
    that are longer than the original may cause buffer overflows or memory issues.

    Length difference handling:
    - 1-4 bytes longer: Warning (might work but risky)
    - 5+ bytes longer: Error (will likely cause issues)

    Args:
        source: Original Japanese text
        translation: Translated text

    Raises:
        ValueError: If translation exceeds safe length limits
    """
    original_bytes = to_eva_sjis(source)
    translation_bytes = to_eva_sjis(translation)
    diff = len(translation_bytes) - len(original_bytes)

    if diff in range(1, 5):
        raise ValueError(
            f"Length warning: Translation is {diff} byte(s) longer than original "
            f"({len(translation_bytes)} vs {len(original_bytes)} bytes). "
            f"May cause issues in EBOOT."
        )
    elif diff > 4:
        raise ValueError(
            f"Length error: Translation is {diff} byte(s) longer than original "
            f"({len(translation_bytes)} vs {len(original_bytes)} bytes). "
            f"Will likely cause buffer overflow in EBOOT."
        )


def encoding_error(source: str, translation: str) -> None:
    """
    Validate that translation can be encoded to EVA SJIS.

    EVA SJIS is a custom Shift-JIS encoding used by the game. Not all Unicode
    characters can be represented in this encoding. This check ensures the
    translation only uses supported characters.

    Args:
        source: Original Japanese text (unused, for signature consistency)
        translation: Translated text to validate

    Raises:
        ValueError: If translation contains characters not supported by EVA SJIS
    """
    try:
        to_eva_sjis(translation)
    except Exception as e:
        raise ValueError(f"Encoding error: {str(e)}")


def paging_error(source: str, translation: str) -> None:
    """
    Check EVS content paging limits.

    EVS dialogue uses the '▽' character to mark page breaks in text boxes.
    Each page has a byte limit (CONTENT_BYTE_LIMIT). This check ensures that
    no single page exceeds this limit after being split by '▽'.

    Args:
        source: Original Japanese text (unused, for signature consistency)
        translation: Translated text to validate

    Raises:
        ValueError: If any page exceeds the byte limit after splitting

    Note:
        Spaces and newlines are stripped before counting, as they may be
        handled specially by the game engine.
    """
    # Split by page break marker
    split_contents = translation.split("▽")
    for idx, content in enumerate(split_contents, 1):
        # Further split by $n
        sub_contents = content.split("$n")
        for sub_idx, sub_content in enumerate(sub_contents, 1):
            raw_content = to_eva_sjis(sub_content)
            # Strip spaces and newlines as they may not count toward the limit
            raw_split_length = len(
                raw_content.replace(b" ", b"").replace(b"\n", b"") + to_eva_sjis("▽")
            )
            if raw_split_length >= CONTENT_BYTE_LIMIT:
                raise ValueError(
                    f"Paging error: Page {idx}-$n{sub_idx} exceeds limit "
                    f"({raw_split_length} >= {CONTENT_BYTE_LIMIT} bytes). "
                    f"Content: '{sub_content[:50]}{'...' if len(sub_content) > 50 else ''}'"
                )


def validate_translations(
    translation_file: Path, report_file: Path, check_type: str
) -> int:
    """
    Validate all translations in a file and generate an error report.

    Args:
        translation_file: Path to JSON file containing translations
        report_file: Path to write error report JSON
        check_type: Type of check to perform ('eboot' or 'evs')

    Returns:
        Number of errors found
    """
    logger.info(f"Loading translations from: {translation_file}")

    # Load translation data
    try:
        with open(translation_file, "r", encoding="utf-8") as f:
            translation_data = json.load(f)
    except FileNotFoundError:
        logger.error(f"Translation file not found: {translation_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in translation file: {e}")
        sys.exit(1)

    logger.info(f"Checking {len(translation_data)} translation entries...")
    logger.info(f"Check type: {check_type}")

    errors: List[Dict] = []
    checked_count = 0
    skipped_count = 0

    # Validate each translation entry
    for idx, elem in enumerate(translation_data, 1):
        # Validate entry structure
        if "original" not in elem or "translation" not in elem:
            logger.warning(
                f"Entry {idx}: Missing 'original' or 'translation' key, skipping"
            )
            skipped_count += 1
            continue

        if not elem.get("translation"):
            # Skip empty translations
            skipped_count += 1
            continue

        original = elem["original"]
        translation = elem["translation"]
        entry_key = elem.get("key", f"entry_{idx}")

        checked_count += 1

        # Run validation checks
        try:
            # Always check format specifiers
            special_character_error(original, translation)

            # Length ratio check (translation > 2x original)
            if len(translation) > 2 * len(original):
                raise ValueError(
                    f"Length ratio warning: Translation length {len(translation)} is more than 2x original length {len(original)}."
                )

            # Type-specific checks
            if check_type == "eboot":
                eboot_length_error(original, translation)
            elif check_type == "evs":
                encoding_error(original, translation)
                paging_error(original, translation)
            else:
                logger.warning(f"Unknown check type: {check_type}")

        except ValueError as e:
            logger.error(f"Entry {idx} ({entry_key}): {e}")
            errors.append(
                {
                    "key": entry_key,
                    "original": original,
                    "translation": translation,
                    "error": str(e),
                }
            )

    # Summary statistics
    logger.info("=" * 60)
    logger.info(f"Validation complete:")
    logger.info(f"  Total entries: {len(translation_data)}")
    logger.info(f"  Checked: {checked_count}")
    logger.info(f"  Skipped: {skipped_count}")
    logger.info(f"  Errors: {len(errors)}")
    logger.info(
        f"  Success rate: {(checked_count - len(errors)) / checked_count * 100:.1f}%"
    )
    logger.info("=" * 60)

    # Write error report
    report_file.parent.mkdir(parents=True, exist_ok=True)
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(errors, f, ensure_ascii=False, indent=4)

    logger.info(f"Error report saved to: {report_file}")

    return len(errors)


def main():
    """Main entry point for the translation checker."""
    if len(sys.argv) < 4:
        print("Usage: python check.py <translation_file> <report_file> <type>")
        print("  type: 'eboot' or 'evs'")
        sys.exit(1)

    translation_file = Path(sys.argv[1])
    report_file = Path(sys.argv[2])
    check_type = sys.argv[3].lower()

    error_count = validate_translations(translation_file, report_file, check_type)

    # Exit with error code if validation failed
    # sys.exit(1 if error_count > 0 else 0)


if __name__ == "__main__":
    main()
