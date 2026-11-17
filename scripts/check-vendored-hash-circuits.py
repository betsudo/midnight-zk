#!/usr/bin/env python3
"""Verify the vendored hash-circuit payload against its recorded source copy."""

import hashlib
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKSUMS = ROOT / "third_party" / "SHA256SUMS"
SOURCE_ROOTS = (
    ROOT / "third_party" / "blake2b_halo2",
    ROOT / "third_party" / "sha3-circuit",
)


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def main() -> None:
    expected: dict[pathlib.Path, str] = {}
    for line in CHECKSUMS.read_text().splitlines():
        checksum, relative = line.split("  ", maxsplit=1)
        path = ROOT / relative
        if path in expected:
            raise SystemExit(f"duplicate checksum entry: {relative}")
        expected[path] = checksum

    actual = {
        path
        for source_root in SOURCE_ROOTS
        for path in source_root.rglob("*")
        if path.is_file() and path.name != "Cargo.toml"
    }
    missing = sorted(path.relative_to(ROOT) for path in expected.keys() - actual)
    unexpected = sorted(path.relative_to(ROOT) for path in actual - expected.keys())
    if missing or unexpected:
        raise SystemExit(
            f"vendored source inventory mismatch; missing={missing}, unexpected={unexpected}"
        )

    mismatches = [
        path.relative_to(ROOT)
        for path, checksum in expected.items()
        if digest(path) != checksum
    ]
    if mismatches:
        raise SystemExit(f"vendored source checksum mismatch: {sorted(mismatches)}")
    print(f"verified {len(expected)} vendored hash-circuit source files")


if __name__ == "__main__":
    main()
