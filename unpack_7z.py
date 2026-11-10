#!/usr/bin/env python3
"""Recursively extract .7z archives, one directory per archive.

Requires: pip install py7zr
Do not run extracted malware; use an isolated analysis environment.
"""

import argparse
import getpass
import os
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath

try:
    import py7zr
except ImportError:
    sys.exit("Install dependency: python3 -m pip install py7zr")

MARKER = ".unpack_7z_complete"


def safe_entry(name: str) -> bool:
    normalized = name.replace("\\", "/")
    p = PurePosixPath(normalized)
    w = PureWindowsPath(name)
    return (bool(normalized) and not p.is_absolute() and not w.is_absolute()
            and not w.drive and ".." not in p.parts and "\x00" not in name)


def unpack(archive: Path, password: str | None, dry_run: bool, force: bool) -> str:
    target = archive.with_suffix("")
    marker = target / MARKER
    if marker.is_file() and not force:
        return "SKIP"
    if target.exists() and not force:
        return "EXISTS"
    if dry_run:
        return "DRY"

    # Temporary extraction directory is on the same filesystem as the target.
    tmp = Path(tempfile.mkdtemp(prefix=".unpack7z-", dir=archive.parent))
    try:
        with py7zr.SevenZipFile(archive, mode="r", password=password) as z:
            entries = z.getnames()
            if not all(safe_entry(n) for n in entries):
                raise ValueError("Archive contains unsafe paths")
            # Reject symbolic links when the archive metadata exposes them.
            for item in z.list():
                if getattr(item, "is_symlink", False):
                    raise ValueError("Archive contains symbolic links")
            z.extractall(path=tmp)

        # Reject links in the output as an additional safety check.
        for base, dirs, files in os.walk(tmp, followlinks=False):
            for name in dirs + files:
                p = Path(base) / name
                if p.is_symlink():
                    raise ValueError(f"Symbolic link in extracted output: {p}")

        if target.exists():
            if force and target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                raise FileExistsError(target)
        tmp.rename(target)
        marker.write_text(f"source={archive.name}\n", encoding="utf-8")
        return "OK"
    finally:
        if tmp.exists():
            shutil.rmtree(tmp)


def main():
    parser = argparse.ArgumentParser(description="Recursively extract .7z archives")
    parser.add_argument("root", type=Path, help="Root directory to scan")
    parser.add_argument("--password", help="7z archive password (avoid for secrets: visible in process arguments)")
    parser.add_argument("--ask-password", action="store_true", help="Prompt for password without echo")
    parser.add_argument("--dry-run", action="store_true", help="Show planned operations only")
    parser.add_argument("--force", action="store_true", help="Replace previously extracted folders")
    args = parser.parse_args()

    root = args.root.expanduser().resolve()
    if not root.is_dir():
        parser.error(f"Not a directory: {root}")
    if args.ask_password and args.password is not None:
        parser.error("Choose either --password or --ask-password")
    password = getpass.getpass("7z password: ") if args.ask_password else args.password

    # Snapshot: don't recursively unpack newly extracted archives in this run.
    archives = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() == ".7z")
    counts = {"OK": 0, "SKIP": 0, "EXISTS": 0, "DRY": 0, "ERROR": 0}
    print(f"Found {len(archives)} .7z archives under {root}", flush=True)
    for i, archive in enumerate(archives, 1):
        try:
            result = unpack(archive, password, args.dry_run, args.force)
            counts[result] += 1
            print(f"[{i}/{len(archives)}] [{result}] {archive.relative_to(root)}", flush=True)
        except (Exception, KeyboardInterrupt) as exc:
            if isinstance(exc, KeyboardInterrupt):
                print("\nInterrupted; completed extractions remain available.", file=sys.stderr)
                raise SystemExit(130)
            counts["ERROR"] += 1
            print(f"[{i}/{len(archives)}] [ERROR] {archive.relative_to(root)}: {exc}", file=sys.stderr, flush=True)
    print("Summary:", ", ".join(f"{key}={value}" for key, value in counts.items()))
    return 1 if counts["ERROR"] else 0


if __name__ == "__main__":
    sys.exit(main())
