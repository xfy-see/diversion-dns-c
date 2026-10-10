#!/usr/bin/env python3
"""Stage a frozen local source snapshot; never download, build, or install it."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def stage(destination, source_ref="HEAD"):
    destination = Path(destination).resolve()
    if destination.exists():
        raise ValueError("destination already exists; choose a fresh package directory")
    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", source_ref + "^{commit}"], cwd=ROOT,
        text=True).strip()
    archive = subprocess.check_output(
        ["git", "archive", "--format=tar", commit, "c", "LICENSE"], cwd=ROOT)
    # Resolve a commit first: uncommitted application changes are never mixed in.
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar:
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("unsafe source archive path")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("source archive must contain only regular files")
            files[member.name] = tar.extractfile(member).read()
    recipe = subprocess.check_output(
        ["git", "show", commit + ":packaging/openwrt/Makefile"], cwd=ROOT)
    destination.mkdir(parents=True)
    for name, content in files.items():
        path = destination / "src" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (destination / "Makefile").write_bytes(recipe)
    manifest = {
        "source_commit": commit,
        "source_files_sha256": {name: hashlib.sha256(content).hexdigest()
                                for name, content in sorted(files.items())},
        "recipe_sha256": hashlib.sha256(recipe).hexdigest(),
        "scope": "experimental package input only; no deployment or firmware changes",
    }
    (destination / "source-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path,
                        help="fresh SDK/package/diversion-dns-c-lite directory")
    parser.add_argument("--source-ref", default="HEAD",
                        help="local commit/ref to freeze (default: HEAD)")
    args = parser.parse_args()
    try:
        manifest = stage(args.destination, args.source_ref)
    except (ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    print(json.dumps({"destination": str(args.destination.resolve()),
                      "source_commit": manifest["source_commit"]}))


if __name__ == "__main__":
    main()
