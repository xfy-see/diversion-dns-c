#!/usr/bin/env python3
"""Pin direct decisions in the known OpenWrt mark-routing shell generator.

Transforms a local copy only. Review, nft-check, back up and apply separately.
Unknown/mixed generators fail closed; repeated application is idempotent.
"""
from pathlib import Path
import argparse

TARGETS = tuple((family, name) for name in ("direct", "geoip_direct", "dns_direct")
                for family in ("ip", "ip6"))
ACTION = ("meta mark set (meta mark & $MARK_CLEAR_HEX) | $BYPASS_MARK_HEX "
          "ct mark set (ct mark & $MARK_CLEAR_HEX) | $BYPASS_MARK_HEX counter return")


def patch(text):
    pairs = []
    for family, name in TARGETS:
        suffix = "v4" if family == "ip" else "v6"
        prefix = f"        {family} daddr @{name}_{suffix} "
        old, new = prefix + "counter return", prefix + ACTION
        pairs.append((old, new))
    lines = text.splitlines()
    old_counts = [lines.count(old) for old, _ in pairs]
    new_counts = [lines.count(new) for _, new in pairs]
    if old_counts == [0] * 6 and new_counts == [1] * 6:
        return text
    if old_counts != [1] * 6 or new_counts != [0] * 6:
        raise ValueError("unsupported or partially patched direct rules; refusing output")
    replacements = dict(pairs)
    return "".join(replacements.get(line.rstrip("\r\n"), line.rstrip("\r\n"))
                   + line[len(line.rstrip("\r\n")):] for line in text.splitlines(keepends=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("use a separate output file to retain the original")
    try:
        result = patch(args.input.read_text())
    except ValueError as error:
        parser.error(str(error))
    with args.output.open("x") as stream:
        stream.write(result)
    args.output.chmod(args.input.stat().st_mode & 0o777)


if __name__ == "__main__":
    main()
