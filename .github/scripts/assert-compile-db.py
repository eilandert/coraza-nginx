#!/usr/bin/env python3
"""Assert a bear-captured compile DB covers every translation unit given.

bear only records compilations it actually observes. When the objects already
exist (cache restore, incremental tree, a retried step) `make modules` is a
no-op, bear captures nothing, and clang-tidy -p silently skips every file while
still exiting 0 -- a security gate that passes having analysed nothing. This
turns that condition into a hard, explicit failure at capture time.
"""
import json
import os
import sys


def main(argv):
    if len(argv) < 3:
        print("usage: assert-compile-db.py <compile_commands.json> <file.c>...",
              file=sys.stderr)
        return 2

    db_path, sources = argv[1], argv[2:]
    try:
        with open(db_path, encoding="utf-8") as fh:
            entries = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"FATAL: unreadable compile DB {db_path}: {exc}", file=sys.stderr)
        return 1

    if not isinstance(entries, list):
        print("FATAL: compile DB is not a JSON array", file=sys.stderr)
        return 1

    covered = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("file", "")
        if not name:
            continue
        # An entry with no command is not coverage: a stale or truncated DB can
        # list every path while carrying no flags, which would let clang-tidy
        # analyse with the wrong (or no) -I set while this gate reports success.
        if not entry.get("command") and not entry.get("arguments"):
            print(f"FATAL: compile DB entry for {name} has no command/arguments",
                  file=sys.stderr)
            return 1
        if not os.path.isabs(name):
            name = os.path.join(entry.get("directory", ""), name)
        covered.add(os.path.realpath(name))

    print(f"compile DB entries: {len(entries)}")

    missing = [s for s in sources if os.path.realpath(s) not in covered]
    for name in missing:
        print(f"FATAL: no compile_commands.json entry for {name}", file=sys.stderr)

    if not sources:
        print("FATAL: no translation units given -- gate would pass vacuously",
              file=sys.stderr)
        return 1

    if missing:
        print(f"FATAL: compile DB covers {len(sources) - len(missing)} of "
              f"{len(sources)} translation units; the clang-tidy gate would "
              "pass vacuously. Refusing to continue.", file=sys.stderr)
        return 1

    print(f"compile DB covers all {len(sources)} translation unit(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
