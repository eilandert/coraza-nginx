#!/usr/bin/env python3
"""Exercise Docker's actual library fetch stanza with local archive fixtures.

Run: python3 ci/docker-library-pin.py
This checks selection, verification and extraction; it is not an image smoke test.
"""

import hashlib
import os
import re
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = Path(os.environ.get("F10_DOCKERFILE", ROOT / "Dockerfile"))


class LibraryPinTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.ci = self.work / "ci"
        self.ci.mkdir()
        self.archive = self.work / "fixture.zip"
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("libcoraza-central/marker", "central")
        self.legacy = self.work / "fixture.tar.gz"
        source = self.work / "legacy-marker"
        source.write_text("override")
        with tarfile.open(self.legacy, "w:gz") as archive:
            archive.add(source, arcname="corazawaf-libcoraza-override/marker")
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        (self.ci / "fetch-verify.sh").write_bytes(
            (ROOT / ".github/scripts/fetch-verify.sh").read_bytes()
        )
        self.write_pin()
        self.stub(
            "curl",
            """#!/bin/sh
printf '%s\\n' "$*" >> "$FETCH_LOG"
while [ "$1" != -o ]; do shift; done
cp "$ZIP_FIXTURE" "$2"
""",
        )
        self.stub(
            "wget",
            """#!/bin/sh
printf '%s\\n' "$1" >> "$FETCH_LOG"
[ "$1" != 'https://github.com/corazawaf/libcoraza/tarball/' ] || exit 2
cp "$TAR_FIXTURE" "$3"
""",
        )

    def stub(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def write_pin(self, checksum=None):
        (self.ci / "versions.env").write_text(
            "LIBCORAZA_VERSION=v9.8.7\nLIBCORAZA_SHA256="
            + (checksum or self.digest)
            + "\n"
        )

    def fetch(self, override=None):
        text = DOCKERFILE.read_text().replace("\\\n", " ")
        match = re.search(r"^RUN (.*?);\s*\./build\.sh;", text, re.MULTILINE)
        self.assertIsNotNone(match, "Docker library fetch/build stanza exists")
        script = match.group(1).replace("/tmp/ci", str(self.ci))
        script = script.replace("/tmp/libcoraza", str(self.work / "libcoraza"))
        # The old recipe extracts in its working directory; the new one selects
        # an isolated directory. Both must yield the downloaded archive marker.
        script += "; cat marker"
        env = os.environ.copy()
        env.pop("LIBCORAZA_VERSION", None)
        default = re.search(r"^ARG LIBCORAZA_VERSION=(.*)$", text, re.MULTILINE)
        if default:
            env["LIBCORAZA_VERSION"] = default.group(1)
        if override is not None:
            env["LIBCORAZA_VERSION"] = override
        env.update(
            PATH=str(self.bin) + os.pathsep + env["PATH"],
            FETCH_LOG=str(self.work / "fetch.log"),
            ZIP_FIXTURE=str(self.archive),
            TAR_FIXTURE=str(self.legacy),
        )
        return subprocess.run(
            ["sh", "-c", script],
            cwd=self.work,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_default_uses_verified_central_archive(self):
        result = self.fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "sha256 verified:",
            result.stdout,
            "default must verify the central archive checksum",
        )
        self.assertTrue(result.stdout.rstrip().endswith("central"))
        self.assertIn(
            "archive/refs/tags/v9.8.7.zip", (self.work / "fetch.log").read_text()
        )

    def test_explicit_override_keeps_tarball_route(self):
        result = self.fetch("custom-ref")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.rstrip().endswith("override"))
        self.assertEqual(
            (self.work / "fetch.log").read_text().strip(),
            "https://github.com/corazawaf/libcoraza/tarball/custom-ref",
        )

    def test_explicit_empty_override_is_not_replaced_by_pin(self):
        result = self.fetch("")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("archive/refs/tags", (self.work / "fetch.log").read_text())

    def test_mismatched_checksum_fails_before_extracting(self):
        self.write_pin("0" * 64)
        result = self.fetch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sha256 MISMATCH", result.stderr)
        self.assertFalse(list((self.work / "libcoraza-build").glob("*/marker")))

    def test_missing_pin_fails(self):
        (self.ci / "versions.env").unlink()
        result = self.fetch()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / "fetch.log").exists())

    def test_malformed_verified_archive_fails(self):
        self.archive.write_bytes(b"not a zip archive")
        self.write_pin(hashlib.sha256(self.archive.read_bytes()).hexdigest())
        result = self.fetch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sha256 verified:", result.stdout)


if __name__ == "__main__":
    unittest.main()
