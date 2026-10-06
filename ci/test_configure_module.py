"""Checks for replaying the target nginx configure arguments."""

import os
import pathlib
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from ci import configure_module as module

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "ci" / "configure_module.py"


class ConfigureModuleTests(unittest.TestCase):
    def test_dockerfile_replays_arguments_as_argv(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn("python3 /tmp/ci/configure_module.py", dockerfile)
        self.assertNotIn('"$CONFARGS"', dockerfile)

    def test_multiple_options_and_quoted_compiler_linker_values(self):
        output = (
            "nginx version: nginx/1.28.0\n"
            "configure arguments: --prefix=/etc/nginx "
            "--with-cc-opt='-O2 -DNAME=\"two words\"' "
            "--with-ld-opt='-Wl,-z,relro -Wl,-z,now' --with-http_ssl_module\n"
        )
        self.assertEqual(
            module.parse_configure_arguments(output),
            [
                "--prefix=/etc/nginx",
                '--with-cc-opt=-O2 -DNAME="two words"',
                "--with-ld-opt=-Wl,-z,relro -Wl,-z,now",
                "--with-http_ssl_module",
            ],
        )

    def test_missing_duplicate_and_malformed_arguments_fail(self):
        for output in (
            "nginx version: nginx/1.28.0\n",
            "configure arguments: --with-debug\nconfigure arguments: --with-compat\n",
            "configure arguments: --with-cc-opt='unterminated\n",
            "configure arguments: \n",
            "configure arguments: --with-debug stray\n",
        ):
            with self.subTest(output=output), self.assertRaises(ValueError):
                module.parse_configure_arguments(output)

    def test_runner_preserves_argv_and_rejects_nginx_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            nginx = root / "nginx"
            configure = root / "configure"
            output = root / "argv"
            nginx.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"configure arguments: --prefix=/etc/nginx "
                "--with-cc-opt='-O2 -DSPACE=hello world' "
                "--with-ld-opt='-Wl,-z,relro -Wl,-z,now'\" >&2\n"
            )
            configure.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > \"$ARGV_OUTPUT\"\n"
            )
            nginx.chmod(0o755)
            configure.chmod(0o755)
            env = dict(os.environ, ARGV_OUTPUT=str(output))
            with mock.patch.dict(os.environ, env):
                module.main(str(configure), "/module", str(nginx))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(configure), "/module", str(nginx)],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_text().splitlines(), [
                "--prefix=/etc/nginx",
                "--with-cc-opt=-O2 -DSPACE=hello world",
                "--with-ld-opt=-Wl,-z,relro -Wl,-z,now",
                "--with-compat",
                "--add-dynamic-module=/module",
            ])
            nginx.write_text("#!/bin/sh\nexit 7\n")
            with self.assertRaises(subprocess.CalledProcessError):
                module.main(str(configure), "/module", str(nginx))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(configure), "/module", str(nginx)],
                env=env, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_cli_usage_and_success(self):
        with mock.patch.object(sys, "argv", [str(SCRIPT)]), self.assertRaises(SystemExit):
            runpy.run_path(str(SCRIPT), run_name="__main__")
        with (
            mock.patch.object(sys, "argv", [str(SCRIPT), "/configure", "/module"]),
            mock.patch("subprocess.run") as run,
        ):
            run.return_value.stdout = "configure arguments: --with-debug\n"
            run.return_value.stderr = ""
            runpy.run_path(str(SCRIPT), run_name="__main__")
            self.assertEqual(run.call_args.args[0], [
                "/configure", "--with-debug", "--with-compat",
                "--add-dynamic-module=/module",
            ])


if __name__ == "__main__":
    unittest.main()
