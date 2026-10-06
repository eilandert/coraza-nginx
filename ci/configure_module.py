"""Replay the target nginx build options without invoking a shell parser."""

import shlex
import subprocess
import sys


def parse_configure_arguments(version_output):
    prefix = "configure arguments: "
    lines = [line[len(prefix):] for line in version_output.splitlines()
             if line.startswith(prefix)]
    if len(lines) != 1 or not lines[0]:
        raise ValueError("expected exactly one nonempty nginx configure arguments line")
    try:
        arguments = shlex.split(lines[0], posix=True)
    except ValueError as error:
        raise ValueError("malformed nginx configure arguments") from error
    if not arguments or any(not arg.startswith("--") for arg in arguments):
        raise ValueError("nginx configure arguments contain an invalid option")
    return arguments


def main(configure, module_path, nginx="nginx"):
    version = subprocess.run([nginx, "-V"], capture_output=True, text=True,
                             check=True)
    arguments = parse_configure_arguments(version.stdout + version.stderr)
    subprocess.run([configure, *arguments, "--with-compat",
                    "--add-dynamic-module=" + module_path], check=True)


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        raise SystemExit("usage: configure_module.py CONFIGURE MODULE_PATH [NGINX]")
    main(*sys.argv[1:])
