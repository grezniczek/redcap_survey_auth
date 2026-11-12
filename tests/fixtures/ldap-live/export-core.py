#!/usr/bin/env python3
"""Export licensed local REDCap tags to temporary fixtures, never into this repository."""
import pathlib
import re
import subprocess
import sys
import tempfile

repository = pathlib.Path(sys.argv[1]).resolve()
versions = sys.argv[2:] or ["16.0.0", "17.5.6"]
destination = pathlib.Path(tempfile.mkdtemp(prefix="surveyauth-core-ldap-"))
files = ["Libraries/PEAR/Auth.php", "Libraries/PEAR/Auth/Container.php",
         "Libraries/PEAR/Auth/Container/LDAP.php", "Libraries/PEAR/PEAR.php"]
for version in versions:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Expected numeric REDCap version tag")
    for source in files:
        target = destination / version / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(subprocess.check_output(
            ["git", "show", f"{version}:{source}"], cwd=repository))
    functions = subprocess.check_output(
        ["git", "show", f"{version}:Config/init_functions.php"], cwd=repository, text=True)
    helpers = []
    for name in ["utf8_encode_rc", "isinteger"]:
        match = re.search(r"^function " + name + r"\([^\n]*\)\s*\n\{.*?^\}", functions, re.M | re.S)
        if match is None:
            raise ValueError(f"Missing core helper {name} in {version}")
        helpers.append(match.group())
    (destination / version / "helpers.php").write_text("<?php\n" + "\n".join(helpers) + "\n")
print(destination)
