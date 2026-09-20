#!/usr/bin/env python3
import json
import runpy
import sys
import types
from pathlib import Path

binary = Path(sys.argv[1]).resolve()
ota = Path(sys.argv[2]).resolve()

scripts = types.ModuleType("scripts")
scripts.__path__ = []
cyrus = types.ModuleType("scripts.cyrus")
layout = types.SimpleNamespace(
    ota_work_dir=Path("/tmp/ota-work"),
    ota_inputimg_dir=Path("/tmp/input-img"),
)
cyrus.V = types.SimpleNamespace(layout=layout)
cyrus.BIN_PATH = str(binary.parent)
sys.modules["scripts"] = scripts
sys.modules["scripts.cyrus"] = cyrus

ns = runpy.run_path("remote-tests/mkbin.py", run_name="mkbin_remote_test")
parts = ns["_get_ota_parts"](ota)
if not parts:
    raise SystemExit("mkbin _get_ota_parts returned no OTA partitions")

cmd, output = ns["_build_patch_cmd"](
    ota,
    Path("/tmp/keys"),
    [("boot", "boot.img")],
    [("new_logical", "new_logical.img", "8192")],
    ["new_logical"],
    disable_avb=True,
)

report = {
    "ota_partitions": parts,
    "output_name": output,
    "command": cmd,
    "uses_unsupported_super_mode": "--super-mode" in cmd,
    "uses_dynamic_partition": "--dynamic-partition" in cmd,
}
print(json.dumps(report, indent=2))
if report["uses_unsupported_super_mode"] or not report["uses_dynamic_partition"]:
    raise SystemExit("mkbin command does not use --dynamic-partition")
