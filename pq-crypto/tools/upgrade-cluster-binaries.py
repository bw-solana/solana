#!/usr/bin/env python3
"""Upgrade only frozen executables after all owned native validators stop.

No node directory, config, identity, key, monotonic store, ledger or WAL is
uploaded. Old binaries and an exact preflight plan are retained privately.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("stage", Path(__file__).with_name("stage-cluster.py"))
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)
cluster = stage.cluster


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--frozen-release", type=Path, required=True)
    parser.add_argument("--validator-sha384", required=True)
    parser.add_argument("--tool-sha384", help="replace the installed tool only when its frozen digest is explicitly supplied")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--key", type=Path, default=Path.home()/"google_compute_engine")
    args = parser.parse_args()
    stage.require(args.output.is_absolute() and not args.output.exists()
        and not args.output.resolve().is_relative_to(Path(__file__).resolve().parents[2]), "fresh private output outside repository required")
    base = args.manifest.resolve().parent
    document = json.loads(args.manifest.read_text())
    nodes = document["nodes"]
    stage.require(len(nodes) == 8 and len({node["host"] for node in nodes}) == 8
        and all(node["host"] in cluster.AUTHORIZED for node in nodes), "exact eight authorized validators required")
    expected = {"agave-validator": args.validator_sha384}
    if args.tool_sha384 is not None:
        expected["agave-pq-tool"] = args.tool_sha384
    for name, sha384 in expected.items():
        stage.require(re.fullmatch("[0-9a-f]{96}", sha384) is not None, "explicit frozen executable digest required")
        stage.require(stage.file_digest(args.frozen_release/"bin"/name) == sha384, "frozen executable digest mismatch")
    local_configs = []
    for index, node in enumerate(nodes):
        path = Path(node["config"])
        stage.require(not path.is_symlink() and path.resolve().parent == base/f"node-{index}", "exact owned config path required")
        local_configs.append(stage.file_digest(path))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        stopped = list(pool.map(lambda node: stage.remote_state(node, args.key, False), nodes))
    stage.require(all(row["config_sha384"] == local_configs[index] for index, row in enumerate(stopped)), "remote configuration changed from local bytes")
    history = base/"binary-history"/str(time.time_ns())
    history.mkdir(mode=0o700, parents=True)
    previous = {}
    for name in expected:
        stage.require(not (base/"bin"/name).is_symlink(), "local executable symlink refused")
        previous[name] = stage.file_digest(base/"bin"/name)
        shutil.copyfile(base/"bin"/name, history/name)
        (history/name).chmod(0o700)
    output = {"format": "agave-pq-binary-only-upgrade-v1", "started_unix_ms": time.time_ns()//1000000,
        "all_owned_validators_stopped": True, "previous_binary_sha384": previous,
        "next_binary_sha384": expected, "node_config_sha384": local_configs,
        "keys_ledgers_wal_configs_not_uploaded": True, "source_sha384": stage.file_digest(Path(__file__)), "complete": False}
    stage.private_write(args.output, output)
    transport = f"ssh -i {shlex.quote(str(args.key))} -o BatchMode=yes"
    def upgrade(node):
        # Stage only the explicitly selected executables under unique names. Atomic replacement
        # repeats the stopped-process/config check after the upload.
        files = {}
        for name, sha384 in expected.items():
            temporary = base/"bin"/f".{name}.upgrade-{sha384[:24]}.tmp"
            subprocess.run(["rsync", "-a", "--chmod=F700", "-e", transport,
                str(args.frozen_release/"bin"/name), f"sol@{node['host']}:{temporary}"],
                check=True, capture_output=True)
            files[name] = str(temporary)
        source = f'''import hashlib,json,os
from pathlib import Path
base=Path({str(base)!r});config=Path({node['config']!r})
if hashlib.sha384(config.read_bytes()).hexdigest()!={local_configs[node['index']]!r}: raise RuntimeError('configuration changed during binary upload')
for proc in Path('/proc').iterdir():
 if not proc.name.isdigit(): continue
 try:
  cmd=(proc/'cmdline').read_bytes().split(b'\\0')
  if b'--experimental-pq-config' in cmd and str(config).encode() in cmd and (proc/'stat').read_text().split()[2]!='Z': raise RuntimeError('owned validator restarted before upgrade')
 except (OSError,PermissionError): pass
expected={expected!r};previous={previous!r};files={files!r}
def sha(path):
 h=hashlib.sha384()
 with path.open('rb') as stream:
  for chunk in iter(lambda:stream.read(1048576),b''): h.update(chunk)
 return h.hexdigest()
for name in expected:
 destination=base/'bin'/name
 if destination.is_symlink() or sha(destination)!=previous[name]: raise RuntimeError('installed executable changed from expected old binary')
 if sha(Path(files[name]))!=expected[name]: raise RuntimeError('staged executable digest mismatch')
for name in expected: Path(files[name]).replace(base/'bin'/name)
directory=os.open(base/'bin',os.O_RDONLY|os.O_DIRECTORY)
try: os.fsync(directory)
finally: os.close(directory)
print(json.dumps({{'host':{node['host']!r},'binary_sha384':{{name:sha(base/'bin'/name) for name in expected}}}}))
'''
        return json.loads(cluster.ssh(node["host"], "python3 -", args.key, source))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        upgraded = list(pool.map(upgrade, nodes))
    stage.require(all(row["binary_sha384"] == expected for row in upgraded), "partial remote binary upgrade; retained preflight plan identifies all binaries")
    for name in expected:
        temporary = base/"bin"/f".{name}.upgrade-local.tmp"
        shutil.copyfile(args.frozen_release/"bin"/name, temporary)
        temporary.chmod(0o700)
        temporary.replace(base/"bin"/name)
    output.update(complete=True, completed_unix_ms=time.time_ns()//1000000, nodes=upgraded)
    stage.private_write(args.output, output)
    print(json.dumps({"validators": 8, "complete": True, "executables_replaced": list(expected), "keys_ledgers_wal_configs_preserved": True}))


if __name__ == "__main__":
    main()
