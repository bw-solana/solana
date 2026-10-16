#!/usr/bin/env python3
"""Launch only the genuine modified agave-validator against isolated ledgers.

The manifest is produced by agave-pq-tool. Remote operations are limited to the
hosts explicitly authorized by the operator. Existing validators remain running.
Owned process command lines are checked before shutdown; Ax state is retained.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import time
import urllib.request

AUTHORIZED = {f"213.239.141.{n}" for n in (43, 44, 45, 46, 47, 48, 49, 32, 51, 31)}


def rpc(url, method, params=None):
    request = urllib.request.Request(url, data=json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params or []
    }).encode(), headers={"Content-Type": "application/json"})
    value = json.loads(urllib.request.urlopen(request, timeout=5).read())
    if "error" in value:
        raise RuntimeError(value["error"])
    return value["result"]


def ssh(host, command, key, stdin=None):
    return subprocess.run(["ssh", "-i", str(key), "-o", "BatchMode=yes", "-o",
        "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
        f"sol@{host}", command], input=stdin, text=True, capture_output=True,
        timeout=180, check=True).stdout


def run_python(node, source, args):
    if args.remote:
        return ssh(node["host"], "python3 -", args.key, source)
    return subprocess.run(["python3", "-"], input=source, text=True,
        capture_output=True, check=True).stdout


def node_directory(node):
    return str(Path(node["config"]).parent)


def command(node, binary, rayon_global_threads=8):
    if not isinstance(rayon_global_threads, int) or not 1 <= rayon_global_threads <= 128:
        raise ValueError("rayon-global-threads must be between 1 and 128")
    directory = Path(node_directory(node))
    dynamic_start = 26000 + node["index"] * 200
    # The ordinary identity is an address identifier. The PQ mode never starts
    # the classical voter, gossip, repair, TPU or TVU authority services.
    return [str(binary), "--identity", node["identity"], "--ledger", str(directory / "ledger"),
        "--experimental-pq-config", node["config"], "--rpc-port", str(node["rpc_port"]),
        "--rpc-bind-address", "0.0.0.0", "--private-rpc", "--full-rpc-api",
        "--enable-rpc-transaction-history",
        "--gossip-port", str(25000 + node["index"]),
        "--dynamic-port-range", f"{dynamic_start}-{dynamic_start + 199}",
        "--no-voting", "--no-xdp", "--do-not-require-vote-history", "--no-poh-speed-test",
        "--no-port-check", "--no-genesis-fetch", "--no-snapshot-fetch", "--no-snapshots",
        "--no-wait-for-vote-to-start-leader", "--allow-private-addr",
        "--no-os-network-limits-test", "--rpc-threads", "4", "--rpc-blocking-threads", "4",
        "--rayon-global-threads", str(rayon_global_threads), "--log", str(directory / "validator.log")]


def launch(node, binary, args):
    directory = node_directory(node)
    source = f'''import json,os,subprocess
from pathlib import Path
directory=Path({directory!r})
pidfile=directory/'owned-validator.pid'
if pidfile.exists():
 pid=int(pidfile.read_text())
 proc=Path('/proc')/str(pid)
 if proc.exists() and (proc/'stat').read_text().split()[2]!='Z': raise RuntimeError('owned validator is already running')
argv={command(node, binary, args.rayon_global_threads)!r}
with open(directory/'console.log','ab',buffering=0) as log:
 process=subprocess.Popen(argv,stdout=log,stderr=log,start_new_session=True,
  env=dict(os.environ,RUST_LOG='warn,solana_core::experimental_pq=info'))
pidfile.write_text(str(process.pid))
print(json.dumps({{'pid':process.pid,'argv':argv}}))
'''
    return json.loads(run_python(node, source, args))


def stop(node, args):
    directory = node_directory(node)
    source = f'''import json,os,signal,time
from pathlib import Path
directory=Path({directory!r});pidfile=directory/'owned-validator.pid'
if not pidfile.exists(): print(json.dumps({{'running':False}}));raise SystemExit
pid=int(pidfile.read_text());proc=Path('/proc')/str(pid)
if proc.exists() and (proc/'stat').read_text().split()[2]!='Z':
 cmd=(proc/'cmdline').read_bytes().split(b'\\0')
 if str(directory/'ledger').encode() not in cmd or b'--experimental-pq-config' not in cmd:
  raise RuntimeError('refusing to signal a process outside the isolated PQ ledger')
 os.kill(pid,signal.SIGTERM)
 for attempt in range(200):
  if not proc.exists() or (proc/'stat').read_text().split()[2]=='Z': break
  time.sleep(.1)
 else: raise RuntimeError('owned validator did not shut down; no forced termination')
pidfile.unlink()
print(json.dumps({{'stopped':True,'pid':pid}}))
'''
    return json.loads(run_python(node, source, args))


def status(node, args):
    if not args.remote:
        return rpc(node["rpc_url"], "getExperimentalPqStatus")
    source = f'''import json,urllib.request
url='http://127.0.0.1:'+str({node['rpc_port']!r})
request=urllib.request.Request(url,data=json.dumps({{'jsonrpc':'2.0','id':1,'method':'getExperimentalPqStatus'}}).encode(),headers={{'Content-Type':'application/json'}})
print(urllib.request.urlopen(request,timeout=5).read().decode())
'''
    value = json.loads(run_python(node, source, args))
    if "error" in value:
        raise RuntimeError(value["error"])
    return value["result"]


def deploy(node, binary, tool, args):
    host = node["host"]
    if host not in AUTHORIZED:
        raise RuntimeError(f"host {host} was not authorized")
    directory = Path(node_directory(node))
    destination = Path(args.manifest).resolve().parent / "bin"
    ssh(host, f"mkdir -p {shlex.quote(str(directory.parent))} {shlex.quote(str(destination))}", args.key)
    transport = f"ssh -i {shlex.quote(str(args.key))} -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
    # A repeat deployment must never overwrite a used signer, monotonic store,
    # release journal or ledger with its original local initialization image.
    subprocess.run(["rsync", "-a", "--ignore-existing", "--chmod=D700,F600", "-e", transport,
        str(directory), f"sol@{host}:{directory.parent}/"], check=True, capture_output=True)
    subprocess.run(["rsync", "-a", "--chmod=F700", "-e", transport,
        str(binary), str(tool), f"sol@{host}:{destination}/"], check=True, capture_output=True)
    digest = ssh(host, f"sha384sum {shlex.quote(str(destination / binary.name))}", args.key).split()[0]
    expected = hashlib.sha384(binary.read_bytes()).hexdigest()
    if digest != expected:
        raise RuntimeError("deployed validator hash differs from the built binary")
    return {"host": host, "validator_sha384": digest, "binary": str(destination / binary.name)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["launch", "stop", "status", "deploy", "wait"])
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=Path("target/release/agave-validator"))
    parser.add_argument("--tool", type=Path, default=Path("target/release/agave-pq-tool"))
    parser.add_argument("--key", type=Path, default=Path.home()/"google_compute_engine")
    parser.add_argument("--remote", action="store_true")
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--rayon-global-threads", type=int, default=8,
        help="explicit bounded validator worker count (1..128, default 8)")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.rayon_global_threads <= 128:
        parser.error("--rayon-global-threads must be between 1 and 128")
    document = json.loads(args.manifest.read_text())
    nodes = document["nodes"]
    for index, node in enumerate(nodes):
        node.setdefault("index", index)
    binary = args.binary.resolve()
    tool = args.tool.resolve()
    if args.remote and any(node["host"] not in AUTHORIZED for node in nodes):
        raise RuntimeError("manifest includes an unauthorized host")
    if args.action == "wait":
        deadline = time.monotonic() + args.timeout
        healthy_samples = 0
        while True:
            def readiness(node):
                try:
                    return status(node, args)
                except Exception as error:
                    return {"unavailable": str(error)}
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(nodes)) as pool:
                values = list(pool.map(readiness, nodes))
            healthy_samples = healthy_samples + 1 if all(
                v.get("experimental_pq") and "fatal_error" not in v for v in values
            ) else 0
            if healthy_samples >= 3:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(json.dumps(values))
            time.sleep(1)
    else:
        def action(node):
            if args.action == "deploy":
                return deploy(node, binary, tool, args)
            if args.action == "stop":
                return stop(node, args)
            if args.action == "status":
                try:
                    return status(node, args)
                except Exception as error:
                    return {"host": node["host"], "unavailable": str(error)}
            selected = Path(args.manifest).resolve().parent / "bin" / binary.name if args.remote else binary
            return launch(node, selected, args)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(nodes)) as pool:
            values = list(pool.map(action, nodes))
    output = {"actual_agave_validator": True, "action": args.action, "wall_ms": int(time.time()*1000),
        "requested_rayon_global_threads":args.rayon_global_threads,
        "nodes": values}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output, indent=2)+"\n")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
