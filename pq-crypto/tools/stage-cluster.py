#!/usr/bin/env python3
"""Pin live native experiment parameters or update only stopped local knobs.

Capture checks the installed and running executable against the private frozen
binary, and checks actual RPC parameters against exact local/remote config
bytes. Tune requires every owned validator to be stopped before changing only
execution_threads/proposal caps; all used signer/ledger/WAL files are preserved.
Outputs stay private. No configuration or credential contents are printed.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("cluster", Path(__file__).with_name("agave-cluster.py"))
cluster = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cluster)
LOCAL_KNOBS = {"execution_threads", "proposal_target_block_bytes", "proposal_max_transactions"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha384(data).hexdigest()


def file_digest(path):
    hasher = hashlib.sha384()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def private_write(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x") as stream:
        temporary.chmod(0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")
    temporary.replace(path)


def parameters(config):
    return {"execution_threads": config.get("execution_threads", 8),
        "proposal_target_block_bytes": config.get("proposal_target_block_bytes") or config["target_block_bytes"],
        "proposal_max_transactions": config.get("proposal_max_transactions") or config["max_transactions"],
        "validation_max_block_bytes": config["target_block_bytes"],
        "validation_max_transactions": config["max_transactions"],
        "block_time_ms": config["block_time_ms"], "network_delay_ms": config["network_delay_ms"],
        "epoch_slots": config["slot_count"]}


def tuned(config, updates):
    require(updates and set(updates) <= LOCAL_KNOBS, "only explicit local performance knobs may change")
    value = dict(config, **updates)
    require(type(value["execution_threads"]) is int and 1 <= value["execution_threads"] <= 32, "execution worker bounds")
    for name, lower, upper in [("proposal_target_block_bytes", 64, config["target_block_bytes"]),
            ("proposal_max_transactions", 1, config["max_transactions"])]:
        cap = value.get(name)
        require(cap is None or type(cap) is int and lower <= cap <= upper, "proposal cap exceeds immutable validation bounds")
    require({k: v for k, v in config.items() if k not in LOCAL_KNOBS}
        == {k: v for k, v in value.items() if k not in LOCAL_KNOBS}, "immutable configuration changed")
    return value


def remote_state(node, key, running):
    config_path = str(Path(node["config"]))
    directory = str(Path(config_path).parent)
    source = f'''import hashlib,json
from pathlib import Path
cfg=Path({config_path!r});directory=Path({directory!r})
raw=cfg.read_bytes(); matches=[]
for proc in Path('/proc').iterdir():
 if not proc.name.isdigit(): continue
 try:
  cmd=(proc/'cmdline').read_bytes().split(b'\\0')
  if b'--experimental-pq-config' in cmd and str(cfg).encode() in cmd and (proc/'stat').read_text().split()[2]!='Z': matches.append((proc,cmd))
 except (OSError,PermissionError): pass
out={{'config_sha384':hashlib.sha384(raw).hexdigest(),'matching_processes':len(matches)}}
if {running!r}:
 if len(matches)!=1: raise RuntimeError('exactly one owned validator required')
 proc,cmd=matches[0];pid=int((directory/'owned-validator.pid').read_text())
 if pid!=int(proc.name) or str(directory/'ledger').encode() not in cmd: raise RuntimeError('owned validator PID/ledger mismatch')
 hasher=hashlib.sha384()
 with (proc/'exe').open('rb') as binary:
  for chunk in iter(lambda:binary.read(1048576),b''): hasher.update(chunk)
 i=cmd.index(b'--rayon-global-threads')
 out.update(pid=pid,start_jiffies=int((proc/'stat').read_text().split()[21]),executable_sha384=hasher.hexdigest(),rayon_global_threads=int(cmd[i+1]),argv_sha384=hashlib.sha384((proc/'cmdline').read_bytes()).hexdigest())
elif matches: raise RuntimeError('all validators must be stopped before config-only tuning')
print(json.dumps(out))
'''
    return json.loads(cluster.ssh(node["host"], "python3 -", key, source))


def remote_update(node, key, previous, raw):
    source = f'''import hashlib,os
from pathlib import Path
cfg=Path({str(Path(node['config']))!r})
if hashlib.sha384(cfg.read_bytes()).hexdigest()!={previous!r}: raise RuntimeError('config changed after stopped-state preflight')
for proc in Path('/proc').iterdir():
 if not proc.name.isdigit(): continue
 try:
  cmd=(proc/'cmdline').read_bytes().split(b'\\0')
  if b'--experimental-pq-config' in cmd and str(cfg).encode() in cmd and (proc/'stat').read_text().split()[2]!='Z': raise RuntimeError('validator restarted before configuration update')
 except (OSError,PermissionError): pass
tmp=cfg.with_suffix('.stage-update.tmp')
with tmp.open('xb') as f:
 os.chmod(tmp,0o600);f.write({raw!r});f.flush();os.fsync(f.fileno())
tmp.replace(cfg)
parent=os.open(cfg.parent,os.O_RDONLY|os.O_DIRECTORY)
try: os.fsync(parent)
finally: os.close(parent)
print(hashlib.sha384(cfg.read_bytes()).hexdigest())
'''
    return cluster.ssh(node["host"], "python3 -", key, source).strip()


def preserves_operating_point(before, after):
    """Compare actual captured processes and immutable parameters across a run."""
    if len(before.get("nodes", [])) != 8 or len(after.get("nodes", [])) != 8:
        return False
    if not before.get("validator_binary_sha384") or any(before.get(field) != after.get(field)
            for field in ("genesis_hash", "source_sha384", "validator_binary_sha384")):
        return False
    fields = ("node", "host", "config_sha384", "executable_sha384", "argv_sha384",
        "rayon_global_threads", "parameters", "pid", "start_jiffies")
    for index, (left, right) in enumerate(zip(before["nodes"], after["nodes"])):
        if left.get("node") != index or right.get("node") != index \
                or any(left.get(field) is None or left.get(field) != right.get(field) for field in fields):
            return False
    return True


def self_test():
    config = {"execution_threads": 8, "target_block_bytes": 8388608, "max_transactions": 8192,
        "proposal_target_block_bytes": 4194304, "proposal_max_transactions": 4096,
        "chain": "unchanged", "peers": [{"id": "unchanged"}]}
    changed = tuned(config, {"execution_threads": 32, "proposal_target_block_bytes": 8388608, "proposal_max_transactions": 8192})
    assert changed["chain"] == config["chain"] and changed["peers"] == config["peers"]
    assert config["execution_threads"] == 8
    for update in ({"chain": "other"}, {"execution_threads": 0}, {"execution_threads": 33},
            {"execution_threads": True}, {"proposal_target_block_bytes": 8388609}, {"proposal_max_transactions": 8193}):
        try:
            tuned(config, update)
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe tuning accepted")
    # Execute the exact remote Python against a local isolated directory. This
    # exercises config-only fsync/replace and a real /proc restart race without
    # contacting a machine or reading any real signer state.
    original_ssh = cluster.ssh
    def local_python(_host, command, _key, source):
        assert command == "python3 -"
        return subprocess.run([sys.executable, "-"], input=source, text=True,
            capture_output=True, check=True, timeout=10).stdout
    cluster.ssh = local_python
    try:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory/"pq-config.json"
            original = json.dumps(config).encode()
            path.write_bytes(original)
            sentinel = directory/"used-signer-history"
            sentinel.write_bytes(b"this must survive tuning")
            node = {"host": "unused-local-test", "config": str(path)}
            assert remote_state(node, Path("unused"), False)["matching_processes"] == 0
            replacement = json.dumps(changed).encode()
            assert remote_update(node, Path("unused"), digest(original), replacement) == digest(replacement)
            assert path.read_bytes() == replacement and sentinel.read_bytes() == b"this must survive tuning"
            try:
                remote_update(node, Path("unused"), digest(original), original)
            except subprocess.CalledProcessError:
                pass
            else:
                raise AssertionError("stale preflight hash accepted")
            child = subprocess.Popen([sys.executable, "-c",
                "import sys; print('ready',flush=True); sys.stdin.read()",
                "--experimental-pq-config", str(path)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
            try:
                assert child.stdout.readline().strip() == b"ready"
                for operation in (lambda: remote_state(node, Path("unused"), False),
                        lambda: remote_update(node, Path("unused"), digest(replacement), original)):
                    try:
                        operation()
                    except subprocess.CalledProcessError:
                        pass
                    else:
                        raise AssertionError("active validator configuration changed")
                assert path.read_bytes() == replacement and sentinel.read_bytes() == b"this must survive tuning"
            finally:
                child.stdin.close()
                child.wait(timeout=5)
    finally:
        cluster.ssh = original_ssh
    print("PASS: immutable settings/bounds, exact config-only atomic update, preserved used history, stale hash and real /proc restart-race refusal")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "tune", "self-test"))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--key", type=Path, default=Path.home()/"google_compute_engine")
    parser.add_argument("--execution-threads", type=int)
    parser.add_argument("--proposal-target-block-bytes", type=int)
    parser.add_argument("--proposal-max-transactions", type=int)
    args = parser.parse_args()
    if args.action == "self-test":
        self_test()
        return
    require(args.manifest is not None and args.output is not None, "manifest and fresh private output required")
    require(args.output.is_absolute() and not args.output.exists()
        and not args.output.resolve().is_relative_to(Path(__file__).resolve().parents[2]), "fresh private output outside repository required")
    directory = args.manifest.resolve().parent
    document = json.loads(args.manifest.read_text())
    nodes = document["nodes"]
    require(len(nodes) == 8 and len({node["host"] for node in nodes}) == 8
        and all(node["host"] in cluster.AUTHORIZED for node in nodes), "exact eight authorized validators required")
    configurations = []
    for index, node in enumerate(nodes):
        path = Path(node["config"])
        require(not path.is_symlink() and path.resolve().parent == directory/f"node-{index}", "node config must remain inside its exact private node directory")
        raw = path.read_bytes()
        configurations.append((raw, json.loads(raw)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        observed = list(pool.map(lambda node: remote_state(node, args.key, args.action == "capture"), nodes))
    require(all(row["config_sha384"] == digest(configurations[index][0]) for index, row in enumerate(observed)), "remote config differs from pinned local bytes")
    output = {"format": "agave-pq-native-stage-parameters-v1", "action": args.action,
        "captured_unix_ms": time.time_ns()//1000000, "genesis_hash": document["genesis_hash"],
        "source_sha384": file_digest(Path(__file__)), "nodes": []}
    if args.action == "capture":
        expected = file_digest(directory/"bin/agave-validator")
        require(all(row["executable_sha384"] == expected for row in observed), "running validator executable differs from frozen binary")
        for index, node in enumerate(nodes):
            status = cluster.rpc(node["rpc_url"], "getExperimentalPqStatus")
            config_parameters = parameters(configurations[index][1])
            require(status.get("experimental_pq") is True and not status.get("fatal_error"), "native validator unavailable or fatal")
            require(all(status.get(name) == value for name, value in config_parameters.items()
                if name not in ("block_time_ms", "network_delay_ms")), "live RPC settings differ from exact configuration")
            output["nodes"].append({"node": index, "host": node["host"], **observed[index],
                "parameters": config_parameters, "native_status": status})
        output["validator_binary_sha384"] = expected
        private_write(args.output, output)
    else:
        updates = {name: value for name, value in vars(args).items() if name in LOCAL_KNOBS and value is not None}
        replacements = [json.dumps(tuned(config, updates), indent=2).encode()+b"\n" for _, config in configurations]
        for index, node in enumerate(nodes):
            output["nodes"].append({"node": index, "host": node["host"],
                "previous_config_sha384": digest(configurations[index][0]), "next_config_sha384": digest(replacements[index]),
                "previous_parameters": parameters(configurations[index][1]), "next_parameters": parameters(json.loads(replacements[index])),
                "previous_configuration": configurations[index][1]})
        output.update(all_validators_stopped=True, allowed_local_updates=updates, complete=False)
        private_write(args.output, output)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            updated = list(pool.map(lambda pair: remote_update(pair[1], args.key, digest(configurations[pair[0]][0]), replacements[pair[0]]), enumerate(nodes)))
        require(all(value == digest(replacements[index]) for index, value in enumerate(updated)), "remote config-only update incomplete; retained plan describes every old/new hash")
        for index, node in enumerate(nodes):
            path = Path(node["config"])
            temporary = path.with_suffix(".stage-update.tmp")
            with temporary.open("xb") as stream:
                temporary.chmod(0o600)
                stream.write(replacements[index])
            temporary.replace(path)
        output.update(complete=True, all_remote_configuration_hashes_match=True)
        private_write(args.output, output)
    print(json.dumps({"action": args.action, "validators": len(nodes), "complete": output.get("complete", True), "private_output_written": True}))


if __name__ == "__main__":
    main()
