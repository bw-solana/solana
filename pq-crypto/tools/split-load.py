#!/usr/bin/env python3
"""Exercise native Agave with two remote generators and an owned-node crash.

Deploy fresh validator state and the two generator requests before calling this
script. It never resets signer state or signals an unrelated validator.
"""
import argparse
import atexit
import concurrent.futures
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time

sys.dont_write_bytecode = True
module = importlib.util.spec_from_file_location("cluster", Path(__file__).with_name("agave-cluster.py"))
cluster = importlib.util.module_from_spec(module)
module.loader.exec_module(cluster)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source-host", action="append", required=True)
    parser.add_argument("--source-request", type=Path, action="append", required=True)
    parser.add_argument("--key", type=Path, default=Path.home()/"google_compute_engine")
    parser.add_argument("--load-only", action="store_true", help="Run the load measurement without crash injection")
    parser.add_argument("--resources-duration", type=float, default=60)
    args = parser.parse_args()
    assert len(args.source_host) == len(args.source_request) == 2
    assert len(set(args.source_host)) == len({path.name for path in args.source_request}) == 2
    assert all(host in cluster.AUTHORIZED for host in args.source_host)
    manifest = json.loads(args.manifest.read_text())
    nodes = manifest["nodes"]
    assert all(node["host"] in cluster.AUTHORIZED for node in nodes)
    assert not set(args.source_host).intersection(node["host"] for node in nodes)
    directory = args.manifest.resolve().parent
    requests = [json.loads(path.read_text()) for path in args.source_request]
    assert all(Path(request["output"]).parent == directory for request in requests)
    assert requests[0].get("expected_recipient_balance") == requests[1].get("expected_recipient_balance")
    assert requests[0].get("expected_recipient_balances") == requests[1].get("expected_recipient_balances")
    helper = str(Path(__file__).with_name("agave-cluster.py"))

    def manage(action, selected=args.manifest, output=None):
        command = [sys.executable, helper, action, "--manifest", str(selected), "--remote", "--key", str(args.key), "--timeout", "75"]
        if output:
            command += ["--output", str(output)]
        with open(directory/(action+"-runner.log"), "a") as log:
            subprocess.run(command, stdout=log, stderr=log, check=True)

    manage("launch", output=directory/"launch.json")
    manage("wait", output=directory/"ready.json")
    def finish_sampling():
        pass

    if args.resources_duration > 0:
        samples = directory/"resources-load"
        sample_log = open(directory/"resources-load.log", "w")
        sampler = subprocess.Popen([sys.executable, str(Path(__file__).with_name("resources.py")),
            "--manifest", str(args.manifest), "--remote", "--key", str(args.key),
            "--duration", str(args.resources_duration), "--output", str(samples)],
            stdout=sample_log, stderr=sample_log)
        sample_log.close()
        # Keep the SSH samplers alive until their raw observations are saved,
        # including when a short load finishes before the requested interval.
        # Waiting at exit preserves the headroom needed for crash injection.
        def finish_sampling():
            code = sampler.wait(timeout=args.resources_duration+30)
            if code:
                raise RuntimeError(f"resource sampling failed: {code}; see resources-load.log")
        atexit.register(finish_sampling)
        deadline = time.monotonic()+30
        while not all((samples/f"node-{index}.ready").exists() for index in range(len(nodes))):
            assert time.monotonic() < deadline, "resource samplers failed to start before load"
            time.sleep(.1)
    while not cluster.rpc(nodes[0]["rpc_url"], "getExperimentalPqStatus")["started"]:
        time.sleep(.1)
    print("native validators ready; starting two dedicated generators", flush=True)

    def source(index):
        request = directory/args.source_request[index].name
        command = " ".join(shlex.quote(str(path)) for path in (
            directory/"bin/agave-pq-tool", "load", request))
        command = f"if [ -x /usr/bin/time ]; then exec /usr/bin/time -v {command}; else exec {command}; fi"
        with open(directory/f"source-{index}-stdout.log", "w") as log:
            result = subprocess.run(["ssh", "-i", str(args.key), "-o", "BatchMode=yes",
                f"sol@{args.source_host[index]}", command], stdout=log, stderr=log)
        completed_monotonic = time.monotonic()
        transport = f"ssh -i {shlex.quote(str(args.key))} -o BatchMode=yes"
        output = Path(requests[index]["output"])
        # Only public result and transaction-ID files are copied back.
        ids_path = output.with_suffix(".ids.json")
        paths = [output, ids_path] if result.returncode == 0 else [ids_path, ids_path.with_suffix(".failure.json")]
        copied = subprocess.run(["rsync", "-a", "--chmod=F600", "-e", transport,
            *[f"sol@{args.source_host[index]}:{path}" for path in paths], str(directory)+"/"], capture_output=True)
        if result.returncode == 0:
            assert copied.returncode == 0, "required generator result/ID artifact missing"
        return {"code": result.returncode, "completed_monotonic": completed_monotonic}

    started_monotonic = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        completed = list(pool.map(source, range(2)))
    codes = [item["code"] for item in completed]
    (directory/"source-exit-codes.json").write_text(json.dumps(codes)+"\n")
    assert codes == [0, 0], f"load generators failed: {codes}; see retained diagnostics"
    results = [json.loads(Path(request["output"]).read_text()) for request in requests]
    ids = [json.loads(Path(request["output"]).with_suffix(".ids.json").read_text()) for request in requests]
    assert len(set(ids[0]+ids[1])) == sum(map(len, ids)), "duplicate transaction IDs"
    generator_elapsed = (max(result["completed_unix_ms"] for result in results)
        - min(result["started_unix_ms"] for result in results))/1000
    elapsed = max(item["completed_monotonic"] for item in completed)-started_monotonic
    summary = {"actual_agave_validator": True, "validator_count": len(nodes),
        "generator_count": 2, "unique_finalized_transactions": sum(map(len, ids)),
        "joint_elapsed_seconds": elapsed, "joint_finalized_tps": sum(map(len, ids))/elapsed,
        "measurement": "controller monotonic SSH launch to last generator exit; artifact copies excluded",
        "generator_reported_wall_interval_seconds": generator_elapsed,
        "generator_reported_joint_tps": sum(map(len, ids))/generator_elapsed,
        "all_validator_balances_match": all(result["all_validator_balances_match"] for result in results)}
    (directory/"split-result.json").write_text(json.dumps(summary, indent=2)+"\n")
    print(json.dumps(summary), flush=True)
    if args.load_only:
        finish_sampling()
        atexit.unregister(finish_sampling)
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(nodes)) as pool:
        observed = list(pool.map(lambda peer: cluster.rpc(peer["rpc_url"], "getExperimentalPqStatus"), nodes))
    before = observed[0]
    config = json.loads(Path(nodes[0]["config"]).read_text())
    assert [peer["id"] for peer in config["peers"]] == [peer["id"] for peer in nodes], "leader order mismatch"
    window = config["window_size"]
    highest_marker = max(max(status["slot"], status["candidate_max_slot"]) for status in observed)
    next_window = (highest_marker-config["first_slot"])//window+2
    victim = next_window % len(nodes)
    missing_last_slot = config["first_slot"]+(next_window+1)*window-1
    assert missing_last_slot < config["first_slot"]+config["slot_count"]-window, "finite epoch lacks room for crash test"
    node = nodes[victim]
    node_dir = Path(node["config"]).parent
    missing_first_slot = missing_last_slot-window+1
    source_text = f'''import os,signal,json,urllib.request
from pathlib import Path
d=Path({str(node_dir)!r});pid=int((d/'owned-validator.pid').read_text())
c=(Path('/proc')/str(pid)/'cmdline').read_bytes().split(b'\\0')
assert str(d/'ledger').encode() in c and b'--experimental-pq-config' in c
r=urllib.request.Request('http://127.0.0.1:{node['rpc_port']}',data=b'{{"jsonrpc":"2.0","id":1,"method":"getExperimentalPqStatus"}}',headers={{'Content-Type':'application/json'}})
status=json.loads(urllib.request.urlopen(r,timeout=5).read())['result']
assert status['candidate_max_slot'] < {missing_first_slot}, 'target leader window already proposed'
os.kill(pid,signal.SIGKILL)
print(json.dumps({{'killed_owned_pid':pid,'before_crash_status':status}}))
'''
    killed = json.loads(cluster.ssh(node["host"], "python3 -", args.key, source_text))
    survivors = [peer for index, peer in enumerate(nodes) if index != victim]
    request = {"manifest": str(args.manifest.resolve()), "count": 100, "start_index": 10000,
        "wallet_index": 2, "rpc_urls": [peer["rpc_url"] for peer in survivors],
        "connections": 8, "signing_threads": 16, "batch_size": 16, "timeout_seconds": 75,
        "output": str(directory/"fault-load.json")}
    request_path = directory/"fault-load-request.json"
    request_path.write_text(json.dumps(request, indent=2)+"\n")
    with open(directory/"fault-load-stdout.log", "w") as log:
        subprocess.run(["target/release/agave-pq-tool", "load", str(request_path)],
            stdout=log, stderr=log, check=True)
    deadline = time.monotonic()+45
    while cluster.rpc(survivors[0]["rpc_url"], "getExperimentalPqStatus")["slot"] <= missing_last_slot:
        assert time.monotonic() < deadline, "no progress past missing scheduled leader"
        time.sleep(.1)
    after = cluster.rpc(survivors[0]["rpc_url"], "getExperimentalPqStatus")
    selected = dict(manifest, nodes=[node])
    selected_path = directory/"restart-selected.json"
    selected_path.write_text(json.dumps(selected, indent=2)+"\n")
    manage("launch", selected_path, directory/"restart.json")
    manage("wait", selected_path, directory/"restart-ready.json")
    expected = json.loads((directory/"fault-load.json").read_text())["expected_recipient_balance"]
    deadline = time.monotonic()+45
    while cluster.rpc(node["rpc_url"], "getBalance", [manifest["recipient"], {"commitment":"finalized"}])["value"] != expected:
        assert time.monotonic() < deadline, "restarted validator failed to catch up"
        time.sleep(.1)
    recovery = {"actual_agave_validator": True, "victim_index": victim,
        "missing_window_last_slot": missing_last_slot, "before_slot": before["slot"],
        "survivor_slot_after_skipped_window": after["slot"], "crash": killed,
        "additional_transfers_finalized_while_offline": 100,
        "restarted_validator_balance_matches": True,
        "restarted_status": cluster.rpc(node["rpc_url"], "getExperimentalPqStatus")}
    (directory/"fault-result.json").write_text(json.dumps(recovery, indent=2)+"\n")
    print("scheduled leader crash, seven-node continuation and durable restart passed", flush=True)
    finish_sampling()
    atexit.unregister(finish_sampling)


if __name__ == "__main__":
    main()
