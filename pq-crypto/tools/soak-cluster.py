#!/usr/bin/env python3
"""Coordinate continuous native Agave traffic and reconcile both generators.

Use a fresh initialized/deployed manifest. This runner preserves every ledger
and Ax history; it never stops or resets an unrelated validator. Short runs are
pilots and are explicitly excluded from the one-hour acceptance result.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("cluster", Path(__file__).with_name("agave-cluster.py"))
cluster = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cluster)


def number(value):
    return type(value) in (int, float) and math.isfinite(value)


def continuous_source_spans(results):
    wall = [(value["last_admission_unix_ms"]-value["first_admission_unix_ms"])/1000
        if number(value.get("first_admission_unix_ms")) and number(value.get("last_admission_unix_ms")) else None
        for value in results]
    monotonic = [value.get("admission_span_seconds_monotonic") for value in results]
    valid = len(results) == 2 and all(number(span) and span >= 3600 for span in wall + monotonic) \
        and all(number(value.get("largest_admission_gap_ms")) and 0 <= value["largest_admission_gap_ms"] <= 30_000 for value in results)
    return wall, monotonic, valid


def resource_traffic_coverage(document, left, right, expected, max_gap_seconds=5):
    """Require pinned, uninterrupted one-second samples throughout admissions.

    The outer stream brackets traffic. Owned samples must approach each edge
    within five seconds: a waiting generator wrapper can legitimately precede
    exec at the left edge. All in-traffic samples are mandatory, including any
    missing/error sample; none is filtered away to improve the observed span.
    """
    observations = document.get("samples", [])
    failures = []
    if not observations or not number(left) or not number(right) or right <= left:
        return {"covers_traffic":False,"failures":["invalid traffic/resource interval"]}
    times = [value.get("wall_seconds") for value in observations]
    if not all(number(value) for value in times) or any(b <= a for a,b in zip(times,times[1:])):
        return {"covers_traffic":False,"failures":["nonmonotonic resource wall timestamps"]}
    if times[0] > left or times[-1] < right:
        failures.append("resource stream does not bracket admission interval")
    selected = [value for value in observations if left <= value["wall_seconds"] <= right]
    if len(selected) < 2:
        return {"covers_traffic":False,"failures":[*failures,"insufficient in-traffic samples"]}
    if selected[0]["wall_seconds"]-left > max_gap_seconds or right-selected[-1]["wall_seconds"] > max_gap_seconds:
        failures.append("owned sample boundary gap exceeds tolerance")
    identity = None
    for value in selected:
        proc = value.get("process")
        if value.get("errors"):
            failures.append("latched resource error during traffic")
        if not isinstance(proc, dict) or not isinstance(proc.get("io"), dict):
            failures.append("missing owned process or process IO during traffic")
            continue
        current = (proc.get("pid"),proc.get("start_jiffies"))
        if any(type(item) is not int or item <= 0 for item in current):
            failures.append("invalid owned PID/start identity")
        elif identity is None:
            identity = current
        elif current != identity:
            failures.append("owned PID/start identity changed during traffic")
        for field in ("executable_sha384","configuration_sha384","argv_sha384"):
            if not expected.get(field) or proc.get(field) != expected[field]:
                failures.append("owned process pin mismatch: "+field)
        if not all(number(proc.get(field)) and proc[field] >= 0 for field in ("cpu_seconds","rss_bytes")) \
            or not all(type(proc["io"].get(field)) is int and proc["io"][field] >= 0 for field in ("read_bytes","write_bytes")):
            failures.append("missing/invalid owned resource counters")
        if not all(value.get("counter_available", {}).get(field) is True for field in ("network","disk")) \
            or len(value.get("cpu_jiffies", [])) != 8 or "MemAvailable" not in value.get("memory", {}) \
            or not value.get("network") or not value.get("disk"):
            failures.append("host resource counter unavailable during traffic")
    maximum_gap = 0
    for previous,current in zip(selected,selected[1:]):
        wall_gap = current["wall_seconds"]-previous["wall_seconds"]
        mono_left,mono_right = previous.get("monotonic_seconds"),current.get("monotonic_seconds")
        if not number(mono_left) or not number(mono_right) or not 0 < mono_right-mono_left <= max_gap_seconds \
            or not 0 < wall_gap <= max_gap_seconds or abs(wall_gap-(mono_right-mono_left)) > 1:
            failures.append("resource sampling gap or clock jump during traffic")
        maximum_gap = max(maximum_gap,wall_gap)
        a,b = previous.get("process"),current.get("process")
        if isinstance(a,dict) and isinstance(b,dict) and isinstance(a.get("io"),dict) and isinstance(b.get("io"),dict):
            if not number(a.get("cpu_seconds")) or not number(b.get("cpu_seconds")) \
                or b["cpu_seconds"] < a["cpu_seconds"] \
                or any(not number(a["io"].get(field)) or not number(b["io"].get(field)) \
                    or b["io"][field] < a["io"][field] for field in ("read_bytes","write_bytes")):
                failures.append("owned process counters decreased during traffic")
    owned_span = selected[-1]["wall_seconds"]-selected[0]["wall_seconds"]
    return {"first":times[0],"last":times[-1],"traffic_first":left,"traffic_last":right,
        "sampling_period_seconds":1,"maximum_allowed_sampling_gap_seconds":max_gap_seconds,
        "owned_boundary_tolerance_seconds":max_gap_seconds,"maximum_observed_sampling_gap_seconds":maximum_gap,
        "in_traffic_samples_checked":len(selected),"owned_identity":identity,
        "owned_process_observed_seconds":owned_span,"owned_process_covers_hour":owned_span >= 3600,
        "all_in_traffic_samples_pinned_and_uninterrupted":not failures,
        "covers_traffic":not failures,"failures":sorted(set(failures))}


def write(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def balances(nodes, recipients, tokens):
    import base64
    def node(peer):
        def accounts(addresses):
            values = []
            for offset in range(0, len(addresses), 100):
                response = cluster.rpc(peer["rpc_url"], "getMultipleAccounts",
                    [addresses[offset:offset+100], {"encoding":"base64", "commitment":"finalized"}])
                values.extend(response["value"])
            return values
        system = [row["lamports"] for row in accounts(recipients)]
        # SPL Token Account amount is the little-endian u64 at byte64.
        token = [int.from_bytes(base64.b64decode(row["data"][0])[64:72], "little")
            for row in accounts(tokens)]
        return {"host":peer["host"], "system":system, "token":token,
            "status":cluster.rpc(peer["rpc_url"], "getExperimentalPqStatus")}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(nodes)) as pool:
        return list(pool.map(node, nodes))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source-host", action="append", required=True)
    parser.add_argument("--source-request", type=Path, action="append", required=True)
    parser.add_argument("--key", type=Path, default=Path.home()/"google_compute_engine")
    parser.add_argument("--launch", action="store_true")
    parser.add_argument("--deploy-generators", action="store_true")
    parser.add_argument("--resource-extra-seconds", type=int, default=120)
    parser.add_argument("--run-label", default="hour")
    parser.add_argument("--generator-binary", type=Path,
        help="absolute generator executable beneath the manifest directory/bin")
    parser.add_argument("--generator-command", choices=("soak", "soak-pipelined"), default="soak")
    parser.add_argument("--rayon-global-threads", type=int, default=8,
        help="validator worker count when --launch is used (1..128, default 8)")
    args = parser.parse_args()
    if not 1 <= args.rayon_global_threads <= 128:
        parser.error("--rayon-global-threads must be between 1 and 128")
    manifest = json.loads(args.manifest.read_text())
    directory = args.manifest.resolve().parent
    assert args.run_label and Path(args.run_label).name == args.run_label
    generator_binary = args.generator_binary or directory/"bin/agave-pq-tool"
    assert generator_binary.is_absolute(), "generator binary must be an absolute path"
    generator_binary = generator_binary.resolve(strict=True)
    assert generator_binary.parent == (directory/"bin").resolve(strict=True), "generator binary must be beneath the manifest directory/bin"
    assert generator_binary.is_file(), "generator executable must be a regular file"
    generator_sha384 = hashlib.sha384(generator_binary.read_bytes()).hexdigest()
    controller_sha384 = hashlib.sha384(Path(__file__).read_bytes()).hexdigest()
    provenance = {"generator_binary_sha384":generator_sha384,
        "generator_command":args.generator_command,"controller_sha384":controller_sha384,
        "requested_rayon_global_threads":args.rayon_global_threads}
    run_directory = directory/args.run_label
    run_directory.mkdir(mode=0o700, exist_ok=False)
    write(run_directory/"soak-provenance.json",provenance)
    nodes = manifest["nodes"]
    requests = [json.loads(path.read_text()) for path in args.source_request]
    assert len(args.source_host) == len(requests) == 2
    assert len(set(args.source_host)) == 2
    assert all(host in cluster.AUTHORIZED for host in args.source_host)
    assert not set(args.source_host).intersection(node["host"] for node in nodes)
    assert all(node["host"] in cluster.AUTHORIZED for node in nodes)
    assert requests[0]["source_id"] != requests[1]["source_id"]
    assert set(requests[0]["wallet_indices"]).isdisjoint(requests[1]["wallet_indices"])
    assert requests[0]["duration_seconds"] == requests[1]["duration_seconds"]
    assert requests[0]["recipient_count"] == requests[1]["recipient_count"]
    assert all(Path(request["output"]).parent == directory for request in requests)
    duration = requests[0]["duration_seconds"]
    assert duration > 0 and args.resource_extra_seconds >= 30
    helper = Path(__file__).with_name("agave-cluster.py")
    transport = f"ssh -i {shlex.quote(str(args.key))} -o BatchMode=yes"

    def manage(action):
        with open(run_directory/f"soak-{action}.log", "a") as log:
            subprocess.run([sys.executable, str(helper), action, "--manifest", str(args.manifest),
                "--remote", "--key", str(args.key), "--timeout", "180",
                "--rayon-global-threads", str(args.rayon_global_threads),
                "--output", str(run_directory/f"soak-{action}.json")], stdout=log, stderr=log, check=True)

    if args.launch:
        manage("launch")
        manage("wait")
    if args.deploy_generators:
        def deploy(index):
            host = args.source_host[index]
            cluster.ssh(host, f"mkdir -p {shlex.quote(str(directory/'bin'))}; chmod 700 {shlex.quote(str(directory))}", args.key)
            files = [args.manifest.resolve(), args.source_request[index].resolve(), generator_binary]
            for wallet in requests[index]["wallet_indices"]:
                record = manifest["wallets"][wallet]
                assert record.get("legacy_private_key") is None, "generic soak must use System-owned fresh payers"
                files.append(Path(record["private_key"]))
            # Preserve relative paths and deploy only this generator's credentials.
            sources = [str(directory)+"/./"+str(path.relative_to(directory)) for path in files]
            subprocess.run(["rsync", "-aR", "--chmod=D700,F600", "-e", transport,
                *sources, f"sol@{host}:{directory}/"], check=True, capture_output=True)
            cluster.ssh(host, f"chmod 700 {shlex.quote(str(generator_binary))}", args.key)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(deploy, range(2)))

    def verify_generator(host):
        observed = cluster.ssh(host,f"sha384sum {shlex.quote(str(generator_binary))}",args.key).split()[0]
        assert observed == generator_sha384, "installed generator binary differs from the selected executable"
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(verify_generator,args.source_host))

    selected = requests[0]["recipient_count"]
    recipients = manifest.get("recipients", [manifest["recipient"]])[:selected]
    uses_tokens = any(phase["kind"] == "token_transfer" for request in requests for phase in request["phases"])
    tokens = manifest.get("recipient_token_accounts", [])[:selected] if uses_tokens else []
    before = balances(nodes, recipients, tokens)
    assert all(row["system"] == before[0]["system"] and row["token"] == before[0]["token"] for row in before)
    write(run_directory/"soak-balances-before.json", before)
    resource_nodes = []
    for node in nodes:
        owned_argv = cluster.command(node, directory/"bin/agave-validator", args.rayon_global_threads)
        resource_nodes.append({**node,"owned_command":owned_argv,"exact_owned_argv":True,
            "executable_sha384":hashlib.sha384((directory/"bin/agave-validator").read_bytes()).hexdigest(),
            "configuration_sha384":hashlib.sha384(Path(node["config"]).read_bytes()).hexdigest(),
            "argv_sha384":hashlib.sha384(b"\0".join(argument.encode() for argument in owned_argv)+b"\0").hexdigest()})
    for index,host in enumerate(args.source_host):
        resource_nodes.append({"host":host,"kind":"generator","config":str(args.source_request[index].resolve()),
            "pidfile":str(directory/f"owned-generator-{args.run_label}-{index}.pid"),
            "owned_command":[str(generator_binary),args.generator_command,str(args.source_request[index].resolve())],
            "exact_owned_argv":True,"executable_sha384":generator_sha384,
            "configuration_sha384":hashlib.sha384(args.source_request[index].read_bytes()).hexdigest(),
            "argv_sha384":hashlib.sha384(b"\0".join(argument.encode() for argument in [str(generator_binary),args.generator_command,str(args.source_request[index].resolve())])+b"\0").hexdigest()})
    resource_manifest = run_directory/"resources-manifest.json"
    write(resource_manifest,{"nodes":resource_nodes})
    samples = run_directory/"resources-soak"
    with open(run_directory/"resources-soak.log", "w") as log:
        sampler = subprocess.Popen([sys.executable, str(Path(__file__).with_name("resources.py")),
            "--manifest", str(resource_manifest), "--remote", "--key", str(args.key),
            "--duration", str(duration+args.resource_extra_seconds), "--output", str(samples)], stdout=log, stderr=log, start_new_session=True)
    def abort_sampling():
        if sampler.poll() is None:
            try: os.killpg(sampler.pid,signal.SIGTERM)
            except ProcessLookupError: pass
            try: sampler.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try: os.killpg(sampler.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                sampler.wait(timeout=10)
    deadline = time.monotonic()+45
    while not all((samples/f"node-{index}.ready").exists() for index in range(len(resource_nodes))):
        if sampler.poll() is not None or time.monotonic() >= deadline:
            abort_sampling()
            raise RuntimeError("resource collectors did not become ready")
        time.sleep(.1)
    common_start_ms = int(time.time()*1000)+5000
    write(run_directory/"soak-common-start.json", {"unix_ms":common_start_ms,"duration_seconds":duration,**provenance})

    def source(index):
        argv = [str(generator_binary), args.generator_command, str(args.source_request[index].resolve())]
        pidfile = directory/f"owned-generator-{args.run_label}-{index}.pid"
        code = "import os,time\nfrom pathlib import Path\n" + f"Path({str(pidfile)!r}).write_text(str(os.getpid()))\n" + f"deadline={common_start_ms}/1000\n" + \
            "while time.time()<deadline: time.sleep(.01)\n" + f"os.execv({argv[0]!r},{argv!r})\n"
        with open(run_directory/f"soak-source-{index}.log", "w") as log:
            result = subprocess.run(["ssh", "-i", str(args.key), "-o", "BatchMode=yes",
                f"sol@{args.source_host[index]}", "python3 -"], input=code, text=True, stdout=log, stderr=log)
        ended = time.monotonic()
        output = Path(requests[index]["output"])
        paths = [output, output.with_suffix(".events.jsonl"), output.with_suffix(".minutes.jsonl")]
        copied = subprocess.run(["rsync", "-a", "--chmod=F600", "-e", transport,
            *[f"sol@{args.source_host[index]}:{path}" for path in paths], str(directory)+"/"], capture_output=True)
        return {"code":result.returncode,"copy_code":copied.returncode,"ended_monotonic":ended}

    def stop_failed_sibling(index):
        # A failed source invalidates the continuous pair. Stop only its exact
        # owned sibling and retain all partial native history and source files.
        argv = [str(generator_binary), args.generator_command, str(args.source_request[index].resolve())]
        pidfile = directory/f"owned-generator-{args.run_label}-{index}.pid"
        code = f'''import hashlib,json,os,signal,time
from pathlib import Path
pid=int(Path({str(pidfile)!r}).read_text());proc=Path('/proc')/str(pid)
expected={[arg.encode() for arg in argv]!r}
def live():
 if not proc.exists() or (proc/'stat').read_text().split()[2]=='Z': return False
 if (proc/'cmdline').read_bytes().rstrip(b'\\0').split(b'\\0')!=expected: raise RuntimeError('failed-pair sibling argv fence mismatch')
 h=hashlib.sha384()
 with (proc/'exe').open('rb') as stream:
  for chunk in iter(lambda:stream.read(1048576),b''): h.update(chunk)
 if h.hexdigest()!={generator_sha384!r}: raise RuntimeError('failed-pair sibling executable fence mismatch')
 return True
for sig in [signal.SIGINT,signal.SIGTERM]:
 if not live(): break
 os.kill(pid,sig);deadline=time.monotonic()+8
 while proc.exists() and (proc/'stat').read_text().split()[2]!='Z' and time.monotonic()<deadline: time.sleep(.1)
if live(): raise RuntimeError('owned failed-pair sibling did not stop')
print(json.dumps({{'source':{index},'pid':pid,'stopped':True,'only_exact_owned_generator_signaled':True}}))
'''
        return json.loads(cluster.ssh(args.source_host[index], "python3 -", args.key, code))

    monitor_path = run_directory/"soak-monitor.jsonl"
    started = time.monotonic()
    source_results = None
    results = None
    summary = None
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool, open(monitor_path,"w") as monitor:
            futures = [pool.submit(source,index) for index in range(2)]
            failed_pair = False
            while not all(future.done() for future in futures):
                if not failed_pair:
                    for index, future in enumerate(futures):
                        if not future.done():
                            continue
                        ended = future.result()
                        if ended["code"] or ended["copy_code"]:
                            failed_pair = True
                            failure = {"wall_ms":int(time.time()*1000),"source":index,"exit":ended,
                                "continuous_pair_rejected":True,"stopped_siblings":[]}
                            write(run_directory/"soak-early-source-failure.json",failure)
                            for sibling, sibling_future in enumerate(futures):
                                if sibling != index and not sibling_future.done():
                                    failure["stopped_siblings"].append(stop_failed_sibling(sibling))
                                    write(run_directory/"soak-early-source-failure.json",failure)
                            print(json.dumps(failure),flush=True)
                            break
                def status(peer):
                    try: return cluster.rpc(peer["rpc_url"], "getExperimentalPqStatus")
                    except Exception as error: return {"unavailable":str(error)}
                with concurrent.futures.ThreadPoolExecutor(max_workers=len(nodes)) as observers:
                    statuses = list(observers.map(status,nodes))
                observation = {"wall_ms":int(time.time()*1000),"elapsed_seconds":time.monotonic()-started,"validators":statuses}
                monitor.write(json.dumps(observation)+"\n"); monitor.flush()
                write(run_directory/"soak-monitor-live.json", observation)
                print(json.dumps({"elapsed_seconds":round(observation["elapsed_seconds"],1),
                    "slots":[row.get("slot") for row in statuses],
                    "finalized_transactions":[row.get("finalized_transactions") for row in statuses],
                    "mempool":[row.get("mempool") for row in statuses],
                    "fatal_errors":[row.get("fatal_error") for row in statuses]}),flush=True)
                time.sleep(10)
            source_results = [future.result() for future in futures]
        write(run_directory/"soak-source-exits.json", source_results)
        assert all(result["copy_code"] == 0 for result in source_results), "generator artifacts missing"
        results = [json.loads(Path(request["output"]).read_text()) for request in requests]
        after = balances(nodes, recipients, tokens)
        write(run_directory/"soak-balances-after.json", after)
        system_expected = [value+sum(result["system_recipient_deltas"][index] for result in results)
            for index,value in enumerate(before[0]["system"])]
        token_expected = [value+sum(result["token_recipient_deltas"][index] for result in results)
            for index,value in enumerate(before[0]["token"])]
        states_match = all(row["system"] == system_expected and row["token"] == token_expected for row in after)
        interval = (max(result["completed_unix_ms"] for result in results)-min(result["started_unix_ms"] for result in results))/1000
        successful = sum(result["counts"]["finalized_success"] for result in results)
        valid = all(result["code"] == 0 for result in source_results) and states_match and all(
            result["pending"] == 0 and result["failure"] is None
            and result["counts"]["generated"] > 0
            and result["counts"]["generated"] == result["counts"]["admitted"] == result["counts"]["finalized_success"]
            and result["counts"]["admission_errors"] == result["counts"]["finalized_error"] == 0
            for result in results)
        spans, monotonic_spans, continuous_pair = continuous_source_spans(results)
        summary = {**provenance,"actual_agave_validator":True,"validator_count":len(nodes),"generator_count":2,
            "requested_continuous_seconds":duration,"hour_acceptance_passed":duration >= 3600 and valid and continuous_pair,
            "source_admission_spans_seconds":spans,
            "source_admission_spans_seconds_monotonic":monotonic_spans,
            "all_expected_recipient_assets_match":states_match,"finalized_success":successful,
            "finalized_error":sum(result["counts"]["finalized_error"] for result in results),
            "admission_errors":sum(result["counts"]["admission_errors"] for result in results),
            "generator_joint_interval_including_drain_seconds":interval,"joint_finalized_success_tps":successful/interval,
            "controller_elapsed_seconds":max(result["ended_monotonic"] for result in source_results)-started,
            "largest_admission_gap_ms":[result["largest_admission_gap_ms"] for result in results],
            "expected_system_balances":system_expected,"expected_token_balances":token_expected,
            "source_counts":[result["counts"] for result in results],"valid":valid}
        write(run_directory/"soak-result.json",summary)
        assert valid, "soak failed exact native-status and asset reconciliation; inspect retained artifacts"
    finally:
        # Persist resource observations before the caller stops its owned nodes.
        if summary is None or not summary["valid"]:
            abort_sampling()
        else:
            code = sampler.wait(timeout=duration+args.resource_extra_seconds+45)
            if code:
                raise RuntimeError("resource sampling failed; see resources-soak.log")
        if summary is not None and summary["valid"] and results is not None:
            left = min(result["first_admission_unix_ms"] for result in results)/1000
            right = max(result["last_admission_unix_ms"] for result in results)/1000
            resource_summary = json.loads((samples/"summary.json").read_text())
            windows = []
            for index in range(len(resource_nodes)):
                document = json.loads((samples/f"node-{index}.json").read_text())
                windows.append({"node":index,**resource_traffic_coverage(document,left,right,resource_nodes[index])})
            summary["resource_windows"] = windows
            summary["all_resources_cover_traffic_interval"] = all(window["covers_traffic"] for window in windows)
            summary["hour_acceptance_passed"] &= summary["all_resources_cover_traffic_interval"]
            summary["hour_acceptance_passed"] &= all(window["owned_process_covers_hour"] for window in windows)
            write(run_directory/"soak-result.json",summary)
    if summary is not None:
        print(json.dumps(summary),flush=True)
        assert duration < 3600 or summary["hour_acceptance_passed"], "one-hour traffic/resource acceptance conditions were not met"


if __name__ == "__main__":
    main()
