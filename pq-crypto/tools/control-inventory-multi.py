#!/usr/bin/env python3
"""Opt-in read-only custody audit after the hour plus three sequential trials.

The original control-inventory.py and hour evidence remain immutable. This
experiment-specific helper requires four System/Token pairs (401/402, 501/502,
601/602, 701/702), committed contiguous ranges, and nonoverlapping pair intervals.
A source may have several rate phases only when every phase has the same kind.
All eight request hashes are explicitly pinned; the first pair also retains the
independent pre-hour operating-point pin. Later request pins record their capture
time and do not claim to precede a trial that already started.

Create pins: --pin-requests --operating-point HOUR_PIN --source-request R (x8)
  --output PRIVATE_PIN_JSON
Final audit: --manifest ORIGINAL --baseline PRIVATE_BEFORE --operating-point
  HOUR_PIN --request-pins PRIVATE_PIN_JSON --source-request R (x8)
  --source-result S (x8) --output FRESH_PRIVATE_DIR
Use --self-test for mocks without RPC. Full vectors stay outside the repository.
"""
import argparse
import concurrent.futures
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
BASE_SHA384 = "0b3b311822a69be68c7db3b094d4dab69dd78a04286c45c82079c5f6647e7b1d43353eb9f97bd83520244fb7c18bd876"
BASE_PATH = Path(__file__).with_name("control-inventory.py")
if hashlib.sha384(BASE_PATH.read_bytes()).hexdigest() != BASE_SHA384:
    raise ValueError("frozen hour account-audit helper changed")
spec = importlib.util.spec_from_file_location("control_inventory", BASE_PATH)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require, read_json, write_private, u64 = base.require, base.read_json, base.write_private, base.u64
PAIRS = ((401, 402), (501, 502), (601, 602), (701, 702))
KINDS = ("system_transfer", "token_transfer")


def private_output(path):
    require(path.is_absolute() and not path.resolve().is_relative_to(Path(__file__).resolve().parents[2]), "private output must be outside repository")
    require(not path.exists(), "fresh output required")


def validate_requests(requests):
    require(len(requests) == 8, "exactly four sequential source pairs required")
    require([row.get("source_id") for row in requests] == [source for pair in PAIRS for source in pair], "source IDs/order differ from the explicit experiment")
    for pair in range(4):
        left, right = requests[2 * pair:2 * pair + 2]
        require(set(left["wallet_indices"]).isdisjoint(right["wallet_indices"]), "payer overlap within simultaneous pair")
        require(left.get("duration_seconds") == right.get("duration_seconds") and left.get("recipient_count") == right.get("recipient_count"), "pair duration/recipient mismatch")
        for kind, request in zip(KINDS, (left, right)):
            duration = u64(request.get("duration_seconds"), "source duration")
            phases = request.get("phases")
            require(duration > 0 and isinstance(phases, list) and phases and all(isinstance(phase, dict) and phase.get("kind") == kind for phase in phases), "mixed-kind/empty rate phases forbidden")
            require(all(u64(phase.get("seconds"), "phase seconds") > 0 and u64(phase.get("target_tps"), "phase rate") > 0 for phase in phases) and sum(phase["seconds"] for phase in phases) == duration, "phase timing/rate does not match duration")


def check_hour_pin(paths, operating_point):
    require(len(operating_point.get("sources", [])) == 2, "pre-hour operating-point source count")
    for index in range(2):
        require(hashlib.sha384(paths[index].read_bytes()).hexdigest() == operating_point["sources"][index]["request_sha384"], "hour request changed from immutable operating point")


def request_pins(paths, requests, operating_point):
    validate_requests(requests)
    check_hour_pin(paths, operating_point)
    return {"format": "agave-pq-post-trials-request-pins-v1", "captured_unix_ms": time.time_ns() // 1000000, "base_helper_sha384": BASE_SHA384, "source_sha384": hashlib.sha384(Path(__file__).read_bytes()).hexdigest(), "hour_requests_match_pre_hour_pin": True, "later_trial_pin_scope": "request contents captured before final account audit; capture may follow launch of an already running trial", "sources": [{"pair": index // 2, "source_id": request["source_id"], "request_sha384": hashlib.sha384(path.read_bytes()).hexdigest(), "phases": request["phases"]} for index, (path, request) in enumerate(zip(paths, requests))]}


def validate_intervals(results):
    require(len(results) == 8, "eight source result intervals required")
    pairs = []
    for index in range(4):
        rows = results[2 * index:2 * index + 2]
        for row in rows:
            start = u64(row.get("started_unix_ms"), "source start")
            first = u64(row.get("first_admission_unix_ms"), "first admission")
            last = u64(row.get("last_admission_unix_ms"), "last admission")
            complete = u64(row.get("completed_unix_ms"), "source completion")
            require(start <= first <= last <= complete and start < complete, "source wall interval is malformed")
        require(max(row["started_unix_ms"] for row in rows) < min(row["completed_unix_ms"] for row in rows), "simultaneous pair did not overlap")
        pair = {"pair": index, "source_ids": list(PAIRS[index]), "started_unix_ms": min(row["started_unix_ms"] for row in rows), "completed_unix_ms": max(row["completed_unix_ms"] for row in rows)}
        if pairs:
            require(pairs[-1]["completed_unix_ms"] < pair["started_unix_ms"], "sequential trial intervals overlap")
        pairs.append(pair)
    return pairs


def run(args):
    require(args.manifest is not None and args.baseline is not None and args.request_pins is not None and args.operating_point is not None, "manifest/baseline/request-pins/pre-hour-pin required")
    require(len(args.source_request) == len(args.source_result) == 8 and 1 <= args.timeout <= 30, "exact eight sources and bounded RPC timeout required")
    private_output(args.output)
    manifest = read_json(args.manifest)
    nodes, _, _, _, _ = base.selection(manifest)
    requests, results = [read_json(path) for path in args.source_request], [read_json(path) for path in args.source_result]
    validate_requests(requests)
    check_hour_pin(args.source_request, read_json(args.operating_point))
    pins = read_json(args.request_pins)
    require(pins.get("format") == "agave-pq-post-trials-request-pins-v1" and pins.get("base_helper_sha384") == BASE_SHA384 and len(pins.get("sources", [])) == 8, "request pin format/helper mismatch")
    for index, (request, path) in enumerate(zip(requests, args.source_request)):
        pin = pins["sources"][index]
        require(pin.get("source_id") == request["source_id"] and pin.get("pair") == index // 2 and pin.get("request_sha384") == hashlib.sha384(path.read_bytes()).hexdigest() and pin.get("phases") == request["phases"], "request differs from explicit post-trial pin")
    intervals = validate_intervals(results)
    lamports, tokens, source_summaries, samples = {}, {}, [], []
    for index, (request, result) in enumerate(zip(requests, results)):
        sol, spl, summary = base.source_deltas(manifest, request, result)
        for address, delta in sol.items():
            lamports[address] = lamports.get(address, 0) + delta
        for address, delta in spl.items():
            tokens[address] = tokens.get(address, 0) + delta
        summary.update({"pair": index // 2, "rate_phases": request["phases"], "request_sha384": hashlib.sha384(args.source_request[index].read_bytes()).hexdigest(), "result_sha384": hashlib.sha384(args.source_result[index].read_bytes()).hexdigest()})
        source_summaries.append(summary)
        samples.append(base.sample_event(result, request))
    count = sum(row["generated_and_committed"] for row in source_summaries)
    require(sum(lamports.values()) == -5000 * count and sum(tokens.values()) == 0, "aggregate independent fee/amount conservation mismatch")
    baseline_summary = read_json(args.baseline / "summary.json")
    require(baseline_summary.get("phase") == "pre-load-baseline" and baseline_summary.get("genesis_hash") == manifest["genesis_hash"] and baseline_summary.get("validators") == 8 and baseline_summary.get("all_validator_full_records_match") is True, "invalid original pre-hour baseline")
    args.output.mkdir(mode=0o700)
    started = time.time_ns() // 1000000
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        collected = list(pool.map(lambda pair: base.collect(manifest, pair[1], pair[0], args.timeout), enumerate(nodes)))
    require(all(row["inventory_sha384"] == collected[0]["inventory_sha384"] and row["policies"] == collected[0]["policies"] and row["native_rent_parameters"] == collected[0]["native_rent_parameters"] for row in collected), "account/policy/rent inventory differs across validators")
    comparisons, fees, hashes = [], [], []
    for index, node in enumerate(collected):
        baseline_path = args.baseline / f"node-{index}.json"
        require(hashlib.sha384(baseline_path.read_bytes()).hexdigest() == baseline_summary["nodes"][index]["private_document_sha384"], "original baseline bytes changed")
        baseline = read_json(baseline_path)
        require(baseline["host"] == node["host"] and baseline["genesis_hash"] == manifest["genesis_hash"] and baseline["policies"] == node["policies"], "baseline host/genesis/policy differs")
        expected = base.expected_records(baseline["records"], lamports, tokens, node["native_rent_parameters"])
        mismatches = base.compare_records(baseline["records"], node["records"], lamports, tokens, node["native_rent_parameters"])
        normalized = [row["address"] for row in baseline["records"] if row["present"] and expected[row["address"]]["rent_epoch"] != row["rent_epoch"]]
        comparison = {"node": index, "accounts": len(baseline["records"]), "unexpected_accounts": mismatches, "all_expected_full_records_match": not mismatches, "predicted_native_rent_epoch_normalizations": len(normalized), "predicted_normalized_addresses": normalized}
        comparisons.append(comparison)
        write_private(args.output / f"comparison-{index}.json", comparison)
        for source, (request, event) in enumerate(zip(requests, samples)):
            receipt = base.rpc(nodes[index]["rpc_url"], "getTransaction", [event["id"], {"encoding": "base64", "commitment": "finalized", "maxSupportedTransactionVersion": 0}], f"control-multi:{index}:fee:{source}", args.timeout)
            fees.append({"node": index, "pair": source // 2, **base.validate_fee_receipt(receipt, event, request, manifest)})
        node["genesis_hash"] = manifest["genesis_hash"]
        write_private(args.output / f"node-{index}.json", node)
        hashes.append(hashlib.sha384((args.output / f"node-{index}.json").read_bytes()).hexdigest())
    all_match = all(row["all_expected_full_records_match"] for row in comparisons)
    summary = {"format": "agave-pq-post-trials-control-inventory-v1", "read_only": True, "actual_bank_svm_accounts": True, "genesis_hash": manifest["genesis_hash"], "source_sha384": hashlib.sha384(Path(__file__).read_bytes()).hexdigest(), "frozen_hour_helper_sha384": BASE_SHA384, "request_pin_sha384": hashlib.sha384(args.request_pins.read_bytes()).hexdigest(), "started_unix_ms": started, "completed_unix_ms": time.time_ns() // 1000000, "validators": 8, "source_streams": 8, "sequential_pairs": intervals, "all_validator_full_records_match": True, "all_expected_full_records_match": all_match, "unexpected_account_count": sum(len(row["unexpected_accounts"]) for row in comparisons), "accounts_per_validator": len(collected[0]["records"]), "policies_per_validator": len(collected[0]["policies"]), "exact_all_metadata_and_full_bytes": True, "no_account_or_field_exclusions": True, "expected_changes": "sum of all independently derived contiguous source payer/recipient lamports and token amount lanes, with the exact frozen native rent-epoch predictor", "native_rent_parameters": collected[0]["native_rent_parameters"], "predicted_native_rent_epoch_normalizations_per_validator": [row["predicted_native_rent_epoch_normalizations"] for row in comparisons], "total_committed_source_transactions": count, "expected_total_payer_fees_lamports": count * 5000, "expected_token_delta_sum": sum(tokens.values()), "source_ranges": source_summaries, "actual_source_fee_samples": fees, "nodes": [{"node": row["node"], "host": row["host"], "inventory_sha384": row["inventory_sha384"], "context_slot_min": row["context_slot_min"], "context_slot_max": row["context_slot_max"], "private_document_sha384": hashes[index]} for index, row in enumerate(collected)]}
    write_private(args.output / "summary.json", summary)
    require(all_match, "post-trial exact account comparison failed; private comparisons preserved")
    print(json.dumps(summary))


def self_test():
    base.self_test()
    def fails(operation):
        try:
            operation()
        except (ValueError, TypeError, KeyError):
            return
        raise AssertionError("negative multi-source case accepted")
    requests, results = [], []
    for pair in range(4):
        for source in range(2):
            requests.append({"source_id": PAIRS[pair][source], "wallet_indices": [33 + source], "duration_seconds": 120, "recipient_count": 256, "phases": [{"kind": KINDS[source], "seconds": 30, "target_tps": rate} for rate in (2000, 4000, 6000, 8000)]})
            start = 1000 + pair * 10000 + source
            results.append({"started_unix_ms": start, "first_admission_unix_ms": start + 1, "last_admission_unix_ms": start + 50, "completed_unix_ms": start + 100})
    validate_requests(requests)
    assert len(validate_intervals(results)) == 4
    bad = copy.deepcopy(requests); bad[2]["source_id"] = 401
    fails(lambda: validate_requests(bad))
    bad = copy.deepcopy(requests); bad[1]["wallet_indices"] = [33]
    fails(lambda: validate_requests(bad))
    bad = copy.deepcopy(requests); bad[0]["phases"][1]["kind"] = "token_transfer"
    fails(lambda: validate_requests(bad))
    bad = copy.deepcopy(requests); bad[0]["phases"][1]["seconds"] = 31
    fails(lambda: validate_requests(bad))
    bad = copy.deepcopy(results); bad[2].update({"started_unix_ms": 1050, "first_admission_unix_ms": 1051, "last_admission_unix_ms": 1100, "completed_unix_ms": 1200})
    fails(lambda: validate_intervals(bad))
    bad = copy.deepcopy(results); bad[0]["last_admission_unix_ms"] = 2000
    fails(lambda: validate_intervals(bad))
    # Independent enumerated counters establish cumulative wallet/recipient
    # changes across repeated payers and four unique source-pair namespaces.
    baseline = [base.record(base.b58(bytes([i]) * 32), {"owner": base.SYSTEM, "lamports": 100000000, "executable": False, "rentEpoch": base.RENT_EXEMPT_EPOCH, "data": ["", "base64"]}) for i in range(1, 6)]
    expected_amounts = [0] * 5
    derived = {}
    for pair in range(4):
        start, count = pair * 3, 13 + pair
        for counter in range(start, start + count):
            expected_amounts[counter % 2] -= 5001
            expected_amounts[2 + counter % 3] += 1
        payer_counts, recipient_counts = base.modulo_counts(start, count, 2), base.modulo_counts(start, count, 3)
        for i, transactions in enumerate(payer_counts):
            address = baseline[i]["address"]; derived[address] = derived.get(address, 0) - 5001 * transactions
        for i, transactions in enumerate(recipient_counts):
            address = baseline[i + 2]["address"]; derived[address] = derived.get(address, 0) + transactions
    assert [derived[row["address"]] for row in baseline] == expected_amounts
    observed = list(base.expected_records(baseline, derived, {}).values())
    assert base.compare_records(baseline, observed, derived, {}) == []
    incomplete = dict(derived); incomplete[baseline[0]["address"]] += 5001
    assert base.compare_records(baseline, observed, incomplete, {}) == [baseline[0]["address"]]
    print("multi-source self-test PASS: same-kind rate phases, unique explicit IDs, within-pair payer separation, strict sequential intervals, malformed range rejection, independently enumerated repeated-payer aggregation and omitted-stream delta rejection")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--operating-point", type=Path)
    parser.add_argument("--source-request", action="append", type=Path, default=[])
    parser.add_argument("--source-result", action="append", type=Path, default=[])
    parser.add_argument("--request-pins", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--pin-requests", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.pin_requests:
        require(args.output is not None and args.operating_point is not None, "fresh private output and pre-hour pin required")
        private_output(args.output)
        pins = request_pins(args.source_request, [read_json(path) for path in args.source_request], read_json(args.operating_point))
        write_private(args.output, pins)
        print(json.dumps(pins))
    else:
        require(args.output is not None, "fresh private output required")
        run(args)


if __name__ == "__main__":
    main()
