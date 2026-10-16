#!/usr/bin/env python3
"""Export public measurements from a completed native Agave traffic run.

Reads retained local observations only. Private manifests, paths, credentials,
addresses and raw error messages are never copied into the report. Publishing
an hour report requires the controller's completed-hour acceptance result and
independent transaction/resource checks. --allow-pilot produces a pilot report.
Matplotlib is needed only for rendering; --self-test uses the standard library.
"""

import argparse
import bisect
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import sys
import tempfile
import unittest


KINDS = {"system_transfer", "token_transfer", "nonce_only"}
PROCESS_METRICS = (
    "process_cpu_cores", "process_rss_GiB", "process_threads",
    "process_read_MBps", "process_write_MBps",
)
HOST_METRICS = (
    "host_cpu_busy_percent", "host_rx_MBps", "host_tx_MBps",
    "host_disk_read_MBps", "host_disk_write_MBps", "host_disk_busy_percent",
    "host_memory_available_GiB",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    return json.loads(path.read_text())


def digest(path):
    hasher = hashlib.sha384()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def finite_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def percentile(values, fraction):
    return sorted(values)[math.ceil((len(values) - 1) * fraction)]


def stats(values, weights=None):
    if not values:
        return None
    require(all(finite_number(value) for value in values), "non-finite measurement")
    return {
        "samples": len(values),
        "mean": sum(value * weight for value, weight in zip(values, weights)) / sum(weights)
        if weights is not None else statistics.mean(values),
        "p50": statistics.median(values),
        "p95": percentile(values, .95),
        "min": min(values),
        "max": max(values),
    }


def latency_counts(counts):
    """Rust Counts buckets use min(milliseconds.bit_length(), 31)."""
    histogram = counts["latency_buckets"]
    require(len(histogram) == 32 and all(isinstance(n, int) and n >= 0 for n in histogram),
            "latency histogram shape")
    total = counts["finalized_success"] + counts["finalized_error"]
    require(total > 0 and sum(histogram) == total, "latency histogram count mismatch")
    rank = math.ceil(total * .95)
    cumulative = 0
    for index, count in enumerate(histogram):
        cumulative += count
        if cumulative >= rank:
            lower = 0 if index == 0 else 2 ** (index - 1)
            upper = None if index == 31 else 1 if index == 0 else 2 ** index
            return {
                "measurement": "generation/reservation to source observation of exact finalized status",
                "mean_seconds": counts["latency_millis_total"] / total / 1000,
                "maximum_seconds": counts["latency_millis_max"] / 1000,
                "p95_histogram_bucket": index,
                "p95_lower_inclusive_seconds": lower / 1000,
                "p95_upper_exclusive_seconds": upper / 1000 if upper is not None else None,
                "histogram_counts": histogram,
                "qualification": "The p95 is a histogram interval, not an exact percentile. Polling, pending scans and client audits are included; this is not native consensus latency.",
            }
    raise ValueError("latency histogram has no p95")


def check_acceptance(result, sources, allow_pilot):
    require(result.get("actual_agave_validator") is True and result.get("valid") is True,
            "completed valid native run required")
    require(result.get("all_expected_recipient_assets_match") is True,
            "exact recipient reconciliation required")
    require(result.get("all_resources_cover_traffic_interval") is True,
            "completed resource coverage required")
    duration = result["requested_continuous_seconds"]
    hour = result.get("hour_acceptance_passed") is True
    if allow_pilot:
        require(duration < 3600 and not hour, "--allow-pilot is restricted to a completed short pilot")
    else:
        require(hour and duration >= 3600, "completed-hour acceptance has not passed")
    expected = 0
    for source in sources:
        require(source.get("actual_agave_rpc") is True and source.get("actual_bank_svm") is True,
                "native Bank/SVM source result required")
        require(source["requested_continuous_seconds"] == duration,
                "source/controller duration mismatch")
        count = source["counts"]
        require(source["pending"] == 0 and source["failure"] is None,
                "source has pending or failed work")
        require(count["generated"] == count["admitted"] == count["finalized_success"] > 0
                and count["admission_errors"] == count["finalized_error"] == 0,
                "source exact transaction reconciliation failed")
        require(source.get("all_validator_recipient_balances_match") is True,
                "source native asset reconciliation failed")
        if not allow_pilot:
            span = (source["last_admission_unix_ms"] - source["first_admission_unix_ms"]) / 1000
            monotonic_span = source.get("admission_span_seconds_monotonic")
            require(isinstance(monotonic_span, (int, float))
                    and not isinstance(monotonic_span, bool) and math.isfinite(monotonic_span)
                    and monotonic_span >= 3600,
                    "source monotonic admission span is shorter than one hour")
            require(span >= 3600 and source["largest_admission_gap_ms"] <= 30_000,
                    "source does not meet continuous-hour admission conditions")
        latency_counts(count)
        expected += count["finalized_success"]
    require(expected == result["finalized_success"]
            and result["finalized_error"] == result["admission_errors"] == 0,
            "controller/source transaction total mismatch")
    return hour


def phases(request):
    output = []
    boundary = 0
    for phase in request["phases"]:
        require(phase["kind"] in KINDS and phase["seconds"] > 0 and phase["target_tps"] > 0,
                "workload phase bounds")
        output.append({"start_seconds": boundary, "end_seconds": boundary + phase["seconds"],
                       "kind": phase["kind"], "offered_tps": phase["target_tps"]})
        boundary += phase["seconds"]
    require(boundary == request["duration_seconds"], "workload phase duration mismatch")
    return output


def source_summary(index, source, request, start):
    count = source["counts"]
    require(source["phases"] == request["phases"], "source/request phase mismatch")
    minutes = []
    for minute in source["minute_summaries"]:
        elapsed = minute["observed_seconds"]
        require(elapsed > 0, "minute observation duration")
        minutes.append({
            "minute_number": minute["minute"],
            "elapsed_minutes": (minute["wall_ms"] / 1000 - start) / 60,
            "observed_seconds": elapsed,
            "finalized_success": minute["counts"]["finalized_success"],
            "finalized_error": minute["counts"]["finalized_error"],
            "source_observed_tps": minute["counts"]["finalized_success"] / elapsed,
            "pending": minute["pending"],
        })
    require(all(a["elapsed_minutes"] < b["elapsed_minutes"] for a, b in zip(minutes, minutes[1:])),
            "source minute timestamps are not ordered")
    summary = {
        "source_index": index,
        "counts": {key: count[key] for key in
                   ("generated", "admitted", "finalized_success", "finalized_error", "admission_errors")},
        "requested_seconds": source["requested_continuous_seconds"],
        "elapsed_including_drain_seconds": source["elapsed_including_drain_seconds"],
        "first_admission_elapsed_seconds": source["first_admission_unix_ms"] / 1000 - start,
        "last_admission_elapsed_seconds": source["last_admission_unix_ms"] / 1000 - start,
        "admission_span_seconds": (source["last_admission_unix_ms"] - source["first_admission_unix_ms"]) / 1000,
        "admission_span_seconds_monotonic": source.get("admission_span_seconds_monotonic"),
        "largest_admission_gap_seconds": source["largest_admission_gap_ms"] / 1000,
        "maximum_outstanding_observed": source["maximum_outstanding_observed"],
        "outstanding_bound": request["max_outstanding"],
        "connections": request["connections"],
        "signing_threads": request["signing_threads"],
        "batch_size": request["batch_size"],
        "status_poll_ms": request["status_poll_ms"],
        "compute_unit_limit": request["compute_unit_limit"],
        "recipient_count": request["recipient_count"],
        "phases": phases(request),
        "latency": latency_counts(count),
        "minute_observations": minutes,
    }

    if "rpc_transport_retry_metrics" in source:
        metrics = source["rpc_transport_retry_metrics"]
        keys = ("requests", "attempts", "transient_errors", "recovered_requests", "failed_requests",
                "maximum_attempts", "total_budget_ms", "attempt_timeout_ms", "backoff_ms")
        require(all(isinstance(metrics.get(key), int) and metrics[key] >= 0 for key in keys),
                "RPC transport retry metric shape")
        summary["rpc_transport_retries"] = {key: metrics[key] for key in keys}
    if "pipelined_status_observation" in source:
        observer = source["pipelined_status_observation"]
        metrics = observer["metrics"]
        keys = ("started", "completed", "rpc_milliseconds_total", "rpc_milliseconds_max",
                "maximum_inflight_jobs", "maximum_inflight_ids", "requested_ids", "minimum_batch_ids",
                "maximum_batch_ids", "null_rows", "finalized_rows", "transport_retry_errors",
                "transport_recovered_jobs")
        retained = {key: metrics[key] for key in keys if key in metrics}
        require(all(value is None or isinstance(value, int) and value >= 0 for value in retained.values()),
                "status observation metric shape")
        endpoints = metrics.get("requests_per_endpoint", [])
        require(all(isinstance(value, int) and value >= 0 for value in endpoints), "status endpoint metric shape")
        retained["requests_per_endpoint"] = endpoints
        if metrics.get("started", 0) and "requested_ids" in metrics:
            retained["mean_requested_ids_per_job"] = metrics["requested_ids"] / metrics["started"]
        observed = metrics.get("null_rows", 0) + metrics.get("finalized_rows", 0)
        if observed:
            retained["null_fraction_of_recorded_rows"] = metrics.get("null_rows", 0) / observed
        summary["status_observer"] = retained
    return summary


def interpolate(points, timestamp):
    times = [point[0] for point in points]
    index = bisect.bisect_right(times, timestamp)
    if index == 0 or index == len(points):
        return points[0][1] if timestamp == times[0] else points[-1][1] if timestamp == times[-1] else None
    left, right = points[index - 1], points[index]
    return left[1] + (right[1] - left[1]) * (timestamp - left[0]) / (right[0] - left[0])


def rooted_series(path, start, end, baseline, validators):
    observations = []
    unavailable = 0
    maximum_gaps = []
    for line in path.open():
        row = json.loads(line)
        timestamp = row["wall_ms"] / 1000
        peers = row["validators"]
        if len(peers) != validators or any(not isinstance(peer.get("finalized_transactions"), int) for peer in peers):
            unavailable += 1
            observations.append((timestamp, None))
            continue
        count = min(peer["finalized_transactions"] for peer in peers) - baseline
        require(count >= 0, "rooted monitor count predates the run baseline")
        observations.append((timestamp, count))
    require(observations and all(a[0] < b[0] for a, b in zip(observations, observations[1:])),
            "rooted monitor timestamps are not ordered")
    valid = [(t, count) for t, count in observations if count is not None]
    require(all(a[1] <= b[1] for a, b in zip(valid, valid[1:])), "rooted monitor counter decreased")
    require(len(valid) >= 2 and observations[0][0] < end and observations[-1][0] > start,
            "rooted monitor does not overlap the traffic interval")
    interval = []
    for left, right in zip(observations, observations[1:]):
        dt = right[0] - left[0]
        maximum_gaps.append(dt)
        if start <= left[0] < right[0] <= end:
            known = left[1] is not None and right[1] is not None and dt <= 30
            interval.append({"elapsed_minutes": (right[0] - start) / 60,
                             "interval_seconds": dt,
                             "transactions_per_second": (right[1] - left[1]) / dt if known else None})
    rolling = []
    for timestamp, count in valid:
        if start + 60 <= timestamp <= end:
            previous = interpolate(valid, timestamp - 60)
            unknown = any(timestamp - 60 <= t <= timestamp and value is None for t, value in observations)
            large_gap = any(timestamp - 60 < b[0] and a[0] < timestamp and b[0] - a[0] > 30
                            for a, b in zip(observations, observations[1:]))
            rolling.append({"elapsed_minutes": (timestamp - start) / 60,
                            "transactions_per_second": (count - previous) / 60
                            if previous is not None and not unknown and not large_gap else None})
    return {
        "measurement": "Derivative of the minimum finalized transaction counter across all eight native validators; excludes the pre-run baseline",
        "monitor_samples": len(observations), "unavailable_samples": unavailable,
        "monitor_covers_entire_traffic_interval": observations[0][0] <= start and observations[-1][0] >= end,
        "unobserved_initial_seconds": max(0, observations[0][0] - start),
        "unobserved_terminal_seconds": max(0, end - observations[-1][0]),
        "maximum_monitor_gap_seconds": max(maximum_gaps, default=0),
        "approximately_10_second_intervals": interval,
        "trailing_60_second_intervals": rolling,
        "counter_observations": [{"elapsed_minutes": (t - start) / 60, "transactions": n}
                                 for t, n in observations if start <= t <= end],
        "counter_interpolation": "The trailing 60-second curve linearly interpolates the earlier approximately 10-second monitor counter; gaps over 30 seconds, unavailable samples and unobserved edges remain missing. No counters are extrapolated outside monitor coverage.",
    }


CONTROL_FIELDS = (
    "mempool", "mempool_bytes", "pending_parent_blocks", "pending_evidence",
    "pending_block_cursors", "candidate_banks", "invalid_packets", "send_queue_retries",
)
REPAIR_FIELDS = (
    "waiting_parent_bytes", "parent_requests", "responses", "pending_responses",
    "cache_bodies", "cache_bytes", "cache_limit_bytes", "durable_lookup_hints",
    "deferred_refetch_descriptors", "incomplete_assemblers", "incomplete_markers",
    "missing_queued_bodies", "missing_repair_fronts",
)


def control_values(status):
    """Retain numeric diagnostics only; identities and arbitrary strings stay private."""
    values = {key: status[key] for key in CONTROL_FIELDS if key in status}
    repair = status.get("repair", {})
    values.update({f"repair_{key}": repair[key] for key in REPAIR_FIELDS if key in repair})
    require(all(isinstance(value, int) and not isinstance(value, bool) and value >= 0
                for value in values.values()), "native control diagnostic shape")
    return values


def control_diagnostics(path, before, after, start, end):
    validators = len(before)
    require(len(after) == validators, "native diagnostic observation count mismatch")
    samples = [[] for _ in range(validators)]
    unavailable = 0
    for line in path.open():
        row = json.loads(line)
        if not start <= row["wall_ms"] / 1000 <= end:
            continue
        peers = row["validators"]
        if len(peers) != validators:
            unavailable += 1
            continue
        for index, peer in enumerate(peers):
            if isinstance(peer.get("finalized_transactions"), int):
                samples[index].append(control_values(peer))
            else:
                unavailable += 1
    per_node = []
    for index, (initial, final, observed) in enumerate(zip(before, after, samples)):
        initial, final = control_values(initial["status"]), control_values(final["status"])
        metrics = {}
        for key in sorted(initial.keys() | final.keys() | set().union(*(v.keys() for v in observed))):
            values = [v[key] for v in observed if key in v]
            metric = {"initial": initial.get(key), "final": final.get(key),
                      "monitor_sample_count": len(values),
                      "minimum_during_traffic": min(values) if values else None,
                      "maximum_during_traffic": max(values) if values else None}
            if key in ("invalid_packets", "send_queue_retries") and key in initial and key in final:
                require(final[key] >= initial[key], "native counter reset during fixed run")
                metric["baseline_to_final_delta"] = final[key] - initial[key]
            metrics[key] = metric
        per_node.append({"validator_index": index, "metrics": metrics})
    return {
        "scope": "Fixed-run baseline and final status snapshots plus approximately ten-second monitor samples during generation; instantaneous peaks between samples are not observed.",
        "unavailable_monitor_observations": unavailable,
        "repair_diagnostics_available": any(any(key.startswith("repair_") for key in node["metrics"]) for node in per_node),
        "counter_qualification": "Invalid-packet and queue-retry deltas span baseline through final drain. They are distinct from source admission/onchain errors; frozen INFO logs do not provide a reason for every invalid packet.",
        "per_validator": per_node,
    }


def counter_delta(left, right, group, field):
    if not left.get("counter_available", {}).get(group) or not right.get("counter_available", {}).get(group):
        return None
    a, b = left.get(group), right.get(group)
    if a is None or b is None or a.keys() != b.keys():
        return None
    deltas = [b[key][field] - a[key][field] for key in a]
    return sum(deltas) if all(value >= 0 for value in deltas) else None


def resource_intervals(document, start, end):
    samples = document["samples"]
    require(len(samples) >= 2 and all(a["wall_seconds"] < b["wall_seconds"] for a, b in zip(samples, samples[1:])),
            "resource timestamps are not ordered")
    require(samples[0]["wall_seconds"] <= start and samples[-1]["wall_seconds"] >= end,
            "resource samples do not cover traffic")
    rows = []
    discontinuities = 0
    for left, right in zip(samples, samples[1:]):
        ta, tb = left["wall_seconds"], right["wall_seconds"]
        if not start <= ta < tb <= end:
            continue
        dt = tb - ta
        row = {"start_elapsed_seconds": ta - start, "end_elapsed_seconds": tb - start, "seconds": dt}
        for group, field, metric in (
            ("network", "rx_bytes", "host_rx_MBps"), ("network", "tx_bytes", "host_tx_MBps"),
            ("disk", "read_bytes", "host_disk_read_MBps"), ("disk", "write_bytes", "host_disk_write_MBps"),
            ("disk", "busy_ms", "host_disk_busy_percent"),
        ):
            delta = counter_delta(left, right, group, field)
            row[metric] = delta / dt / (10 if field == "busy_ms" else 1_000_000) if delta is not None else None
        cpu_a, cpu_b = left.get("cpu_jiffies"), right.get("cpu_jiffies")
        cpu = [b - a for a, b in zip(cpu_a, cpu_b)] if cpu_a and cpu_b and len(cpu_a) == len(cpu_b) >= 5 else None
        row["host_cpu_busy_percent"] = 100 * (sum(cpu) - cpu[3] - cpu[4]) / sum(cpu) if cpu and min(cpu) >= 0 and sum(cpu) > 0 else None
        available = right.get("memory", {}).get("MemAvailable")
        row["host_memory_available_GiB"] = available / 2 ** 30 if available is not None else None
        a, b = left.get("process"), right.get("process")
        same = a and b and (a["pid"], a.get("start_jiffies")) == (b["pid"], b.get("start_jiffies"))
        if a and b and not same:
            discontinuities += 1
        for metric in PROCESS_METRICS:
            row[metric] = None
        if same and b["cpu_seconds"] >= a["cpu_seconds"]:
            row["process_cpu_cores"] = (b["cpu_seconds"] - a["cpu_seconds"]) / dt
            row["process_rss_GiB"] = b["rss_bytes"] / 2 ** 30
            row["process_threads"] = b["threads"]
            if a.get("io") is not None and b.get("io") is not None:
                for field, metric in (("read_bytes", "process_read_MBps"), ("write_bytes", "process_write_MBps")):
                    delta = b["io"][field] - a["io"][field]
                    row[metric] = delta / dt / 1_000_000 if delta >= 0 else None
        rows.append(row)
    return rows, discontinuities


def resource_bins(rows, start, end, width=10):
    """Weighted rates, and max RSS/threads, per ten-second plot bin."""
    bins = {}
    for row in rows:
        first = int(row["start_elapsed_seconds"] // width)
        last = int(math.nextafter(row["end_elapsed_seconds"], -math.inf) // width)
        for bucket in range(first, last + 1):
            overlap = min(row["end_elapsed_seconds"], (bucket + 1) * width) - max(row["start_elapsed_seconds"], bucket * width)
            if overlap <= 0:
                continue
            values = bins.setdefault(bucket, {})
            for metric in PROCESS_METRICS + HOST_METRICS:
                value = row.get(metric)
                if value is None:
                    continue
                count, total, peak = values.get(metric, (0, 0, -math.inf))
                values[metric] = (count + overlap, total + value * overlap, max(peak, value))
    output = []
    for bucket, values in sorted(bins.items()):
        item = {"elapsed_minutes": min((bucket + .5) * width, end - start) / 60}
        for metric in PROCESS_METRICS + HOST_METRICS:
            value = values.get(metric)
            item[metric] = (value[2] if metric in ("process_rss_GiB", "process_threads") else value[1] / value[0]) if value else None
        output.append(item)
    return output


def require_owned_resource_continuity(document, start, end, expected=None):
    """Endpoint coverage cannot hide a missing or changed process in the middle."""
    samples = document["samples"]
    relevant = [sample for sample in samples if start <= sample["wall_seconds"] <= end]
    if expected is not None:
        require(samples[0]["wall_seconds"] <= start and samples[-1]["wall_seconds"] >= end,
                "resource stream does not bracket admissions")
        require(relevant and relevant[0]["wall_seconds"] - start <= 5
                and end - relevant[-1]["wall_seconds"] <= 5,
                "owned resource admission boundary exceeds five seconds")
    identity = None
    previous_cpu = None
    for sample in relevant:
        require(not sample.get("errors"), "resource observation contains an error")
        process = sample.get("process")
        require(isinstance(process, dict)
                and all(isinstance(process.get(key), int)
                        and not isinstance(process[key], bool) and process[key] >= 0
                        for key in ("pid", "start_jiffies", "rss_bytes", "threads"))
                and isinstance(process.get("cpu_seconds"), (int, float))
                and not isinstance(process["cpu_seconds"], bool)
                and math.isfinite(process["cpu_seconds"]) and process["cpu_seconds"] >= 0,
                "owned resource process missing or malformed during traffic")
        current = (process["pid"], process["start_jiffies"])
        if identity is None:
            identity = current
        require(current == identity, "owned resource process changed during traffic")
        require(previous_cpu is None or process["cpu_seconds"] >= previous_cpu,
                "owned resource CPU counter reset during traffic")
        previous_cpu = process["cpu_seconds"]
        if expected is not None:
            require(current == (expected["pid"], expected["start_jiffies"]),
                    "owned resource process differs from captured operating point")
            require(all(process.get(field) == expected[field] for field in
                        ("executable_sha384", "configuration_sha384", "argv_sha384")),
                    "owned resource pin differs from captured operating point")
            require(isinstance(process.get("io"), dict)
                    and all(type(process["io"].get(field)) is int and process["io"][field] >= 0
                            for field in ("read_bytes", "write_bytes"))
                    and all(sample.get("counter_available", {}).get(field) is True
                            for field in ("network", "disk"))
                    and len(sample.get("cpu_jiffies", [])) == 8
                    and "MemAvailable" in sample.get("memory", {})
                    and sample.get("network") and sample.get("disk"),
                    "owned or host resource counters missing during admissions")
    require(relevant, "no owned resource observations during traffic")
    if expected is not None:
        require(relevant[-1]["wall_seconds"] - relevant[0]["wall_seconds"] >= 3600,
                "owned process observation span is shorter than one hour")
        for left, right in zip(relevant, relevant[1:]):
            wall_gap = right["wall_seconds"] - left["wall_seconds"]
            require(finite_number(left.get("monotonic_seconds"))
                    and finite_number(right.get("monotonic_seconds")),
                    "monotonic resource timestamps missing")
            mono_gap = right["monotonic_seconds"] - left["monotonic_seconds"]
            require(0 < wall_gap <= 5 and 0 < mono_gap <= 5 and abs(wall_gap - mono_gap) <= 1,
                    "resource sampling gap or clock jump during admissions")
            require(all(right["process"]["io"][field] >= left["process"]["io"][field]
                        for field in ("read_bytes", "write_bytes")),
                    "owned process IO counter reset during admissions")


def summarize_resources(directory, validators, start, end, hashes, expected=None, admission_start=None):
    output = []
    for index in range(validators + 2):
        path = directory / f"node-{index}.json"
        document = read_json(path)
        require_owned_resource_continuity(document, start if admission_start is None else admission_start,
                                          end, expected[index] if expected is not None else None)
        rows, discontinuities = resource_intervals(document, start, end)
        require(rows, "no resource intervals inside traffic")
        hashes[f"resource_node_{index}"] = digest(path)
        metrics = {}
        for metric in PROCESS_METRICS + HOST_METRICS:
            present = [row for row in rows if row.get(metric) is not None]
            metrics[metric] = stats([row[metric] for row in present], [row["seconds"] for row in present])
        output.append({
            "node_index": index, "role": "validator" if index < validators else "generator",
            "role_index": index if index < validators else index - validators,
            "logical_cpu_count": document["logical_cpus"],
            "resource_samples": len(document["samples"]),
            "whole_interval_observed_seconds": sum(row["seconds"] for row in rows),
            "owned_process_observed_seconds": sum(row["seconds"] for row in rows if row["process_cpu_cores"] is not None),
            "pid_discontinuities": discontinuities,
            "metrics": metrics, "ten_second_plot_bins": resource_bins(rows, start, end),
        })
    return output


def public_safe(value):
    """Final defense; the report is built from explicit numeric whitelists."""
    text = json.dumps(value, allow_nan=False)
    require(not re.search(r"(?:\d{1,3}\.){3}\d{1,3}", text), "IP address reached public output")
    require(not any(token in text for token in ("/home/", "PRIVATE KEY", "private_key", "rpc_url", "manifest_path")),
            "private context reached public output")


def background_inventory(directory, hashes):
    """Normalize the older genesis inventory and the full-account RPC audit."""
    path = directory / "starting-state-inventory.json"
    if path.exists():
        inventory = read_json(path)
        count = inventory["background_account_count"]
        total = inventory["background_account_data_bytes"]
        observed = False
    else:
        path = directory / "background-before-load" / "summary.json"
        if not path.exists():
            return None
        inventory = read_json(path)
        require(inventory.get("read_only") is True
                and inventory.get("phase") == "baseline"
                and inventory.get("validator_count") == 8
                and inventory.get("all_nodes_full_records_match") is True,
                "all-eight baseline account inventory required")
        count = inventory["background_account_count"]
        total = inventory["total_data_bytes_per_validator"]
        each = inventory["data_bytes_per_account"]
        require(isinstance(each, int) and not isinstance(each, bool)
                and each > 0 and total == count * each,
                "background account-data total differs from inventory")
        observed = True
    require(isinstance(count, int) and not isinstance(count, bool) and count > 0
            and isinstance(total, int) and not isinstance(total, bool) and total > 0
            and total % count == 0, "background inventory shape")
    hashes["background_state_inventory"] = digest(path)
    return {"background_account_count": count, "background_account_data_bytes": total,
            "data_bytes_per_account": total // count,
            "all_eight_full_account_records_observed": observed}


def frozen_main_digest(frozen):
    # Release5 packages pin rebuilt Main/native Tool separately. The unchanged
    # dedicated traffic generator is pinned by the trial's launch provenance;
    # it must never be inferred from the newly rebuilt native Tool executable.
    value = frozen.get("main_sha384")
    if value is None:
        value = frozen.get("binary_files", {}).get("agave-validator", {}).get("sha384")
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{96}", value),
            "frozen validator binary digest missing")
    return value


def require_preserved_operating_points(proof, before, after, main_sha384):
    top_fields = ("genesis_hash", "source_sha384", "validator_binary_sha384")
    node_fields = ("node", "host", "config_sha384", "executable_sha384", "argv_sha384",
                   "rayon_global_threads", "parameters", "pid", "start_jiffies")
    require(proof.get("read_only") is True
            and proof.get("all8_actual_operating_points_preserved") is True
            and proof.get("no_owned_validator_restart") is True
            and set(top_fields + node_fields) <= set(proof.get("compared_fields", [])),
            "explicit operating-point preservation proof required")
    require(before.get("validator_binary_sha384") == main_sha384
            and all(before.get(field) is not None and before[field] == after.get(field)
                    for field in top_fields)
            and len(before.get("nodes", [])) == len(after.get("nodes", [])) == 8,
            "captured validator operating points differ")
    for index, (left, right) in enumerate(zip(before["nodes"], after["nodes"])):
        require(left.get("node") == right.get("node") == index
                and left.get("executable_sha384") == main_sha384
                and all(left.get(field) is not None and left[field] == right.get(field)
                        for field in node_fields),
                "captured validator process or parameters changed")


def completed_operational_contract(directory, label, binary_hashes, hashes, result):
    """Bind the strengthened hour gate to retained, pinned observations.

    Historical recordings without this later contract remain readable. A run
    carrying the contract cannot fall back to its controller's headline flag.
    Raw identities and manifests are used only for comparison, never exported.
    """
    helper_path = directory / label / "operational-helper-provenance.json"
    if not helper_path.exists():
        helper_path = directory / "retry2-operational-helper-provenance.json"
    if not helper_path.exists():
        return None, None
    helpers = read_json(helper_path)
    require(helpers.get("source_generator_requests_native_rust_and_binaries_unchanged") is True
            and helpers.get("main_sha384") == binary_hashes["main_sha384"]
            and helpers.get("generator_sha384") == binary_hashes["generator_sha384"],
            "operational acceptance helpers do not pin these binaries")
    helper_hashes = {entry["archived_name"]: entry["sha384"] for entry in helpers["files"]}
    require(len(helper_hashes) == len(helpers["files"])
            and all(re.fullmatch(r"[A-Za-z0-9_-]+\.py", name)
                    and re.fullmatch(r"[0-9a-f]{96}", value)
                    for name, value in helper_hashes.items()), "operational helper digest shape")
    require(helper_hashes.get("soak-cluster.py") == binary_hashes["controller_sha384"],
            "operational acceptance controller pin differs")
    require(helpers.get("maximum_allowed_sampling_gap_seconds") == 5
            and helpers.get("owned_boundary_tolerance_seconds") == 5
            and helpers.get("required_wall_and_monotonic_admission_seconds") == 3600,
            "operational acceptance bounds differ")
    proof_path = directory / f"{label}-operating-point-preservation.json"
    before_path, after_path = [directory / f"stage-{label}-{phase}.json" for phase in ("before", "after")]
    proof, before, after = [read_json(path) for path in (proof_path, before_path, after_path)]
    require(proof.get("before_sha384") == digest(before_path)
            and proof.get("after_sha384") == digest(after_path),
            "operating-point preservation capture digest differs")
    require_preserved_operating_points(proof, before, after, binary_hashes["main_sha384"])
    running_path = directory / f"{label}-generator-running.json"
    running = read_json(running_path)
    require(running.get("running_executable_and_exact_requests_verified") is True
            and len(running.get("nodes", [])) == 2, "captured traffic generator identities required")
    expected = [{"pid": node["pid"], "start_jiffies": node["start_jiffies"],
                 "executable_sha384": node["executable_sha384"],
                 "configuration_sha384": node["config_sha384"], "argv_sha384": node["argv_sha384"]}
                for node in before["nodes"]]
    for index, node in enumerate(running["nodes"]):
        require(node["generator_sha384"] == binary_hashes["generator_sha384"]
                and node["request_sha384"] == hashes[f"source_{index}_request"],
                "captured traffic generator binary or request differs")
        expected.append({"pid": node["pid"], "start_jiffies": node["start_tick"],
                         "executable_sha384": node["generator_sha384"],
                         "configuration_sha384": node["request_sha384"], "argv_sha384": node["argv_sha384"]})
    windows = result.get("resource_windows", [])
    require(len(windows) == 10 and all(window.get("node") == index
            and window.get("covers_traffic") is True
            and window.get("all_in_traffic_samples_pinned_and_uninterrupted") is True
            and window.get("failures") == [] and window.get("owned_process_covers_hour") is True
            and finite_number(window.get("owned_process_observed_seconds"))
            and window["owned_process_observed_seconds"] >= 3600
            for index, window in enumerate(windows)),
            "all ten uninterrupted pinned resource windows required")
    acceptance_path = directory / f"{label}-full-state-acceptance.json"
    acceptance = read_json(acceptance_path)
    require(acceptance.get("read_only") is True
            and acceptance.get("script_sha384") == helper_hashes.get(f"post-{label}.py")
            and all(acceptance.get(field) is True for field in
                    ("continuous_source_resource_gate_passed", "native_count_all8_passed",
                     "clock_observation_preserved", "stage_running_binary_parameters_preserved")),
            "completed full-state and operating-point acceptance required")
    protected, background = acceptance["protected_records"], acceptance["background"]
    require(protected.get("all_validator_full_records_match") is True
            and protected.get("all_expected_full_records_match") is True
            and protected.get("exact_all_metadata_and_full_bytes") is True
            and protected.get("unexpected_account_count") == 0
            and protected.get("validators") == 8
            and protected.get("requests_match_pre_hour_operating_point") is True
            and protected.get("total_committed_source_transactions") == result["finalized_success"]
            and background.get("all_nodes_full_records_match") is True
            and background.get("all_background_accounts_unchanged_from_baseline") is True
            and background.get("validator_count") == 8,
            "all-eight full protected and background state audits required")
    ranges = protected.get("source_ranges", [])
    require(len(ranges) == 2 and all(row.get("immutable_request_sha384") == hashes[f"source_{index}_request"]
            and row.get("source_result_sha384") == hashes[f"source_{index}_result"]
            for index, row in enumerate(ranges)), "full-state audit source artifacts differ")
    for name, path in (("operational_helper_provenance", helper_path),
                       ("operating_point_preservation", proof_path), ("stage_before", before_path),
                       ("stage_after", after_path), ("generator_running", running_path),
                       ("completed_full_state_acceptance", acceptance_path)):
        hashes[name] = digest(path)
    return expected, {
        "explicit_before_after_operating_points_preserved": True,
        "no_owned_validator_restart": True,
        "all_ten_resource_windows_pinned_and_uninterrupted": True,
        "maximum_allowed_sampling_gap_seconds": 5,
        "owned_boundary_tolerance_seconds": 5,
        "required_wall_and_monotonic_admission_seconds": 3600,
        "all_eight_protected_full_account_records_match": True,
        "all_eight_background_full_account_records_unchanged": True,
        "helper_sha384": helper_hashes,
    }


def build_report(directory, label, allow_pilot=False):
    run = directory / label
    paths = [directory / f"{label}-source-{index}.json" for index in range(2)]
    request_paths = [directory / f"{label}-source-{index}-request.json" for index in range(2)]
    sources = [read_json(path) for path in paths]
    requests = [read_json(path) for path in request_paths]
    result = read_json(run / "soak-result.json")
    hour = check_acceptance(result, sources, allow_pilot)
    validators = result["validator_count"]
    require(validators == 8 and result["generator_count"] == 2, "report expects eight validators and two generators")
    before, after = [read_json(run / name) for name in ("soak-balances-before.json", "soak-balances-after.json")]
    require(len(before) == len(after) == validators, "native final observation count mismatch")
    baseline = before[0]["status"]["finalized_transactions"]
    require(all(row["status"]["finalized_transactions"] == baseline for row in before),
            "native baseline transaction counts differ")
    expected = baseline + result["finalized_success"]
    require(all(row["status"]["finalized_transactions"] == expected for row in after),
            "every native validator must finalize the exact expected count")
    require(all(row["system"] == result["expected_system_balances"] and row["token"] == result["expected_token_balances"] for row in after),
            "native final balances differ from exact expected assets")
    start = min(source["started_unix_ms"] for source in sources) / 1000
    traffic_end = max(source["last_admission_unix_ms"] for source in sources) / 1000
    completed = max(source["completed_unix_ms"] for source in sources) / 1000
    require(start < traffic_end <= completed, "traffic timeline order")
    hashes = {"controller_result": digest(run / "soak-result.json"),
              "rooted_monitor": digest(run / "soak-monitor.jsonl")}
    for index in range(2):
        hashes[f"source_{index}_result"] = digest(paths[index])
        hashes[f"source_{index}_request"] = digest(request_paths[index])
    # Local proposal tuning may restart the same ledger with a later binary.
    # A retained trial must use its launch pin, even after the global run pin
    # advances to the next release. Older recordings retain the global fallback.
    frozen_path = run / "frozen-provenance.json"
    if not frozen_path.exists():
        frozen_path = directory / "frozen-provenance.json"
    if hour:
        candidates = (run / "operating-point.json", directory / f"{label}-operating-point.json",
                      directory / "hour-operating-point.json")
        operating_path = next((path for path in candidates if path.exists()), candidates[0])
    else:
        operating_path = run / "soak-provenance.json"
    if not operating_path.exists():
        operating_path = frozen_path
    operating = read_json(operating_path)
    generator_command = "soak"
    if hour:
        binary_hashes = {key: operating[key] for key in ("main_sha384", "generator_sha384", "controller_sha384")}
        source_launch_path = run / "soak-provenance.json"
        if source_launch_path.exists():
            source_launch = read_json(source_launch_path)
            require(source_launch["generator_binary_sha384"] == binary_hashes["generator_sha384"],
                    "hour source binary differs from operating point")
            require(source_launch["controller_sha384"] == binary_hashes["controller_sha384"],
                    "hour source controller differs from operating point")
            generator_command = source_launch["generator_command"]
            require(generator_command in ("soak", "soak-pipelined"), "unknown generator command")
            hashes["source_launch_provenance"] = digest(source_launch_path)
        for index, source in enumerate(operating["sources"]):
            require(source["request_sha384"] == hashes[f"source_{index}_request"], "operating-point source request changed")
    elif "generator_binary_sha384" in operating:
        frozen = read_json(frozen_path)
        binary_hashes = {"main_sha384": frozen_main_digest(frozen),
                         "generator_sha384": operating["generator_binary_sha384"],
                         "controller_sha384": operating["controller_sha384"]}
        generator_command = operating["generator_command"]
        require(generator_command in ("soak", "soak-pipelined"), "unknown generator command")
    else:
        binary_hashes = {"main_sha384": operating["main_sha384"], "generator_sha384": operating["tool_sha384"]}
    require(all(re.fullmatch(r"[0-9a-f]{96}", value) for value in binary_hashes.values()), "binary digest shape")
    hashes["operating_point"] = digest(operating_path)
    resource_expected, operational_contract = completed_operational_contract(
        directory, label, binary_hashes, hashes, result) if hour else (None, None)
    admission_start = min(source["first_admission_unix_ms"] for source in sources) / 1000
    manifest = read_json(directory / "manifest.json")
    config_path = Path(manifest["nodes"][0]["config"])
    config = read_json(config_path)
    cutoff = manifest["cutoff_slot"]
    before_slots = [row["status"]["slot"] for row in before]
    after_slots = [row["status"]["slot"] for row in after]
    authentication_period = "post-cutoff" if min(before_slots) >= cutoff else "pre-cutoff" if max(after_slots) < cutoff else "crosses-cutoff"
    report = {
        "format": "native-agave-pq-completed-traffic-v1", "run_label": label,
        "scope": "Completed continuous hour of native Agave Bank/SVM traffic" if hour else "Completed short native Agave pilot; this is not hour evidence",
        "hour_acceptance_passed": hour, "requested_seconds": result["requested_continuous_seconds"],
        "validator_count": validators, "generator_count": 2,
        "native_baseline_finalized_transactions": baseline,
        "native_finalized_transactions_after_run": expected,
        "finalized_success": result["finalized_success"],
        "finalized_error": result["finalized_error"], "admission_errors": result["admission_errors"],
        "all_native_transaction_counts_reconciled": True,
        "all_expected_recipient_assets_match": True,
        "joint_source_interval_including_drain_seconds": result["generator_joint_interval_including_drain_seconds"],
        "joint_source_observed_finalized_success_tps": result["joint_finalized_success_tps"],
        "traffic_interval_seconds": traffic_end - start,
        "source_completion_elapsed_seconds": completed - start,
        "all_resource_samplers_cover_traffic_interval": True,
        "authentication_period": authentication_period,
        "cutoff_slot": cutoff,
        "baseline_root_slot_range": [min(before_slots), max(before_slots)],
        "final_observed_root_slot_range": [min(after_slots), max(after_slots)],
        "native_configuration": {key: config[key] for key in
                                 ("slot_count", "first_slot", "window_size", "block_time_ms", "network_delay_ms", "max_transactions", "target_block_bytes")},
        "binary_provenance": binary_hashes,
        "generator_command": generator_command,
        "input_sha384": hashes,
        "sources": [source_summary(index, source, requests[index], start) for index, source in enumerate(sources)],
        "native_rooted_throughput": rooted_series(run / "soak-monitor.jsonl", start, traffic_end, baseline, validators),
        "native_control_and_repair": control_diagnostics(run / "soak-monitor.jsonl", before, after, start, traffic_end),
        "resources": summarize_resources(run / "resources-soak", validators, start, traffic_end, hashes,
                                          resource_expected, admission_start if resource_expected is not None else None),
        "units": {
            "cpu": "Busy logical CPU cores: 1.0 equals one fully busy logical CPU; not percent of all host CPUs",
            "rss": "GiB (2^30 bytes)", "io_rates": "MB/s (10^6 bytes per second)",
            "disk_busy": "Sum of per-device busy percent; may exceed 100 on multiple disks",
            "resource_mean": "Duration-weighted mean over complete approximately one-second intervals inside traffic",
            "resource_percentiles": "Percentiles of those approximately one-second samples",
            "resource_plots": "Ten-second weighted CPU/IO means and ten-second maximum RSS; missing counters remain missing",
            "process_io": "Linux /proc/PID/io read_bytes and write_bytes counters; distinct from logical transaction bytes and whole-device disk counters",
        },
        "qualifications": [
            "Source minute series use each generator's independent observation cadence; they are displayed separately and are not summed as synchronized one-minute throughput.",
            "Source latency measures generation/reservation through exact finalized-status observation. Native execution, polling, pending scans and audits contribute; it is not isolated consensus latency.",
            "Process CPU/RSS/physical IO identify the sampled owned process. Network, disk busy, aggregate host CPU and available host memory include other workloads.",
            "No same-duration stock Agave baseline is implied by these measurements.",
            "The configured Ax epoch is finite; this report does not demonstrate automatic epoch rollover or production-scale account state.",
        ],
    }
    inventory = background_inventory(directory, hashes)
    if inventory is not None:
        report["background_state_inventory"] = inventory
    if operational_contract is not None:
        require(read_json(directory / f"{label}-full-state-acceptance.json")["native_total_transactions"] == expected,
                "completed full-state acceptance native count differs")
        report["completed_operational_acceptance"] = operational_contract
    public_safe(report)
    return report


def render(report, output):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
                         "svg.fonttype": "none", "figure.facecolor": "white"})
    minutes = report["traffic_interval_seconds"] / 60
    scope = "Completed hour" if report["hour_acceptance_passed"] else "Short pilot"
    title = f"{scope}: native Agave PQ traffic ({minutes:.1f} minutes)"
    colors = list(plt.get_cmap("tab10").colors)
    def save(figure, name):
        figure.savefig(output / f"{name}.png", dpi=180, bbox_inches="tight",
                       metadata={"Software": "Native Agave measurement report"})
        figure.savefig(output / f"{name}.svg", bbox_inches="tight",
                       metadata={"Creator": "Native Agave measurement report", "Date": None})
        plt.close(figure)
    def axes_common(axes):
        for axis in axes.flat:
            axis.set_xlim(0, minutes)
            axis.grid(alpha=.2)
            axis.set_xlabel("Minutes since traffic generation began")
            axis.set_ylim(bottom=0)
    def line(axis, points, key, label, color, **kwargs):
        axis.plot([point["elapsed_minutes"] for point in points],
                  [point.get(key) if point.get(key) is not None else math.nan for point in points],
                  label=label, color=color, **kwargs)
    figure, axes = plt.subplots(2, 1, figsize=(12, 7), sharex=True, constrained_layout=True)
    native = report["native_rooted_throughput"]
    line(axes[0], native["approximately_10_second_intervals"], "transactions_per_second",
         "Native minimum across all 8 validators (~10 s intervals)", "#9db9cf", linewidth=.8)
    line(axes[0], native["trailing_60_second_intervals"], "transactions_per_second",
         "Native minimum across all 8 validators (trailing 60 s)", "#16547c", linewidth=2)
    axes[0].set_ylabel("Rooted transactions/s")
    axes[0].legend(loc="best", fontsize=8)
    axes[0].set_title("Native rooted counter measurements")
    for source in report["sources"]:
        kinds = sorted({phase["kind"] for phase in source["phases"]})
        workload = {"system_transfer": "System", "token_transfer": "SPL", "nonce_only": "SBF no-op"}
        label = f"Source {source['source_index']} ({'/'.join(workload[kind] for kind in kinds)}) observed minute TPS"
        line(axes[1], source["minute_observations"], "source_observed_tps", label,
             colors[source["source_index"]], marker="o", markersize=3)
    axes[1].set_ylabel("Observed transactions/s\nper source")
    axes[1].set_title("Separate client observations; includes status polling and audit effects")
    axes[1].legend(loc="best", fontsize=8)
    axes_common(axes)
    figure.suptitle(title)
    save(figure, "throughput")
    figure, axes = plt.subplots(2, 2, figsize=(13, 8), sharex=True, constrained_layout=True)
    for resource in report["resources"]:
        index = resource["role_index"]
        column = 0 if resource["role"] == "validator" else 1
        label = ("V" if column == 0 else "G") + str(index)
        line(axes[0, column], resource["ten_second_plot_bins"], "process_cpu_cores", label, colors[index], linewidth=1.2)
        line(axes[1, column], resource["ten_second_plot_bins"], "process_rss_GiB", label, colors[index], linewidth=1.2)
    for column, role in enumerate(("validators", "generators")):
        axes[0, column].set_title(f"Owned {role}: CPU (10 s means)")
        axes[0, column].set_ylabel("Busy logical CPU cores")
        axes[1, column].set_title(f"Owned {role}: RSS (10 s maximum)")
        axes[1, column].set_ylabel("Resident memory (GiB)")
        axes[0, column].legend(ncol=4 if column == 0 else 2, fontsize=8)
    axes_common(axes)
    figure.suptitle(title + " — owned process resources")
    save(figure, "process-resources")
    figure, axes = plt.subplots(2, 2, figsize=(13, 8), sharex=True, constrained_layout=True)
    plots = (("process_write_MBps", "Owned physical writes"), ("host_disk_write_MBps", "Host disk writes, including other workloads"),
             ("host_rx_MBps", "Host network RX, including other workloads"), ("host_tx_MBps", "Host network TX, including other workloads"))
    for axis, (metric, subtitle) in zip(axes.flat, plots):
        for resource in report["resources"]:
            index = resource["role_index"]
            generator = resource["role"] == "generator"
            label = ("G" if generator else "V") + str(index)
            line(axis, resource["ten_second_plot_bins"], metric, label, colors[index],
                 linewidth=1, linestyle="--" if generator else "-")
        axis.set_title(subtitle + " (10 s means)")
        axis.set_ylabel("MB/s (decimal)")
    axes[0, 0].legend(ncol=5, fontsize=8)
    axes_common(axes)
    figure.suptitle(title + " — IO and network")
    save(figure, "io-network")


def readme(report):
    title = "Completed native Agave hour" if report["hour_acceptance_passed"] else "Completed native Agave pilot — not hour evidence"
    text = [f"# {title}\n", f"Eight validators and two generators finalized **{report['finalized_success']:,}** transactions with zero admission or execution errors. Exact finalized counts and expected recipient assets reconcile across all eight native validators.\n",
            f"The requested generation interval was {report['requested_seconds']:,} seconds. Joint client completion including drain was {report['joint_source_interval_including_drain_seconds']:.3f} seconds: **{report['joint_source_observed_finalized_success_tps']:.2f} TPS**. This denominator includes observation and drain.\n",
            "`throughput.png` / `.svg` plots the derivative of the minimum finalized transaction counter across all eight validators. The separate source minute curves use independent observation intervals and are not summed. The trailing native 60-second curve interpolates between approximately 10-second monitor counters.\n",
            "`process-resources.png` / `.svg` shows owned validator and generator CPU/RSS over the whole traffic interval. One CPU core means one fully busy logical CPU. RSS uses binary GiB. `io-network.png` / `.svg` uses decimal MB/s; host network and disk counters include other workloads. Ten-second means smooth physical-write bursts; `summary.json` retains approximately one-second maxima.\n",
            "Latency is generation/reservation to source observation of exact finalized status. It includes status polling, pending scans and client audits and is not isolated native consensus latency. The p95 values are histogram bounds, not exact percentiles.\n"]
    text.append(f"Authentication period: **{report['authentication_period']}**. The native Bank-slot cutoff is {report['cutoff_slot']}; elapsed UTC time does not define activation.\n")
    if "background_state_inventory" in report:
        inventory = report["background_state_inventory"]
        text.append(f"Background state contains {inventory['background_account_count']:,} accounts and {inventory['background_account_data_bytes']:,} account-data bytes, in addition to the application, SPL and runtime accounts.\n")
    diagnostics = report["native_control_and_repair"]
    invalid = [node["metrics"]["invalid_packets"]["baseline_to_final_delta"]
               for node in diagnostics["per_validator"] if "invalid_packets" in node["metrics"]
               and "baseline_to_final_delta" in node["metrics"]["invalid_packets"]]
    if invalid:
        text.append(f"Native invalid-packet counter deltas range from {min(invalid):,} to {max(invalid):,} per validator ({sum(invalid):,} summed across validators). These counters are separate from the zero source admission/onchain errors. Detailed repair and queue diagnostics are in `summary.json`; INFO logs do not identify every rejection reason.\n")
    for source in report["sources"]:
        latency = source["latency"]
        upper = latency["p95_upper_exclusive_seconds"]
        bound = f"[{latency['p95_lower_inclusive_seconds']:.3f}, {upper:.3f}) seconds" if upper is not None else f"at least {latency['p95_lower_inclusive_seconds']:.3f} seconds"
        text.append(f"Source {source['source_index']}: {source['counts']['finalized_success']:,} successes, mean observed latency {latency['mean_seconds']:.3f} seconds, p95 in {bound}, maximum {latency['maximum_seconds']:.3f} seconds. Maximum outstanding {source['maximum_outstanding_observed']:,}/{source['outstanding_bound']:,}; largest admission gap {source['largest_admission_gap_seconds']:.3f} seconds.\n")
    text.extend(["The immutable provisioned Ax epoch is finite. These measurements do not establish automatic rollover, production-scale account state, or a same-duration default Agave comparison.\n",
                 "`summary.json` contains numerical phase settings, recorded binary hashes and SHA384 digests of private input artifacts. Raw manifests, addresses, credentials, paths and error messages are excluded.\n",
                 f"Reproduce with Matplotlib installed:\n\n```sh\npython3 pq-crypto/tools/report-soak.py --manifest-directory RUN_DIRECTORY --run-label {report['run_label']} --output REPORT_DIRECTORY" + ("" if report["hour_acceptance_passed"] else " --allow-pilot") + "\n```\n\nA completed short run requires `--allow-pilot` and produces explicit pilot labels. The exporter performs no remote calls or mutations of its inputs.\n"])
    return "\n".join(text)


class ReportTests(unittest.TestCase):
    def test_preservation_flag_cannot_substitute_for_captured_process_and_parameters(self):
        main = "1" * 96
        node_fields = ("node", "host", "config_sha384", "executable_sha384", "argv_sha384",
                       "rayon_global_threads", "parameters", "pid", "start_jiffies")
        top_fields = ("genesis_hash", "source_sha384", "validator_binary_sha384")
        before = {"genesis_hash": "genesis", "source_sha384": "2" * 96,
                  "validator_binary_sha384": main, "nodes": [{
                      "node": i, "host": f"private-host-{i}", "config_sha384": "3" * 96,
                      "executable_sha384": main, "argv_sha384": "4" * 96,
                      "rayon_global_threads": 8, "parameters": {"execution_threads": 8},
                      "pid": i + 10, "start_jiffies": 100,
                  } for i in range(8)]}
        proof = {"read_only": True, "all8_actual_operating_points_preserved": True,
                 "no_owned_validator_restart": True, "compared_fields": top_fields + node_fields}
        after = json.loads(json.dumps(before))
        require_preserved_operating_points(proof, before, after, main)
        for field, value in (("pid", 99), ("argv_sha384", "5" * 96),
                             ("parameters", {"execution_threads": 16}), ("rayon_global_threads", 16)):
            changed = json.loads(json.dumps(after))
            changed["nodes"][3][field] = value
            with self.assertRaisesRegex(ValueError, "process or parameters changed"):
                require_preserved_operating_points(proof, before, changed, main)
        proof["no_owned_validator_restart"] = False
        with self.assertRaisesRegex(ValueError, "preservation proof"):
            require_preserved_operating_points(proof, before, after, main)

    def test_hour_resource_clock_and_process_pins_are_checked_inside_entire_window(self):
        expected = {"pid": 10, "start_jiffies": 20, "executable_sha384": "1" * 96,
                    "configuration_sha384": "2" * 96, "argv_sha384": "3" * 96}
        document = {"samples": [{
            "wall_seconds": t, "monotonic_seconds": t + 9000, "errors": [],
            "process": {**expected, "cpu_seconds": t, "rss_bytes": 100, "threads": 2,
                        "io": {"read_bytes": 0, "write_bytes": t}},
            "counter_available": {"network": True, "disk": True},
            "cpu_jiffies": [0] * 8, "memory": {"MemAvailable": 1},
            "network": {"link": {}}, "disk": {"device": {}},
        } for t in range(3603)]}
        require_owned_resource_continuity(document, 0, 3602, expected)
        middle = document["samples"][1800]
        middle["process"]["executable_sha384"] = "9" * 96
        with self.assertRaisesRegex(ValueError, "pin differs"):
            require_owned_resource_continuity(document, 0, 3602, expected)
        middle["process"]["executable_sha384"] = expected["executable_sha384"]
        middle["monotonic_seconds"] += 30
        with self.assertRaisesRegex(ValueError, "sampling gap or clock jump"):
            require_owned_resource_continuity(document, 0, 3602, expected)
        middle["monotonic_seconds"] -= 30
        middle["process"]["io"] = None
        with self.assertRaisesRegex(ValueError, "resource counters missing"):
            require_owned_resource_continuity(document, 0, 3602, expected)

    def test_monotonic_hour_span_cannot_be_replaced_by_wall_clock_span(self):
        counts = {"generated": 20, "admitted": 20, "finalized_success": 20,
                  "finalized_error": 0, "admission_errors": 0,
                  "latency_millis_total": 20, "latency_millis_max": 1,
                  "latency_buckets": [0, 20] + [0] * 30}
        source = {"actual_agave_rpc": True, "actual_bank_svm": True,
                  "requested_continuous_seconds": 3660, "pending": 0, "failure": None,
                  "counts": counts, "all_validator_recipient_balances_match": True,
                  "first_admission_unix_ms": 0, "last_admission_unix_ms": 3660000,
                  "admission_span_seconds_monotonic": 3599.0, "largest_admission_gap_ms": 1000}
        result = {"actual_agave_validator": True, "valid": True,
                  "all_expected_recipient_assets_match": True,
                  "all_resources_cover_traffic_interval": True,
                  "requested_continuous_seconds": 3660, "hour_acceptance_passed": True,
                  "finalized_success": 20, "finalized_error": 0, "admission_errors": 0}
        with self.assertRaisesRegex(ValueError, "monotonic admission span"):
            check_acceptance(result, [source], False)
        source["admission_span_seconds_monotonic"] = 3660.0
        self.assertTrue(check_acceptance(result, [source], False))

    def test_resource_endpoints_cannot_hide_interior_process_holes_or_errors(self):
        document = {"samples": [{"wall_seconds": t, "errors": [], "process": {
            "pid": 20, "start_jiffies": 5, "cpu_seconds": float(t),
            "rss_bytes": 100, "threads": 2,
        }} for t in range(5)]}
        require_owned_resource_continuity(document, .5, 3.5)
        process = document["samples"][2]["process"]
        document["samples"][2]["process"] = None
        with self.assertRaisesRegex(ValueError, "process missing"):
            require_owned_resource_continuity(document, .5, 3.5)
        document["samples"][2]["process"] = process
        document["samples"][2]["errors"] = ["a latched error"]
        with self.assertRaisesRegex(ValueError, "contains an error"):
            require_owned_resource_continuity(document, .5, 3.5)
        document["samples"][2]["errors"] = []
        process["start_jiffies"] += 1
        with self.assertRaisesRegex(ValueError, "process changed"):
            require_owned_resource_continuity(document, .5, 3.5)

    def test_release5_native_tool_pin_is_not_the_dedicated_source_generator(self):
        main = "1" * 96
        self.assertEqual(frozen_main_digest({"main_sha384": main}), main)
        self.assertEqual(frozen_main_digest({"binary_files": {
            "agave-validator": {"sha384": main}, "agave-pq-tool": {"sha384": "2" * 96},
        }}), main)
        with self.assertRaisesRegex(ValueError, "validator binary digest missing"):
            frozen_main_digest({"binary_files": {"agave-pq-tool": {"sha384": "2" * 96}}})

    def test_control_diagnostics_keep_exact_deltas_and_only_numeric_whitelist(self):
        before = [{"status": {"invalid_packets": 3, "send_queue_retries": 7,
                              "repair": {"cache_bytes": 0, "cache_limit_bytes": 67108864}}}]
        after = [{"status": {"invalid_packets": 5, "send_queue_retries": 11,
                             "repair": {"cache_bytes": 0, "cache_limit_bytes": 67108864}}}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "monitor.jsonl"
            path.write_text(json.dumps({"wall_ms": 1000, "validators": [{
                "finalized_transactions": 1, "invalid_packets": 4,
                "send_queue_retries": 9, "mempool": 20,
                "validator": "private-identity", "private_key": "/home/sol/credential",
                "repair": {"cache_bytes": 60000000, "cache_limit_bytes": 67108864,
                           "parent_requests": 8, "deferred_refetch_descriptors": 32,
                           "incomplete_assemblers": 16, "incomplete_markers": 14,
                           "missing_queued_bodies": 5, "missing_repair_fronts": 2,
                           "private_path": "/home/sol/secret"},
            }]}) + "\n")
            result = control_diagnostics(path, before, after, 0, 2)
            metrics = result["per_validator"][0]["metrics"]
            self.assertEqual(metrics["invalid_packets"]["baseline_to_final_delta"], 2)
            self.assertEqual(metrics["send_queue_retries"]["baseline_to_final_delta"], 4)
            self.assertEqual(metrics["repair_cache_bytes"]["maximum_during_traffic"], 60000000)
            self.assertEqual(metrics["repair_deferred_refetch_descriptors"]["maximum_during_traffic"], 32)
            self.assertEqual(metrics["repair_incomplete_assemblers"]["maximum_during_traffic"], 16)
            self.assertEqual(metrics["repair_incomplete_markers"]["maximum_during_traffic"], 14)
            self.assertEqual(metrics["repair_missing_queued_bodies"]["maximum_during_traffic"], 5)
            self.assertEqual(metrics["repair_missing_repair_fronts"]["maximum_during_traffic"], 2)
            self.assertTrue(result["repair_diagnostics_available"])
            public_safe(result)
            self.assertNotIn("private", json.dumps(result))
            after[0]["status"]["invalid_packets"] = 2
            with self.assertRaisesRegex(ValueError, "counter reset"):
                control_diagnostics(path, before, after, 0, 2)
        with self.assertRaisesRegex(ValueError, "diagnostic shape"):
            control_values({"repair": {"cache_bytes": "malformed"}})
        with self.assertRaisesRegex(ValueError, "diagnostic shape"):
            control_values({"repair": {"missing_repair_fronts": True}})

    def test_full_account_inventory_uses_total_bytes_and_rejects_failed_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "background-before-load" / "summary.json"
            path.parent.mkdir()
            audit = {"read_only": True, "phase": "baseline", "validator_count": 8,
                     "all_nodes_full_records_match": True, "background_account_count": 10000,
                     "data_bytes_per_account": 2048, "total_data_bytes_per_validator": 20480000}
            path.write_text(json.dumps(audit))
            hashes = {}
            summary = background_inventory(root, hashes)
            self.assertEqual(summary["background_account_data_bytes"], 20480000)
            self.assertEqual(summary["data_bytes_per_account"], 2048)
            self.assertTrue(summary["all_eight_full_account_records_observed"])
            self.assertEqual(hashes["background_state_inventory"], digest(path))
            audit["all_nodes_full_records_match"] = False
            path.write_text(json.dumps(audit))
            with self.assertRaisesRegex(ValueError, "all-eight baseline"):
                background_inventory(root, {})

    def test_truncated_monitor_keeps_unobserved_tail_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "monitor.jsonl"
            path.write_text("".join(json.dumps({
                "wall_ms": seconds * 1000,
                "validators": [{"finalized_transactions": count}] * 8,
            }) + "\n" for seconds, count in [(0, 10), (10, 20), (20, 40)]))
            series = rooted_series(path, 0, 40, 10, 8)
        self.assertFalse(series["monitor_covers_entire_traffic_interval"])
        self.assertEqual(series["unobserved_terminal_seconds"], 20)
        self.assertEqual([row["transactions_per_second"] for row in series["approximately_10_second_intervals"]], [1, 2])
        self.assertEqual(series["counter_observations"][-1]["transactions"], 30)
        self.assertEqual(series["counter_observations"][-1]["elapsed_minutes"], 20 / 60)
        self.assertIsNone(interpolate([(0, 10), (20, 40)], 40))

    def test_latency_exact_power_and_saturated_bucket(self):
        count = {"finalized_success": 20, "finalized_error": 0, "latency_millis_total": 20 * 1024,
                 "latency_millis_max": 1024, "latency_buckets": [0] * 32}
        count["latency_buckets"][11] = 20
        self.assertEqual(latency_counts(count)["p95_lower_inclusive_seconds"], 1.024)
        self.assertEqual(latency_counts(count)["p95_upper_exclusive_seconds"], 2.048)
        count["latency_buckets"][11] = 0
        count["latency_buckets"][31] = 20
        self.assertIsNone(latency_counts(count)["p95_upper_exclusive_seconds"])

    def test_unaccepted_hour_cannot_be_exported(self):
        result = {"actual_agave_validator": True, "valid": True, "all_expected_recipient_assets_match": True,
                  "all_resources_cover_traffic_interval": True, "requested_continuous_seconds": 3660,
                  "hour_acceptance_passed": False}
        with self.assertRaisesRegex(ValueError, "completed-hour acceptance"):
            check_acceptance(result, [], False)
        with self.assertRaisesRegex(ValueError, "restricted"):
            check_acceptance(result, [], True)

    def test_counter_reset_is_missing_and_pid_change_is_not_cpu(self):
        a = {"wall_seconds": 1, "process": {"pid": 2, "start_jiffies": 1, "cpu_seconds": 8},
             "network": {"bond0": {"rx_bytes": 200}}, "counter_available": {"network": True}}
        b = {"wall_seconds": 2, "process": {"pid": 3, "start_jiffies": 2, "cpu_seconds": 100},
             "network": {"bond0": {"rx_bytes": 100}}, "counter_available": {"network": True}}
        self.assertIsNone(counter_delta(a, b, "network", "rx_bytes"))
        # Only complete same-PID resource intervals may grant process metrics.
        for row in (a, b):
            row["network"]["bond0"].update(tx_bytes=0)
        rows, resets = resource_intervals({"samples": [a, b]}, 1, 2)
        self.assertEqual(resets, 1)
        self.assertIsNone(rows[0]["process_cpu_cores"])

    def test_duration_weighted_mean_and_decimal_io(self):
        self.assertEqual(stats([1, 3], [1, 3])["mean"], 2.5)
        rows = [{"start_elapsed_seconds": 0, "end_elapsed_seconds": 1, "process_write_MBps": 10,
                 "process_rss_GiB": 2},
                {"start_elapsed_seconds": 1, "end_elapsed_seconds": 4, "process_write_MBps": 20,
                 "process_rss_GiB": 3}]
        bucket = resource_bins(rows, 0, 4)[0]
        self.assertEqual(bucket["process_write_MBps"], 17.5)
        self.assertEqual(bucket["process_rss_GiB"], 3)

    def test_actual_resource_units_use_one_core_and_decimal_megabytes(self):
        samples = []
        for timestamp in (0, 1):
            samples.append({"wall_seconds": timestamp,
                            "process": {"pid": 2, "start_jiffies": 1, "cpu_seconds": timestamp,
                                        "rss_bytes": 2 ** 30, "threads": 3,
                                        "io": {"read_bytes": 0, "write_bytes": timestamp * 1_000_000}}})
        rows, _ = resource_intervals({"samples": samples}, 0, 1)
        self.assertEqual(rows[0]["process_cpu_cores"], 1.0)
        self.assertEqual(rows[0]["process_rss_GiB"], 1.0)
        self.assertEqual(rows[0]["process_write_MBps"], 1.0)

    def test_private_context_is_rejected(self):
        with self.assertRaises(ValueError):
            public_safe({"detail": "http://213.239.141.43:21899"})
        with self.assertRaises(ValueError):
            public_safe({"detail": "/home/sol/credential"})
        public_safe({"mean_seconds": 10.603, "count": 367076})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-directory", type=Path)
    parser.add_argument("--run-label", default="hour-baseline")
    parser.add_argument("--output", type=Path, default=Path("pq-crypto/results/continuous-agave/hour-c"))
    parser.add_argument("--allow-pilot", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReportTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1
    if args.manifest_directory is None:
        parser.error("--manifest-directory is required")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.run_label):
        parser.error("run label must be a single simple directory name")
    try:
        report = build_report(args.manifest_directory, args.run_label, args.allow_pilot)
        if args.allow_pilot and args.output.name == "hour-c":
            raise ValueError("a pilot cannot be written to the public hour-c directory")
        # All acceptance, reconciliation and privacy checks precede output creation.
        args.output.mkdir(parents=True, exist_ok=True)
        render(report, args.output)
        (args.output / "summary.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
        (args.output / "README.md").write_text(readme(report))
    except (ValueError, KeyError, OSError) as error:
        parser.exit(2, f"Report refused: {error}\n")
    print(json.dumps({"hour_acceptance_passed": report["hour_acceptance_passed"],
                      "finalized_success": report["finalized_success"],
                      "joint_source_observed_finalized_success_tps": report["joint_source_observed_finalized_success_tps"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
