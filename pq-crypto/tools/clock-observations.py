#!/usr/bin/env python3
"""Read native Clock and every configured native Vote timestamp at all8 RPCs.

Uses Agave's actual jsonParsed sysvar/VoteStateV4 decoder. Wall intervals bracket
each same-context nine-account response. No clock, account or ledger is changed.
"""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import time
import urllib.request

CLOCK = "SysvarC1ock11111111111111111111111111111111"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def rpc(url, method, params, identifier):
    request = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": identifier,
        "method": method, "params": params}).encode(), headers={"Content-Type": "application/json"})
    value = json.loads(urllib.request.urlopen(request, timeout=10).read())
    require(value.get("id") == identifier and "error" not in value, "native RPC response identity/error")
    return value["result"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    require(args.output.is_absolute() and not args.output.exists()
        and not args.output.resolve().is_relative_to(Path(__file__).resolve().parents[2]), "fresh private output outside repository required")
    manifest = json.loads(args.manifest.read_text())
    nodes = manifest["nodes"]
    require(len(nodes) == 8 and len({n["host"] for n in nodes}) == 8, "eight distinct native validators required")
    addresses = [CLOCK, *[node["vote_account"] for node in nodes]]
    def collect(pair):
        index, node = pair
        started = time.time_ns()//1000000
        response = rpc(node["rpc_url"], "getMultipleAccounts",
            [addresses, {"encoding": "jsonParsed", "commitment": "finalized"}], f"clock:{index}")
        completed = time.time_ns()//1000000
        values = response["value"]
        require(isinstance(values, list) and len(values) == 9 and all(isinstance(value, dict) for value in values), "clock/vote account missing or malformed")
        clock_data = values[0]["data"]
        require(clock_data.get("program") == "sysvar" and clock_data["parsed"]["type"] == "clock", "native Clock decoder mismatch")
        clock = clock_data["parsed"]["info"]
        require(clock["slot"] == response["context"]["slot"] and type(clock["unixTimestamp"]) is int, "native Clock/context slot or timestamp mismatch")
        votes = []
        for peer, value in zip(nodes, values[1:]):
            data = value["data"]
            require(data.get("program") == "vote" and data["parsed"]["type"] == "vote", "native VoteStateV4 decoder mismatch")
            info = data["parsed"]["info"]
            require(info["nodePubkey"] == peer["id"], "native vote identity differs from configured committee")
            votes.append({"configured_node": peer["index"], "vote_account": peer["vote_account"],
                "node_pubkey": info["nodePubkey"], "last_timestamp": info["lastTimestamp"],
                "native_votes": len(info["votes"]), "epoch_credit_rows": len(info["epochCredits"]),
                "native_root_slot": info["rootSlot"]})
        schedule = rpc(node["rpc_url"], "getEpochSchedule", [], f"schedule:{index}")
        return {"node": index, "host": node["host"], "wall_started_unix_ms": started,
            "wall_completed_unix_ms": completed, "context_slot": response["context"]["slot"],
            "clock": clock, "native_epoch_schedule": schedule,
            "wall_minus_clock_seconds_lower": started/1000-clock["unixTimestamp"],
            "wall_minus_clock_seconds_upper": completed/1000-clock["unixTimestamp"], "votes": votes}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        observations = list(pool.map(collect, enumerate(nodes)))
    result = {"format": "agave-pq-native-clock-vote-observations-v1", "read_only": True,
        "actual_native_json_parsed_decoder": True, "genesis_hash": manifest["genesis_hash"],
        "source_sha384": hashlib.sha384(Path(__file__).read_bytes()).hexdigest(),
        "rpc_timeout_seconds": 10, "native_slot_duration_ms": 400, "configured_pq_cadence_ms": 500,
        "all_64_vote_views_have_zero_timestamp_votes_and_credits": all(vote["last_timestamp"] == {"slot": 0, "timestamp": 0}
            and vote["native_votes"] == vote["epoch_credit_rows"] == 0 for observation in observations for vote in observation["votes"]),
        "clock_fix_not_asserted": True, "nodes": observations}
    with args.output.open("x") as stream:
        args.output.chmod(0o600)
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({"native_slots": [row["context_slot"] for row in observations],
        "native_unix_timestamps": [row["clock"]["unixTimestamp"] for row in observations],
        "wall_clock_lag_seconds_range": [min(row["wall_minus_clock_seconds_lower"] for row in observations),
            max(row["wall_minus_clock_seconds_upper"] for row in observations)],
        "all64_vote_timestamps_votes_credits_zero": result["all_64_vote_views_have_zero_timestamp_votes_and_credits"]}))


if __name__ == "__main__":
    main()
