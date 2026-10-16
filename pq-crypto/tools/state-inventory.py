#!/usr/bin/env python3
"""Read-only full-data inventory of the original manifest's background SBF state.

Run after every shared-authority probe and before load, then repeat with
--baseline after load. Private per-account vectors are never public summaries.
Only getGenesisHash/getMultipleAccounts are sent to the ten authorized hosts.

Baseline:
  python3 state-inventory.py --manifest ORIGINAL_MANIFEST --output PRIVATE_BASELINE
Post-load:
  python3 state-inventory.py --manifest ORIGINAL_MANIFEST --output PRIVATE_POST \
    --baseline PRIVATE_BASELINE

Use the original manifest: migrated manifests also mark managed vaults false.
Outputs must be fresh directories outside the repository. Only summary.json
is publication-safe; --public-summary may write that whitelisted summary to a
fresh file. Full node vectors/comparison files stay private. Each record binds
complete raw data and owner/lamports/executable/rent_epoch/data length; changing
RPC context slots are recorded but do not change the immutable account record.
All application authority references must match the original manifest, and
post-load comparisons exclude no selected account, including the four probes.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import time
import urllib.parse
import urllib.request


AUTHORIZED = {f"213.239.141.{n}" for n in (43, 44, 45, 46, 47, 48, 49, 32, 51, 31)}
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
RECORD_DOMAIN = b"agave/pq/background-account-record/v1"
INVENTORY_DOMAIN = b"agave/pq/background-account-inventory/v1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pubkey_bytes(value):
    require(isinstance(value, str) and 32 <= len(value) <= 44, "invalid pubkey text")
    number = 0
    for character in value:
        require(character in BASE58, "invalid pubkey base58")
        number = number * 58 + BASE58.index(character)
    leading = len(value) - len(value.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    decoded = b"\0" * leading + body
    require(len(decoded) == 32, "pubkey must decode to exactly32 bytes")
    return decoded


def u64(value, label):
    require(type(value) is int and 0 <= value < 1 << 64, f"invalid {label}")
    return value


def framed_hash(domain, fields):
    digest = hashlib.sha384()
    for field in (domain, *fields):
        digest.update(len(field).to_bytes(8, "little"))
        digest.update(field)
    return digest.hexdigest()


def account_record(address, account, owner, data_bytes, authorities=None):
    require(isinstance(account, dict), "required background account missing/null")
    require(account.get("owner") == owner, "background account owner changed")
    require(type(account.get("executable")) is bool, "invalid executable metadata")
    require(not account["executable"], "background state unexpectedly executable")
    lamports = u64(account.get("lamports"), "lamports")
    require(lamports > 0, "background account has no lamports")
    rent_epoch = u64(account.get("rentEpoch"), "rent epoch")
    encoded = account.get("data")
    require(
        isinstance(encoded, list) and len(encoded) == 2
        and isinstance(encoded[0], str) and encoded[1] == "base64",
        "expected full base64 account data",
    )
    require(len(encoded[0]) <= ((data_bytes + 2) // 3) * 4, "oversized account encoding")
    data = base64.b64decode(encoded[0], validate=True)
    require(len(data) == data_bytes, "background full data length changed")
    require(base64.b64encode(data).decode() == encoded[0], "noncanonical account base64")
    if authorities is not None:
        require(data[:8] == b"PQVAULT1", "background application layout mismatch")
        require(data[8:40] == authorities[0] and data[40:72] == authorities[1], "background authority references differ from original manifest")
    record_hash = framed_hash(RECORD_DOMAIN, [
        pubkey_bytes(address), pubkey_bytes(owner), lamports.to_bytes(8, "little"),
        bytes([account["executable"]]), rent_epoch.to_bytes(8, "little"),
        len(data).to_bytes(8, "little"), data,
    ])
    return {
        "address": address, "owner": owner, "lamports": lamports,
        "executable": account["executable"], "rent_epoch": rent_epoch,
        "data_bytes": len(data), "data_sha384": hashlib.sha384(data).hexdigest(),
        "full_record_sha384": record_hash,
    }


def inventory_hash(records):
    ordered = sorted(records, key=lambda row: pubkey_bytes(row["address"]))
    digest = hashlib.sha384()
    digest.update(len(INVENTORY_DOMAIN).to_bytes(8, "little"))
    digest.update(INVENTORY_DOMAIN)
    digest.update(len(ordered).to_bytes(8, "little"))
    for row in ordered:
        digest.update(pubkey_bytes(row["address"]))
        digest.update(bytes.fromhex(row["full_record_sha384"]))
    return digest.hexdigest(), ordered


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON response field")
        value[key] = item
    return value


def rpc_result(value, request_id):
    require(isinstance(value, dict), "JSON-RPC response must be an object")
    require(value.get("jsonrpc") == "2.0", "JSON-RPC version mismatch")
    require(type(value.get("id")) is str and value["id"] == request_id, "JSON-RPC response ID mismatch")
    require("error" not in value, "JSON-RPC returned an error")
    require("result" in value, "JSON-RPC result missing")
    return value["result"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("inventory RPC redirects are forbidden")


def rpc(url, method, params, request_id, timeout):
    require(method in ("getGenesisHash", "getMultipleAccounts"), "inventory method is not read-only")
    request = urllib.request.Request(url, data=json.dumps({
        "jsonrpc": "2.0", "id": request_id, "method": method, "params": params,
    }).encode(), headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        require(response.status == 200, "inventory RPC HTTP status is not200")
        wire = response.read(MAX_RESPONSE_BYTES + 1)
    require(len(wire) <= MAX_RESPONSE_BYTES, "inventory RPC response size bound")
    return rpc_result(json.loads(wire, object_pairs_hook=unique_object), request_id)


def read_json(path):
    require(path.stat().st_size <= 64 * 1024 * 1024, "JSON input size bound")
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def write_private(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def manifest_selection(manifest, expected_count, data_bytes):
    nodes = manifest.get("nodes")
    require(isinstance(nodes, list) and len(nodes) == 8, "inventory requires exactly8 validators")
    require(len({node["host"] for node in nodes}) == len(nodes), "duplicate validator host")
    for node in nodes:
        require(node["host"] in AUTHORIZED, "unauthorized inventory host")
        url = urllib.parse.urlsplit(node["rpc_url"])
        require(url.scheme in ("http", "https") and url.hostname == node["host"], "RPC URL must identify its authorized host")
        require(url.username is None and url.password is None and not url.query and not url.fragment, "unexpected RPC URL credentials/query")
        require(url.path in ("", "/") and url.port == node["rpc_port"], "RPC URL port/path mismatch")
    owner = manifest.get("workload_program")
    pubkey_bytes(owner)
    states = [row for row in manifest.get("workload_states", []) if row.get("authority_is_state_address") is False]
    require(len(states) == expected_count, "original manifest must select exactly the background account count; migrated manifest is unsuitable")
    require(all(row.get("data_bytes") == data_bytes for row in states), "background manifest data length mismatch")
    addresses = [row["state"] for row in states]
    require(len(set(addresses)) == len(addresses), "duplicate background account address")
    addresses.sort(key=pubkey_bytes)
    wallets = manifest.get("wallets")
    require(isinstance(wallets, list), "manifest authority wallets missing")
    authorities = {}
    for state in states:
        primary = u64(state.get("primary_wallet"), "primary wallet index")
        secondary = u64(state.get("secondary_wallet"), "secondary wallet index")
        require(primary < len(wallets) and secondary < len(wallets), "background authority wallet index bound")
        authorities[state["state"]] = (
            pubkey_bytes(wallets[primary]["address"]),
            pubkey_bytes(wallets[secondary]["address"]),
        )
    return nodes, owner, addresses, authorities


def collect(node, index, owner, addresses, authorities, data_bytes, genesis_hash, timeout):
    observed_genesis = rpc(node["rpc_url"], "getGenesisHash", [], f"inventory:{index}:genesis", timeout)
    require(observed_genesis == genesis_hash, "inventory RPC genesis differs from manifest")
    records, context_slots = [], []
    for offset in range(0, len(addresses), 100):
        chunk = addresses[offset:offset + 100]
        result = rpc(node["rpc_url"], "getMultipleAccounts", [
            chunk, {"encoding": "base64", "commitment": "finalized"},
        ], f"inventory:{index}:{offset}", timeout)
        require(isinstance(result, dict) and isinstance(result.get("context"), dict), "missing inventory context")
        context_slots.append(u64(result["context"].get("slot"), "context slot"))
        values = result.get("value")
        require(isinstance(values, list) and len(values) == len(chunk), "inventory account response count mismatch")
        records.extend(account_record(address, value, owner, data_bytes, authorities[address]) for address, value in zip(chunk, values))
    digest, ordered = inventory_hash(records)
    return {
        "node": index, "host": node["host"], "inventory_sha384": digest,
        "context_slot_min": min(context_slots), "context_slot_max": max(context_slots),
        "context_slots": context_slots, "records": ordered,
    }


def run(args):
    manifest = read_json(args.manifest)
    nodes, owner, addresses, authorities = manifest_selection(manifest, args.expected_count, args.data_bytes)
    require(1 <= args.timeout <= 30, "inventory per-RPC timeout bound")
    require(args.output.is_absolute(), "inventory output must be an absolute private directory")
    repo = Path(__file__).resolve().parents[2]
    require(not args.output.resolve().is_relative_to(repo), "full account inventories must remain outside repository")
    args.output.mkdir(mode=0o700, exist_ok=False)
    started_ms = time.time_ns() // 1_000_000
    genesis_hash = manifest.get("genesis_hash")
    pubkey_bytes(genesis_hash)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(collect, node, index, owner, addresses, authorities, args.data_bytes, genesis_hash, args.timeout)
            for index, node in enumerate(nodes)]
        results = []
        for index, future in enumerate(futures):
            result = future.result()
            write_private(args.output / f"node-{index}.json", result)
            result["private_document_sha384"] = hashlib.sha384(
                (args.output / f"node-{index}.json").read_bytes()
            ).hexdigest()
            results.append(result)
    all_nodes_equal = all(result["records"] == results[0]["records"] for result in results)
    mismatches = []
    if args.baseline is not None:
        baseline_summary = read_json(args.baseline / "summary.json")
        require(baseline_summary["genesis_hash"] == genesis_hash, "baseline genesis mismatch")
        require(baseline_summary["manifest_sha384"] == hashlib.sha384(args.manifest.read_bytes()).hexdigest(), "baseline manifest mismatch")
        require(baseline_summary["all_nodes_full_records_match"] is True, "baseline did not establish all-node equality")
        require(baseline_summary["background_account_count"] == len(addresses), "baseline count mismatch")
        for index, result in enumerate(results):
            baseline_path = args.baseline / f"node-{index}.json"
            require(baseline_path.stat().st_size <= 64 * 1024 * 1024, "baseline document size bound")
            require(
                hashlib.sha384(baseline_path.read_bytes()).hexdigest()
                == baseline_summary["nodes"][index]["private_document_sha384"],
                "baseline private account document hash mismatch",
            )
            baseline = read_json(baseline_path)
            require(baseline["host"] == result["host"], "baseline validator host mismatch")
            require(len(baseline["records"]) == len(addresses), "baseline account vector count mismatch")
            prior = {row["address"]: row for row in baseline["records"]}
            require(set(prior) == set(addresses), "baseline background account set mismatch")
            changed = [row["address"] for row in result["records"] if prior[row["address"]] != row]
            mismatches.append({"node": index, "changed_account_count": len(changed)})
            write_private(args.output / f"node-{index}-comparison.json", {"changed_addresses": changed})
    unchanged = all(row["changed_account_count"] == 0 for row in mismatches) if args.baseline is not None else None
    summary = {
        "format": "agave-pq-background-account-inventory/v1",
        "read_only": True, "phase": "post" if args.baseline is not None else "baseline",
        "genesis_hash": genesis_hash,
        "manifest_sha384": hashlib.sha384(args.manifest.read_bytes()).hexdigest(),
        "audit_tool_source_sha384": hashlib.sha384(Path(__file__).read_bytes()).hexdigest(),
        "validator_count": len(nodes), "background_account_count": len(addresses),
        "data_bytes_per_account": args.data_bytes, "total_data_bytes_per_validator": len(addresses) * args.data_bytes,
        "all_nodes_full_records_match": all_nodes_equal,
        "all_application_authority_references_match_original_manifest": True,
        "inventory_sha384": results[0]["inventory_sha384"] if all_nodes_equal else None,
        "all_background_accounts_unchanged_from_baseline": unchanged,
        "baseline_changed_accounts_by_node": mismatches,
        "nodes": [{key: row[key] for key in ("node", "host", "inventory_sha384", "private_document_sha384", "context_slot_min", "context_slot_max")} for row in results],
        "started_unix_ms": started_ms, "completed_unix_ms": time.time_ns() // 1_000_000,
        "scope": "Every selected account's complete bytes are SHA384 hashed; owner,lamports,executable,rent_epoch,data length and raw bytes are bound by full-record SHA384. Context slots may differ; immutable background state must match exactly. No account exclusions.",
    }
    write_private(args.output / "summary.json", summary)
    if args.public_summary is not None:
        write_private(args.public_summary, summary)
    require(all_nodes_equal, "background account records differ across validators; private evidence retained")
    require(unchanged is not False, "background state changed after baseline; private evidence retained")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--public-summary", type=Path)
    parser.add_argument("--expected-count", type=int, default=10_000)
    parser.add_argument("--data-bytes", type=int, default=2048)
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    require(1 <= args.expected_count <= 100_000 and 128 <= args.data_bytes <= 16_384, "inventory account/data bounds")
    print(json.dumps(run(args), indent=2))


if __name__ == "__main__":
    main()
