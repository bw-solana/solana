#!/usr/bin/env python3
"""Read-only exact account audit before/after the continuous native workload.

Baseline after migration, seed recovery, shared-authority probes AND the pilot:
  control-inventory.py --manifest ORIGINAL --output PRIVATE_BASELINE
Post hour (one immutable request/result pair per generator, in matching order):
  control-inventory.py --manifest ORIGINAL --baseline PRIVATE_BASELINE \
    --source-request REQUEST0 --source-result RESULT0 \
    --source-request REQUEST1 --source-result RESULT1 --output PRIVATE_POST

All full account bytes and account vectors stay in fresh private directories
outside the repository. Only summary.json is publication-safe. RPC is bounded,
read-only, finalized, and restricted to the authorized validator hosts. Every
account metadata/data byte must remain exact, except explicitly calculated
sender/recipient lamports, SPL amount lanes, and independently predicted native
rent-exempt epoch normalization of their writable accounts. No account is excluded after
observing a difference. Source requests supply start_counter (older measured
clients omit it in results); positive contiguous, successful counts are required.
The frozen native genesis has FeeRateGovernor::new(5000,0), no priority fee and
one signer; actual source receipts independently verify this fee/wire contract.
Use --self-test for mock checks; this never contacts a node.
"""
import argparse
import base64
import concurrent.futures
import copy
import hashlib
import importlib.util
import json
import os
import struct
from pathlib import Path
import sys
import time
import urllib.request

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("state_inventory", Path(__file__).with_name("state-inventory.py"))
shared = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shared)
require = shared.require
u64 = shared.u64
pubkey_bytes = shared.pubkey_bytes
read_json = shared.read_json
write_private = shared.write_private


def b58(data):
    number, encoded = int.from_bytes(data, "big"), ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = shared.BASE58[remainder] + encoded
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + encoded


SYSTEM = b58(bytes(32))
CONFIG = b58(bytes([0x50]) * 32)
AUTH = b58(bytes([0x51]) * 32)
ROLES = b58(bytes([0x54]) * 32)
TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
COMPUTE = "ComputeBudget111111111111111111111111111111"
RENT = "SysvarRent111111111111111111111111111111111"
SYSVAR = "Sysvar1111111111111111111111111111111111111"
RENT_EXEMPT_EPOCH = (1 << 64) - 1
# Frozen C genesis uses Rent::default(); the activated native rent feature
# rewrites 3480 * 2.0 to 6960 * 1.0, preserving every minimum balance.
FROZEN_RENT = (6960, 1.0, 50)
DOMAIN = b"agave/pq/control-account-record/v1"
MAX_RESPONSE = 8 * 1024 * 1024


def rpc(url, method, params, request_id, timeout):
    require(method in ("getGenesisHash", "getMultipleAccounts", "getProgramAccounts", "getTransaction"), "control inventory method must be read-only")
    request = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode(), headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), shared.NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        require(response.status == 200, "control inventory RPC HTTP status")
        wire = response.read(MAX_RESPONSE + 1)
    require(len(wire) <= MAX_RESPONSE, "control inventory response size bound")
    return shared.rpc_result(json.loads(wire, object_pairs_hook=shared.unique_object), request_id)


def data_bytes(account):
    encoded = account.get("data")
    require(isinstance(encoded, list) and len(encoded) == 2 and encoded[1] == "base64" and isinstance(encoded[0], str), "full base64 account data required")
    require(len(encoded[0]) <= MAX_RESPONSE, "account encoding bound")
    data = base64.b64decode(encoded[0], validate=True)
    require(base64.b64encode(data).decode() == encoded[0], "noncanonical base64")
    return data


def record(address, account):
    pubkey_bytes(address)
    if account is None:
        return {"address": address, "present": False, "full_record_sha384": shared.framed_hash(DOMAIN, [pubkey_bytes(address), b"\0"])}
    require(isinstance(account, dict), "invalid account object")
    owner = account.get("owner")
    pubkey_bytes(owner)
    lamports = u64(account.get("lamports"), "lamports")
    require(lamports > 0, "zero-lamport account must be absent")
    rent = u64(account.get("rentEpoch"), "rent epoch")
    require(type(account.get("executable")) is bool, "invalid executable field")
    data = data_bytes(account)
    return {"address": address, "present": True, "owner": owner, "lamports": lamports, "executable": account["executable"], "rent_epoch": rent, "data_base64": account["data"][0], "data_bytes": len(data), "data_sha384": hashlib.sha384(data).hexdigest(), "full_record_sha384": shared.framed_hash(DOMAIN, [pubkey_bytes(address), b"\1", pubkey_bytes(owner), lamports.to_bytes(8, "little"), bytes([account["executable"]]), rent.to_bytes(8, "little"), len(data).to_bytes(8, "little"), data])}


def raw(row):
    require(row.get("present") is True, "required account absent")
    return base64.b64decode(row["data_base64"], validate=True)


def rebuild(row, lamport_delta=0, token_delta=0, rent_epoch=None):
    data = bytearray(raw(row))
    if token_delta:
        require(row["owner"] == TOKEN and len(data) == 165, "token adjustment must target SPL account")
        amount = u64(int.from_bytes(data[64:72], "little") + token_delta, "expected token amount")
        data[64:72] = amount.to_bytes(8, "little")
    return record(row["address"], {"owner": row["owner"], "lamports": u64(row["lamports"] + lamport_delta, "expected lamports"), "executable": row["executable"], "rentEpoch": row["rent_epoch"] if rent_epoch is None else u64(rent_epoch, "predicted rent epoch"), "data": [base64.b64encode(data).decode(), "base64"]})


def native_rent_parameters(account):
    require(isinstance(account, dict) and account.get("owner") == SYSVAR and account.get("executable") is False, "native Rent owner/executable mismatch")
    data = data_bytes(account)
    require(len(data) == 17 and struct.unpack("<QdB", data) == FROZEN_RENT, "native Rent differs from frozen C eligibility parameters")
    return {"lamports_per_byte_year": FROZEN_RENT[0], "exemption_threshold": FROZEN_RENT[1], "burn_percent": FROZEN_RENT[2], "account_storage_overhead_bytes": 128, "data_sha384": hashlib.sha384(data).hexdigest()}


def predicted_rent_epoch(row, lamport_delta, token_delta, rent):
    # Only independently counter-derived, nonzero workload deltas identify a
    # writable account. Readonly mints/policies/programs and untargeted states
    # retain all baseline metadata, including rent_epoch.
    if not lamport_delta and not token_delta:
        return row["rent_epoch"]
    require(row.get("present") is True and row["executable"] is False, "writable workload account absent/executable")
    if token_delta:
        require(not lamport_delta and row["owner"] == TOKEN and row["data_bytes"] == 165, "writable token lane owner/layout mismatch")
    else:
        require(row["owner"] == SYSTEM and row["data_bytes"] == 0, "writable SOL lane owner/layout mismatch")
    require((rent["lamports_per_byte_year"], rent["exemption_threshold"], rent["burn_percent"], rent["account_storage_overhead_bytes"]) == (*FROZEN_RENT, 128), "unfrozen rent eligibility")
    minimum = (128 + row["data_bytes"]) * rent["lamports_per_byte_year"]
    # SVM account_loader.rs:331/615 and transaction_processor.rs:889 update
    # rent-exempt status while loading writable accounts, before execution/fees.
    # This frozen workload starts every touched account rent exempt. If a
    # future fixture crosses the threshold from below, reject this simpler
    # predictor rather than infer an epoch from an observed post-load value.
    if row["lamports"] < minimum:
        require(row["lamports"] + lamport_delta < minimum, "nonexempt-to-exempt crossing requires a per-transaction rent model")
        return row["rent_epoch"]
    return RENT_EXEMPT_EPOCH


def commitment(domain, parts):
    digest = hashlib.sha384()
    digest.update(b"agave-pq-commitment-v1")
    digest.update(len(domain).to_bytes(8, "little"))
    digest.update(domain)
    digest.update(len(parts).to_bytes(8, "little"))
    for part in parts:
        digest.update(len(part).to_bytes(8, "little"))
        digest.update(part)
    return digest.digest()


def policy(row):
    data = raw(row)
    require(row["owner"] == AUTH and not row["executable"], "policy owner/executable mismatch")
    require(997 <= len(data) <= 997 + 128 * 48 and data[:8] == b"PQAUTH01", "policy layout mismatch")
    retired_count = int.from_bytes(data[995:997], "little")
    generation = int.from_bytes(data[985:993], "little")
    require(len(data) == 997 + retired_count * 48 and generation == retired_count + 1, "policy generation/retired count mismatch")
    require(data[994] == 1 and data[993] in (1, 2, 3), "policy must permanently retire legacy authorization")
    require(data[40] == 9 and data[937:985] == commitment(b"agave-pq/auth-key/v1", [data[40:937]]), "policy key commitment mismatch")
    retired = [data[997 + 48 * i:1045 + 48 * i] for i in range(retired_count)]
    require(len(set(retired)) == retired_count and data[937:985] not in retired, "policy reused retired key")
    return {"authority": b58(data[8:40]), "generation": generation, "origin": data[993], "legacy_permanently_disabled": True, "retired_keys": retired_count}


def selection(manifest):
    nodes, owner, _, _ = shared.manifest_selection(manifest, 10000, 2048)
    wallets = manifest["wallets"]
    recipients = manifest["recipients"]
    states = [row for row in manifest["workload_states"] if row.get("authority_is_state_address") is True]
    require(len(wallets) == 545 and len(recipients) == 256 and len(states) == 16, "rich control fixture count mismatch")
    require(len(manifest["wallet_token_accounts"]) == 545 and len(manifest["recipient_token_accounts"]) == 256, "SPL control fixture count mismatch")
    require([wallet["index"] for wallet in wallets] == list(range(545)), "wallet indices must be canonical")
    require([i for i, wallet in enumerate(wallets) if wallet.get("legacy_private_key") is not None] == list(range(33)), "legacy fixture selection mismatch")
    addresses = {wallet["address"] for wallet in wallets} | set(recipients) | set(manifest["wallet_token_accounts"]) | set(manifest["recipient_token_accounts"])
    addresses.update((CONFIG, ROLES, owner, TOKEN, manifest["token_mint"], manifest["legacy_authority"], manifest["seed_escrow"], manifest["seed_token_account"]))
    absent = {state["escrow"] for state in states}
    addresses.update(state["state"] for state in states)
    addresses.update(absent)
    for address in addresses:
        pubkey_bytes(address)
    require(len({wallet["address"] for wallet in wallets}) == 545 and len(set(recipients)) == 256, "duplicate custody authority")
    return nodes, owner, addresses, absent, states


def fetch_accounts(node, addresses, prefix, timeout):
    records, slots = {}, []
    ordered = sorted(addresses, key=pubkey_bytes)
    for offset in range(0, len(ordered), 100):
        chunk = ordered[offset:offset + 100]
        result = rpc(node["rpc_url"], "getMultipleAccounts", [chunk, {"encoding": "base64", "commitment": "finalized"}], f"control:{prefix}:{offset}", timeout)
        require(isinstance(result, dict) and isinstance(result.get("context"), dict), "account RPC context missing")
        slots.append(u64(result["context"].get("slot"), "context slot"))
        values = result.get("value")
        require(isinstance(values, list) and len(values) == len(chunk), "account response count mismatch")
        records.update((address, record(address, account)) for address, account in zip(chunk, values))
    return records, slots


def validate_semantics(manifest, rows, policies, absent, states, owner):
    require(all(not rows[address]["present"] for address in absent), "managed PDA custody was not drained")
    require(all(row["present"] for address, row in rows.items() if address not in absent), "required custody/control account missing")
    rotated = {state["primary_wallet"] for state in states}
    require(rotated == set(range(0, 32, 2)), "managed primary authority selection mismatch")
    for i, wallet in enumerate(manifest["wallets"]):
        row = rows[wallet["address"]]
        require(not row["executable"], "authority unexpectedly executable")
        if i in rotated:
            require(row["owner"] == owner and len(raw(row)) == 2048 and raw(row)[:8] == b"PQVAULT1", "program-owned legacy authority changed")
        else:
            require(row["owner"] == SYSTEM and raw(row) == b"", "System authority owner/data mismatch")
        info = policies[wallet["address"]]["decoded"]
        require(info["origin"] == (3 if i < 33 else 2) and info["generation"] == (2 if i in rotated else 1), "migrated/Fresh policy origin/generation mismatch")
    for state in states:
        data = raw(rows[state["state"]])
        require(data[:8] == b"PQVAULT1" and data[8:40] == pubkey_bytes(manifest["wallets"][33]["address"]) and data[40:72] == pubkey_bytes(manifest["wallets"][34]["address"]), "managed 2-of-2 authority rotation missing")
        require(int.from_bytes(data[72:80], "little") == 8 and int.from_bytes(data[104:112], "little") == 1 and int.from_bytes(data[120:128], "little") == 1, "managed application lifecycle incomplete")
        require(any(data[128:]), "managed application padding unexpectedly empty")
    for address in manifest["recipients"]:
        row = rows[address]
        require(row["owner"] == SYSTEM and not row["executable"] and raw(row) == b"", "recipient SOL owner/data mismatch")
        require(policies[address]["decoded"]["origin"] == 2 and policies[address]["decoded"]["generation"] == 1, "recipient custody policy mismatch")
    tokens = list(zip(manifest["wallet_token_accounts"], [w["address"] for w in manifest["wallets"]])) + list(zip(manifest["recipient_token_accounts"], manifest["recipients"])) + [(manifest["seed_token_account"], manifest["legacy_authority"])]
    for address, authority in tokens:
        row, data = rows[address], raw(rows[address])
        require(row["owner"] == TOKEN and not row["executable"] and len(data) == 165 and data[:32] == pubkey_bytes(manifest["token_mint"]) and data[32:64] == pubkey_bytes(authority) and data[108] == 1, "SPL custody owner/mint/state mismatch")
    mint, mint_data = rows[manifest["token_mint"]], raw(rows[manifest["token_mint"]])
    require(mint["owner"] == TOKEN and not mint["executable"] and len(mint_data) == 82 and mint_data[44:46] == b"\0\1", "mint layout mismatch")
    original_primary = pubkey_bytes(manifest["wallets"][0]["address"])
    require(mint_data[:36] == (1).to_bytes(4, "little") + original_primary and mint_data[46:82] == (1).to_bytes(4, "little") + original_primary, "mint/freeze authority address changed")
    seed = rows[manifest["legacy_authority"]]
    seed_data = raw(seed)
    require(seed["owner"] == owner and not seed["executable"] and len(seed_data) == 2048 and seed_data[:8] == b"PQVAULT1" and any(seed_data[128:]), "recovered program-owned seed state mismatch")
    require(seed_data[8:40] == pubkey_bytes(manifest["legacy_authority"]) and seed_data[40:72] == pubkey_bytes(manifest["wallets"][manifest["seed_secondary_wallet"]]["address"]), "recovered seed authority references changed")
    info = policies[manifest["legacy_authority"]]["decoded"]
    require(info["origin"] == 1 and info["generation"] == 1, "private-seed origin/generation mismatch")
    require(rows[manifest["seed_escrow"]]["owner"] == SYSTEM and raw(rows[manifest["seed_escrow"]]) == b"", "seed PDA owner/data mismatch")
    config = rows[CONFIG]
    require(config["owner"] == AUTH and not config["executable"] and raw(config) == b"AGAVEPQC" + bytes.fromhex(manifest["chain"]) + bytes.fromhex(manifest["migration_context"]) + manifest["cutoff_slot"].to_bytes(8, "little"), "immutable auth configuration differs from manifest")
    require(rows[ROLES]["owner"] == AUTH and not rows[ROLES]["executable"], "immutable role registry owner mismatch")


def collect(manifest, node, index, timeout):
    _, owner, addresses, absent, states = selection(manifest)
    require(rpc(node["rpc_url"], "getGenesisHash", [], f"control:{index}:genesis", timeout) == manifest["genesis_hash"], "control RPC genesis mismatch")
    result = rpc(node["rpc_url"], "getProgramAccounts", [AUTH, {"encoding": "base64", "commitment": "finalized", "withContext": True, "filters": [{"memcmp": {"offset": 0, "bytes": b58(b"PQAUTH01")}}]}], f"control:{index}:policies", timeout)
    require(isinstance(result, dict) and isinstance(result.get("value"), list), "policy scan response mismatch")
    slots = [u64(result["context"]["slot"], "policy context slot")]
    require(len(result["value"]) <= 4096, "policy inventory count bound")
    policies, scanned_records = {}, {}
    for entry in result["value"]:
        row = record(entry["pubkey"], entry["account"])
        info = policy(row)
        require(info["authority"] not in policies, "duplicate authority policy")
        policies[info["authority"]] = {"address": row["address"], "decoded": info}
        scanned_records[row["address"]] = row
        addresses.add(row["address"])
    required_authorities = {w["address"] for w in manifest["wallets"]} | set(manifest["recipients"]) | {manifest["legacy_authority"]}
    require(required_authorities.issubset(policies), "custody authority has no installed PQ policy")
    rent_response = rpc(node["rpc_url"], "getMultipleAccounts", [[RENT], {"encoding": "base64", "commitment": "finalized"}], f"control:{index}:rent", timeout)
    require(isinstance(rent_response, dict) and isinstance(rent_response.get("context"), dict) and isinstance(rent_response.get("value"), list) and len(rent_response["value"]) == 1, "native Rent response mismatch")
    slots.append(u64(rent_response["context"].get("slot"), "Rent context slot"))
    rent = native_rent_parameters(rent_response["value"][0])
    rows, account_slots = fetch_accounts(node, addresses, index, timeout)
    slots.extend(account_slots)
    program_data = set()
    for program in (owner, TOKEN):
        row, data = rows[program], raw(rows[program])
        require(row["executable"], "actual SBF/SPL executable missing")
        if row["owner"] == LOADER:
            require(len(data) == 36 and data[:4] == (2).to_bytes(4, "little"), "UpgradeableLoader Program layout mismatch")
            program_data.add(b58(data[4:36]))
    if program_data:
        extra, account_slots = fetch_accounts(node, program_data, f"{index}:programdata", timeout)
        rows.update(extra)
        slots.extend(account_slots)
    # Re-read policies under the same account inventory and reject concurrent change.
    for authority, entry in policies.items():
        require(policy(rows[entry["address"]]) == entry["decoded"] and rows[entry["address"]] == scanned_records[entry["address"]], "policy changed during inventory scan")
    validate_semantics(manifest, rows, policies, absent, states, owner)
    ordered = sorted(rows.values(), key=lambda row: pubkey_bytes(row["address"]))
    digest, _ = shared.inventory_hash(ordered)
    return {"node": index, "host": node["host"], "inventory_sha384": digest, "context_slot_min": min(slots), "context_slot_max": max(slots), "context_slots": slots, "native_rent_parameters": rent, "policies": policies, "records": ordered}


def modulo_counts(start, count, length):
    require(length > 0, "empty counter destination vector")
    start, count = u64(start, "start counter"), u64(count, "generated count")
    require(start + count < 1 << 64, "counter range overflow")
    return [count // length + int((position - start % length) % length < count % length) for position in range(length)]


def source_deltas(manifest, request, result):
    counts = result.get("counts", {})
    count = u64(counts.get("generated"), "generated count")
    start = u64(request.get("start_counter", 0), "request start counter")
    for key in ("admitted", "finalized_success", "admission_errors", "finalized_error"):
        u64(counts.get(key), f"source {key}")
    u64(request.get("source_id"), "source ID")
    require(count > 0 and counts.get("admitted") == counts.get("finalized_success") == count and counts.get("admission_errors") == counts.get("finalized_error") == 0 and result.get("pending") == 0 and result.get("failure") is None, "source does not contain only committed successful contiguous transactions")
    require(result.get("actual_bank_svm") is True and result.get("actual_agave_rpc") is True and result.get("all_validator_recipient_balances_match") is True, "source execution/convergence evidence missing")
    require(result.get("last_counter_exclusive") == start + count, "source counter range has a gap")
    require(result.get("source_id") == request.get("source_id") and result.get("phases") == request.get("phases"), "source request/result identity mismatch")
    if "start_counter" in result:
        require(result["start_counter"] == start, "source explicit start counter mismatch")
    wallets = request.get("wallet_indices")
    require(isinstance(wallets, list) and wallets and len(set(wallets)) == len(wallets) and result.get("wallet_indices") == wallets, "source wallet selection mismatch")
    require(all(type(i) is int and 33 <= i < 545 for i in wallets), "source must use only original fresh System payers")
    phases = request.get("phases")
    require(isinstance(phases, list) and phases and all(phase.get("kind") == phases[0].get("kind") for phase in phases), "source must have one fixed transfer kind")
    kind = phases[0]["kind"]
    require(kind in ("system_transfer", "token_transfer"), "source fixed transfer kind required")
    require(u64(request.get("amount", 1), "transfer amount") == 1, "audited hour amount must equal one")
    recipients = u64(request.get("recipient_count"), "recipient count")
    require(1 <= recipients <= len(manifest["recipients"]), "source recipient bound")
    require(result.get("recipients") == manifest["recipients"][:recipients], "source recipient selection mismatch")
    if kind == "token_transfer":
        require(result.get("token_recipients") == manifest["recipient_token_accounts"][:recipients], "source token recipient selection mismatch")
    payer_counts, recipient_counts = modulo_counts(start, count, len(wallets)), modulo_counts(start, count, recipients)
    expected_system = recipient_counts if kind == "system_transfer" else [0] * recipients
    expected_token = recipient_counts if kind == "token_transfer" else [0] * recipients
    require(result.get("system_recipient_deltas") == expected_system and result.get("token_recipient_deltas") == expected_token, "source reported destination deltas differ from independent counter math")
    lamports, tokens = {}, {}
    for i, transactions in zip(wallets, payer_counts):
        lamports[manifest["wallets"][i]["address"]] = -transactions * (5000 + int(kind == "system_transfer"))
        if kind == "token_transfer":
            tokens[manifest["wallet_token_accounts"][i]] = -transactions
    for i, transactions in enumerate(recipient_counts):
        target = manifest["recipients"][i] if kind == "system_transfer" else manifest["recipient_token_accounts"][i]
        destination = lamports if kind == "system_transfer" else tokens
        destination[target] = destination.get(target, 0) + transactions
    return lamports, tokens, {"source_id": request["source_id"], "kind": kind, "start_counter": start, "last_counter_exclusive": start + count, "generated_and_committed": count, "sender_wallets": len(wallets), "recipients": recipients, "fee_lamports_per_transaction": 5000}


def shortvec(data, offset):
    value = 0
    for shift in (0, 7, 14):
        require(offset < len(data), "truncated transaction shortvec")
        byte, offset = data[offset], offset + 1
        value |= (byte & 127) << shift
        if byte < 128:
            require(value <= 65535 and (shift == 0 or byte != 0), "noncanonical transaction shortvec")
            return value, offset
    raise ValueError("oversized transaction shortvec")


def wire_transaction(encoded):
    require(isinstance(encoded, list) and len(encoded) == 2 and encoded[1] == "base64", "base64 transaction receipt required")
    data = base64.b64decode(encoded[0], validate=True)
    require(len(data) <= 16384, "PQ transaction wire bound")
    signatures, offset = shortvec(data, 0)
    require(signatures == 1 and offset + 64 + 3 <= len(data), "load receipt must contain exactly one signer")
    transaction_id = b58(data[offset:offset + 64])
    offset += 64
    header, offset = data[offset:offset + 3], offset + 3
    require(header[0] == 1, "legacy static message must have one required signer")
    key_count, offset = shortvec(data, offset)
    require(key_count > 0 and offset + key_count * 32 + 32 <= len(data), "transaction keys truncated")
    keys = [b58(data[offset + i * 32:offset + (i + 1) * 32]) for i in range(key_count)]
    offset += key_count * 32 + 32
    instruction_count, offset = shortvec(data, offset)
    instructions = []
    for _ in range(instruction_count):
        require(offset < len(data), "instruction program missing")
        program_index, offset = data[offset], offset + 1
        require(program_index < key_count, "instruction program index bound")
        account_count, offset = shortvec(data, offset)
        require(offset + account_count <= len(data), "instruction accounts truncated")
        accounts = list(data[offset:offset + account_count])
        require(all(index < key_count for index in accounts), "instruction account index bound")
        offset += account_count
        size, offset = shortvec(data, offset)
        require(offset + size <= len(data), "instruction data truncated")
        instructions.append((keys[program_index], [keys[index] for index in accounts], data[offset:offset + size]))
        offset += size
    require(offset == len(data), "transaction has trailing bytes")
    return transaction_id, keys[0], instructions


def validate_fee_receipt(receipt, event, request, manifest):
    require(isinstance(receipt, dict) and receipt.get("meta", {}).get("err") is None and receipt.get("meta", {}).get("fee") == 5000, "actual source receipt does not confirm fixed 5000 fee")
    transaction_id, payer, instructions = wire_transaction(receipt.get("transaction"))
    counter = u64(event.get("counter"), "sample counter")
    wallet_index = request["wallet_indices"][counter % len(request["wallet_indices"])]
    require(transaction_id == event.get("id") and payer == manifest["wallets"][wallet_index]["address"], "sample transaction ID/payer mismatch")
    require(instructions and instructions[0][0] == AUTH and instructions[0][2][:9] == b"AGAVEPQ1\1", "sample one-signer Falcon carrier missing")
    budget = [data for program, _, data in instructions if program == COMPUTE]
    require(len(budget) == 1 and budget[0] == b"\2" + request.get("compute_unit_limit", 20000).to_bytes(4, "little"), "sample must set only a fixed CU limit, with no priority fee")
    nonce = [data for program, _, data in instructions if program == manifest["workload_program"]]
    require(nonce == [b"\0" + request["source_id"].to_bytes(8, "little") + counter.to_bytes(8, "little")], "sample actual SBF source/counter nonce mismatch")
    kind = request["phases"][0]["kind"]
    recipient_index = counter % request["recipient_count"]
    require(event.get("kind") == kind and event.get("recipient_index") == recipient_index, "sample reported phase/recipient differs from actual counter")
    if kind == "system_transfer":
        transfer = [instruction for instruction in instructions if instruction[0] == SYSTEM]
        require(len(instructions) == 4 and len(transfer) == 1 and transfer[0][1] == [payer, manifest["recipients"][recipient_index]] and transfer[0][2] == (2).to_bytes(4, "little") + (1).to_bytes(8, "little"), "sample actual System transfer differs from fixed workload")
    elif kind == "token_transfer":
        transfer = [instruction for instruction in instructions if instruction[0] == TOKEN]
        require(len(instructions) == 4 and len(transfer) == 1 and transfer[0][1] == [manifest["wallet_token_accounts"][wallet_index], manifest["token_mint"], manifest["recipient_token_accounts"][recipient_index], payer] and transfer[0][2] == b"\x0c" + (1).to_bytes(8, "little") + b"\0", "sample actual SPL transfer_checked differs from fixed workload")
    else:
        require(kind == "nonce_only" and len(instructions) == 3, "sample unknown workload instructions")
    return {"source_id": request["source_id"], "signature": transaction_id, "counter": counter, "fee": 5000, "required_signatures": 1, "no_priority_fee": True, "slot": u64(receipt.get("slot"), "receipt slot")}


def sample_event(result, request):
    path = Path(result["events_file"])
    require(path.is_absolute() and path.is_file(), "private source event file unavailable")
    start, end = request.get("start_counter", 0), result["last_counter_exclusive"]
    with path.open() as stream:
        for _ in range(100000):
            line = stream.readline(1024 * 1024 + 1)
            if not line:
                break
            require(len(line) <= 1024 * 1024, "event line bound")
            event = json.loads(line, object_pairs_hook=shared.unique_object)
            if event.get("event") == "finalized" and event.get("success") is True:
                require(event.get("error") is None and start <= event.get("counter", -1) < end, "sample event outside committed range")
                return event
    raise ValueError("no successful finalized source event sample")


def expected_records(records, lamports, tokens, rent=None):
    rows = {row["address"]: row for row in records}
    require(len(rows) == len(records), "duplicate baseline account")
    require(set(lamports).union(tokens).issubset(rows), "source delta targets an uninventoried account")
    return {address: rebuild(row, lamports.get(address, 0), tokens.get(address, 0), predicted_rent_epoch(row, lamports.get(address, 0), tokens.get(address, 0), rent) if rent else None) if address in lamports or address in tokens else row for address, row in rows.items()}


def compare_records(baseline, observed, lamports, tokens, rent=None):
    expected = expected_records(baseline, lamports, tokens, rent)
    observed = {row["address"]: row for row in observed}
    require(set(expected) == set(observed), "protected account set changed")
    return [address for address in expected if expected[address] != observed[address]]


def run(args):
    manifest = read_json(args.manifest)
    nodes, _, _, _, _ = selection(manifest)
    require(1 <= args.timeout <= 30, "control RPC timeout bound")
    require(args.output.is_absolute() and not args.output.resolve().is_relative_to(Path(__file__).resolve().parents[2]), "private output must be outside repository")
    require(len(args.source_request) == len(args.source_result) and (not args.source_request or args.baseline is not None), "source request/result pairs require a baseline")
    requests, results = [read_json(path) for path in args.source_request], [read_json(path) for path in args.source_result]
    if requests:
        require(len(requests) == 2 and len({request["source_id"] for request in requests}) == 2, "post-hour requires two distinct generators")
        require({request["phases"][0]["kind"] for request in requests} == {"system_transfer", "token_transfer"}, "post-hour must include exactly the System and Token source")
    pinned = read_json(args.operating_point) if args.operating_point else None
    if pinned:
        require(len(requests) == len(pinned.get("sources", [])) == 2, "operating-point source count mismatch")
        for source, path in enumerate(args.source_request):
            require(hashlib.sha384(path.read_bytes()).hexdigest() == pinned["sources"][source]["request_sha384"], "request changed from the pre-hour operating-point pin")
    lamports, tokens, source_summaries, samples = {}, {}, [], []
    source_wallets = set()
    for source, (request, result) in enumerate(zip(requests, results)):
        require(not source_wallets.intersection(request["wallet_indices"]), "source payer overlap forbidden")
        source_wallets.update(request["wallet_indices"])
        sol_delta, token_delta, summary = source_deltas(manifest, request, result)
        for target, delta in sol_delta.items():
            lamports[target] = lamports.get(target, 0) + delta
        for target, delta in token_delta.items():
            tokens[target] = tokens.get(target, 0) + delta
        summary["immutable_request_sha384"] = hashlib.sha384(args.source_request[source].read_bytes()).hexdigest()
        summary["source_result_sha384"] = hashlib.sha384(args.source_result[source].read_bytes()).hexdigest()
        source_summaries.append(summary)
        samples.append(sample_event(result, request))
    total_transactions = sum(source["generated_and_committed"] for source in source_summaries)
    require(sum(lamports.values()) == -5000 * total_transactions and sum(tokens.values()) == 0, "independent delta conservation mismatch")
    baseline_summary = read_json(args.baseline / "summary.json") if args.baseline else None
    if baseline_summary:
        require(baseline_summary["phase"] == "pre-load-baseline" and baseline_summary["genesis_hash"] == manifest["genesis_hash"] and baseline_summary["validators"] == 8 and baseline_summary["all_validator_full_records_match"] is True, "invalid baseline summary")
    args.output.mkdir(mode=0o700, exist_ok=False)
    started = time.time_ns() // 1000000
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        collected = list(pool.map(lambda pair: collect(manifest, pair[1], pair[0], args.timeout), enumerate(nodes)))
    require(all(node["inventory_sha384"] == collected[0]["inventory_sha384"] and node["policies"] == collected[0]["policies"] and node["native_rent_parameters"] == collected[0]["native_rent_parameters"] for node in collected), "control account inventory differs between validators")
    comparisons, fee_samples, document_hashes = [], [], []
    for index, node in enumerate(collected):
        if args.baseline:
            baseline_path = args.baseline / f"node-{index}.json"
            require(hashlib.sha384(baseline_path.read_bytes()).hexdigest() == baseline_summary["nodes"][index]["private_document_sha384"], "baseline account bytes changed after capture")
            baseline = read_json(baseline_path)
            require(baseline["host"] == node["host"] and baseline["genesis_hash"] == manifest["genesis_hash"] and baseline["policies"] == node["policies"], "baseline genesis/host/policy mismatch")
            expected = expected_records(baseline["records"], lamports, tokens, node["native_rent_parameters"])
            mismatches = compare_records(baseline["records"], node["records"], lamports, tokens, node["native_rent_parameters"])
            normalized = [row["address"] for row in baseline["records"] if row["present"] and expected[row["address"]]["rent_epoch"] != row["rent_epoch"]]
            comparison = {"predicted_native_rent_epoch_normalizations": len(normalized), "predicted_normalized_addresses": normalized, "node": index, "host": node["host"], "accounts": len(baseline["records"]), "unexpected_accounts": mismatches, "all_expected_full_records_match": not mismatches}
            write_private(args.output / f"comparison-{index}.json", comparison)
            comparisons.append(comparison)
        for source, (request, event) in enumerate(zip(requests, samples)):
            receipt = rpc(nodes[index]["rpc_url"], "getTransaction", [event["id"], {"encoding": "base64", "commitment": "finalized", "maxSupportedTransactionVersion": 0}], f"control:{index}:fee:{source}", args.timeout)
            fee_samples.append({"node": index, **validate_fee_receipt(receipt, event, request, manifest)})
        node["genesis_hash"] = manifest["genesis_hash"]
        write_private(args.output / f"node-{index}.json", node)
        document_hashes.append(hashlib.sha384((args.output / f"node-{index}.json").read_bytes()).hexdigest())
    all_match = not comparisons or all(row["all_expected_full_records_match"] for row in comparisons)
    summary = {"format": "agave-pq-control-inventory-v1", "read_only": True, "actual_bank_svm_accounts": True, "phase": "post-load" if args.baseline else "pre-load-baseline", "genesis_hash": manifest["genesis_hash"], "source_sha384": hashlib.sha384(Path(__file__).read_bytes()).hexdigest(), "state_inventory_helper_sha384": hashlib.sha384(Path(shared.__file__).read_bytes()).hexdigest(), "started_unix_ms": started, "completed_unix_ms": time.time_ns() // 1000000, "validators": len(nodes), "all_validator_full_records_match": True, "accounts_per_validator": len(collected[0]["records"]), "policies_per_validator": len(collected[0]["policies"]), "managed_program_owned_vaults": 16, "legacy_authority_policies": 33, "all_wallet_authorities": 545, "fresh_system_wallets": 512, "recipient_authorities": 256, "token_accounts_including_recovered_seed": 802, "seed_program_owned_custody": True, "exact_all_metadata_and_full_bytes": True, "managed_drained_pdas_remain_absent": True, "no_posthoc_exclusions": True, "expected_changes": "counter-derived payer/recipient lamports and SPL amount bytes64..72; native rent_epoch MAX only for independently derived writable rent-exempt lanes", "native_rent_parameters": collected[0]["native_rent_parameters"], "predicted_native_rent_epoch_normalizations_per_validator": [row["predicted_native_rent_epoch_normalizations"] for row in comparisons], "predicted_native_rent_epoch_normalization_views": sum(row["predicted_native_rent_epoch_normalizations"] for row in comparisons), "all_expected_full_records_match": all_match, "unexpected_account_count": sum(len(row["unexpected_accounts"]) for row in comparisons), "total_committed_source_transactions": total_transactions, "expected_total_payer_fees_lamports": total_transactions * 5000, "expected_token_delta_sum": sum(tokens.values()), "requests_match_pre_hour_operating_point": bool(pinned), "source_ranges": source_summaries, "actual_source_fee_samples": fee_samples, "nodes": [{"node": row["node"], "host": row["host"], "inventory_sha384": row["inventory_sha384"], "context_slot_min": row["context_slot_min"], "context_slot_max": row["context_slot_max"], "private_document_sha384": document_hashes[index]} for index, row in enumerate(collected)]}
    write_private(args.output / "summary.json", summary)
    if args.public_summary:
        write_private(args.public_summary, summary)
    require(all_match, "post-load protected/full-record comparison failed; private comparison files identify mismatches")
    print(json.dumps(summary))


def self_test():
    def fails(operation):
        try:
            operation()
        except (ValueError, KeyError, TypeError):
            return
        raise AssertionError("negative case unexpectedly accepted")
    authority = b58(bytes([11]) * 32)
    token_address = b58(bytes([12]) * 32)
    payer = record(authority, {"owner": SYSTEM, "lamports": 1000000, "executable": False, "rentEpoch": 99, "data": ["", "base64"]})
    data = bytes([17]) * 64 + (10000).to_bytes(8, "little") + bytes([29]) * 93
    token = record(token_address, {"owner": TOKEN, "lamports": 2039280, "executable": False, "rentEpoch": 99, "data": [base64.b64encode(data).decode(), "base64"]})
    expected = expected_records([payer, token], {authority: -15000}, {token_address: -3})
    assert expected[authority]["lamports"] == 985000
    assert int.from_bytes(raw(expected[token_address])[64:72], "little") == 9997
    assert raw(expected[token_address])[:64] == data[:64] and raw(expected[token_address])[72:] == data[72:]
    tail_mutation = copy.deepcopy(expected[token_address])
    tail = bytearray(raw(tail_mutation)); tail[-1] ^= 1
    tail_mutation["data_base64"] = base64.b64encode(tail).decode()
    assert tail_mutation != expected[token_address]
    fails(lambda: expected_records([payer], {}, {authority: 1}))
    fails(lambda: expected_records([payer], {authority: -2000000}, {}))
    nodes = [list(expected.values()) for _ in range(8)]
    assert all(compare_records([payer, token], node, {authority: -15000}, {token_address: -3}) == [] for node in nodes)
    for field, value in [("owner", SYSTEM), ("lamports", 2039281), ("rentEpoch", 100), ("executable", True)]:
        account = {"owner": TOKEN, "lamports": 2039280, "executable": False, "rentEpoch": 99, "data": [expected[token_address]["data_base64"], "base64"]}
        account[field] = value
        changed = record(token_address, account)
        assert compare_records([payer, token], [expected[authority], changed], {authority: -15000}, {token_address: -3}) == [token_address]
    tail = bytearray(raw(expected[token_address])); tail[-1] ^= 1
    changed = record(token_address, {"owner": TOKEN, "lamports": 2039280, "executable": False, "rentEpoch": 99, "data": [base64.b64encode(tail).decode(), "base64"]})
    assert compare_records([payer, token], [expected[authority], changed], {authority: -15000}, {token_address: -3}) == [token_address]
    assert compare_records([payer, token], [expected[authority], record(token_address, None)], {authority: -15000}, {token_address: -3}) == [token_address]
    fails(lambda: compare_records([payer, token], [expected[authority]], {authority: -15000}, {token_address: -3}))
    rent_account = {"owner": SYSVAR, "lamports": 1000000, "executable": False, "rentEpoch": RENT_EXEMPT_EPOCH, "data": [base64.b64encode(struct.pack("<QdB", *FROZEN_RENT)).decode(), "base64"]}
    rent = native_rent_parameters(rent_account)
    key = lambda label: b58(hashlib.sha256(label.encode()).digest())
    def mock_account(address, owner, lamports, epoch, data=b""):
        return record(address, {"owner": owner, "lamports": lamports, "executable": False, "rentEpoch": epoch, "data": [base64.b64encode(data).decode(), "base64"]})
    recipient_rows = [mock_account(key(f"rent-recipient:{i}"), SYSTEM, 1000000000, RENT_EXEMPT_EPOCH if i == 0 else 0) for i in range(256)]
    readonly = [mock_account(key("readonly-mint"), TOKEN, 1461600, 0, bytes(82)), mock_account(key("readonly-policy"), AUTH, 100000000, 0, bytes(997)), mock_account(key("untouched-background"), key("sbf-owner"), 20000000, 0, bytes([1]) * 2048)]
    touched = {row["address"]: 13858 for row in recipient_rows}
    rent_expected = expected_records(recipient_rows + readonly, touched, {}, rent)
    assert sum(rent_expected[row["address"]]["rent_epoch"] != row["rent_epoch"] for row in recipient_rows) == 255
    assert all(rent_expected[row["address"]] == row for row in readonly)
    assert all(compare_records(recipient_rows + readonly, list(rent_expected.values()), touched, {}, rent) == [] for _ in range(8))
    # Exact epoch comparison remains mandatory: neither missed normalization
    # nor normalization of a readonly account can pass the revised audit.
    for original in (recipient_rows[1], *readonly):
        changed = copy.deepcopy(rent_expected)
        changed[original["address"]] = rebuild(changed[original["address"]], rent_epoch=0 if original is recipient_rows[1] else RENT_EXEMPT_EPOCH)
        assert compare_records(recipient_rows + readonly, list(changed.values()), touched, {}, rent) == [original["address"]]
    paying = mock_account(key("rent-paying"), SYSTEM, 1, 0)
    paying_expected = expected_records([paying], {paying["address"]: 1}, {}, rent)
    assert paying_expected[paying["address"]]["rent_epoch"] == 0
    unexpected = rebuild(paying_expected[paying["address"]], rent_epoch=RENT_EXEMPT_EPOCH)
    assert compare_records([paying], [unexpected], {paying["address"]: 1}, {}, rent) == [paying["address"]]
    fails(lambda: expected_records([paying], {paying["address"]: 890880}, {}, rent))
    wrong_owner = mock_account(key("wrong-write-owner"), AUTH, 1000000000, 0)
    fails(lambda: expected_records([wrong_owner], {wrong_owner["address"]: 1}, {}, rent))
    wrong_layout = mock_account(key("wrong-write-layout"), SYSTEM, 1000000000, 0, bytes(1))
    fails(lambda: expected_records([wrong_layout], {wrong_layout["address"]: 1}, {}, rent))
    changed_rent = copy.deepcopy(rent_account); changed_rent["owner"] = SYSTEM
    fails(lambda: native_rent_parameters(changed_rent))
    changed_rent = copy.deepcopy(rent_account); changed_rent["data"][0] = base64.b64encode(struct.pack("<QdB", 6961, 1.0, 50)).decode()
    fails(lambda: native_rent_parameters(changed_rent))
    print("native rent predictor PASS: independently writable 255 recipient 0->MAX; already-exempt unchanged; readonly mint/policy/untouched background metadata exact; nonexempt/wrong owner/layout/unexpected epoch/changed Rent rejected")
    for start in range(17):
        for count in range(37):
            assert modulo_counts(start, count, 7) == [sum(counter % 7 == i for counter in range(start, start + count)) for i in range(7)]
    key = lambda label: b58(hashlib.sha256(label.encode()).digest())
    manifest = {"wallets": [{"address": key(f"wallet:{i}")} for i in range(545)], "wallet_token_accounts": [key(f"token:{i}") for i in range(545)], "recipients": [key(f"recipient:{i}") for i in range(3)], "recipient_token_accounts": [key(f"recipient-token:{i}") for i in range(3)], "token_mint": key("mint"), "workload_program": b58(bytes([0x55]) * 32)}
    request = {"source_id": 4, "start_counter": 7, "wallet_indices": [33, 34], "recipient_count": 3, "phases": [{"seconds": 10, "target_tps": 100, "kind": "token_transfer"}]}
    result = {"actual_bank_svm": True, "actual_agave_rpc": True, "all_validator_recipient_balances_match": True, "source_id": 4, "phases": request["phases"], "counts": {"generated": 8, "admitted": 8, "finalized_success": 8, "admission_errors": 0, "finalized_error": 0}, "pending": 0, "failure": None, "last_counter_exclusive": 15, "wallet_indices": [33, 34], "recipients": manifest["recipients"], "token_recipients": manifest["recipient_token_accounts"], "system_recipient_deltas": [0, 0, 0], "token_recipient_deltas": [2, 3, 3]}
    sol, amounts, source = source_deltas(manifest, request, result)
    assert source["generated_and_committed"] == 8
    assert sol == {manifest["wallets"][33]["address"]: -20000, manifest["wallets"][34]["address"]: -20000}
    assert amounts == {manifest["wallet_token_accounts"][33]: -4, manifest["wallet_token_accounts"][34]: -4, manifest["recipient_token_accounts"][0]: 2, manifest["recipient_token_accounts"][1]: 3, manifest["recipient_token_accounts"][2]: 3}
    system_request, system_result = copy.deepcopy(request), copy.deepcopy(result)
    system_request["phases"][0]["kind"] = "system_transfer"
    system_result["phases"] = system_request["phases"]
    system_result["system_recipient_deltas"], system_result["token_recipient_deltas"] = [2, 3, 3], [0, 0, 0]
    sol, amounts, _ = source_deltas(manifest, system_request, system_result)
    assert amounts == {} and sum(sol.values()) == -8 * 5000
    assert sol[manifest["wallets"][33]["address"]] == -4 * 5001
    for field, value in [("last_counter_exclusive", 16), ("pending", 1), ("failure", "error"), ("token_recipient_deltas", [3, 3, 2])]:
        invalid = copy.deepcopy(result); invalid[field] = value
        fails(lambda: source_deltas(manifest, request, invalid))
    invalid = copy.deepcopy(result); invalid["counts"]["admission_errors"] = 1
    fails(lambda: source_deltas(manifest, request, invalid))
    invalid = copy.deepcopy(request); invalid["phases"].append({"kind": "system_transfer"})
    fails(lambda: source_deltas(manifest, invalid, result))
    for receipt in ({"meta": {"err": None, "fee": 5001}}, {"meta": {"err": "error", "fee": 5000}}):
        fails(lambda: validate_fee_receipt(receipt, {}, request, manifest))
    def encode_shortvec(value):
        output = bytearray()
        while value >= 128:
            output.append((value & 127) | 128); value >>= 7
        output.append(value)
        return bytes(output)
    def mock_receipt(kind, budget_price=False, transfer_amount=1):
        counter, signer = 7, manifest["wallets"][34]["address"]
        nonce = b"\0" + (4).to_bytes(8, "little") + counter.to_bytes(8, "little")
        instructions = [(AUTH, [signer, key("policy"), CONFIG], b"AGAVEPQ1\1" + bytes(3)), (COMPUTE, [], (b"\3" + (1).to_bytes(8, "little")) if budget_price else b"\2" + (20000).to_bytes(4, "little")), (manifest["workload_program"], [], nonce)]
        if kind == "token_transfer":
            instructions.append((TOKEN, [manifest["wallet_token_accounts"][34], manifest["token_mint"], manifest["recipient_token_accounts"][1], signer], b"\x0c" + transfer_amount.to_bytes(8, "little") + b"\0"))
        else:
            instructions.append((SYSTEM, [signer, manifest["recipients"][1]], (2).to_bytes(4, "little") + transfer_amount.to_bytes(8, "little")))
        keys = [signer]
        for program, accounts, _ in instructions:
            for address in [program, *accounts]:
                if address not in keys:
                    keys.append(address)
        wire = b"\1" + bytes([7]) * 64 + b"\1\0\0" + encode_shortvec(len(keys)) + b"".join(pubkey_bytes(address) for address in keys) + bytes(32) + encode_shortvec(len(instructions))
        for program, accounts, data in instructions:
            wire += bytes([keys.index(program)]) + encode_shortvec(len(accounts)) + bytes(keys.index(address) for address in accounts) + encode_shortvec(len(data)) + data
        return {"meta": {"err": None, "fee": 5000}, "transaction": [base64.b64encode(wire).decode(), "base64"], "slot": 42}, {"counter": counter, "id": b58(bytes([7]) * 64), "kind": kind, "recipient_index": 1}
    for kind in ("system_transfer", "token_transfer"):
        sample_request = system_request if kind == "system_transfer" else request
        receipt, event = mock_receipt(kind)
        assert validate_fee_receipt(receipt, event, sample_request, manifest)["fee"] == 5000
        changed, _ = mock_receipt(kind, budget_price=True)
        fails(lambda: validate_fee_receipt(changed, event, sample_request, manifest))
        changed, _ = mock_receipt(kind, transfer_amount=2)
        fails(lambda: validate_fee_receipt(changed, event, sample_request, manifest))
        wrong_event = copy.deepcopy(event); wrong_event["counter"] = 8
        fails(lambda: validate_fee_receipt(receipt, wrong_event, sample_request, manifest))
    key_data = b"\11" + bytes(896)
    current = commitment(b"agave-pq/auth-key/v1", [key_data])
    policy_data = b"PQAUTH01" + pubkey_bytes(authority) + key_data + current + (2).to_bytes(8, "little") + b"\3\1" + (1).to_bytes(2, "little") + bytes([27]) * 48
    account = {"owner": AUTH, "lamports": 50000000, "executable": False, "rentEpoch": 99, "data": [base64.b64encode(policy_data).decode(), "base64"]}
    assert policy(record(key("policy"), account))["generation"] == 2
    for offset in (0, 940, 985, 993, 994, 995):
        invalid = bytearray(policy_data); invalid[offset] ^= 128
        changed = copy.deepcopy(account); changed["data"][0] = base64.b64encode(invalid).decode()
        fails(lambda: policy(record(key("policy"), changed)))
    fails(lambda: wire_transaction([base64.b64encode(b"\2" + bytes(128)).decode(), "base64"]))
    fails(lambda: shared.rpc_result({"jsonrpc": "2.0", "id": "other", "result": None}, "expected"))
    print("control-inventory self-test PASS: exact token lanes/metadata, full-tail mutation, underflow, exhaustive independent modulo counters, contiguous successful ranges, actual System/SPL wire/payer/nonce checks, wrong amounts/priority fee/extra signers, policy commitment/generation/origin/legacy retirement corruption")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--source-request", type=Path, action="append", default=[])
    parser.add_argument("--source-result", type=Path, action="append", default=[])
    parser.add_argument("--operating-point", type=Path, help="optional immutable pre-hour request hash pins")
    parser.add_argument("--public-summary", type=Path)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        require(args.manifest is not None and args.output is not None, "manifest/output required")
        run(args)


if __name__ == "__main__":
    main()
