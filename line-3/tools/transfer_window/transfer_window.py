#!/usr/bin/env python3
"""Summarize ERC-20 Transfer logs from a bounded Ethereum block window."""

import argparse
from collections import Counter
import json
import re
from urllib import request


ZTO = "0xd782bdea4ef02a0bd391eb9089470c8080f0a68e"
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ZERO = "0x" + "0" * 40
RPC = "https://ethereum-rpc.publicnode.com"
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
HEX_WORD = re.compile(r"0x[0-9a-fA-F]{64}\Z")


def rpc_call(url, method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params}).encode("ascii")
    req = request.Request(url, payload, headers={
        "Content-Type": "application/json",
        "User-Agent": "IdentityMD-transfer-window/1.0",
    })
    # Do not consult proxy-related environment variables.
    opener = request.build_opener(request.ProxyHandler({}))
    with opener.open(req, timeout=30) as response:
        reply = json.load(response)
    if "error" in reply:
        raise RuntimeError(f"{method}: {reply['error']}")
    if "result" not in reply:
        raise RuntimeError(f"{method}: missing result")
    return reply["result"]


def live_logs(url, token, blocks, confirmations, chunk):
    head = int(rpc_call(url, "eth_blockNumber", []), 16)
    end = max(0, head - confirmations)
    start = max(0, end - blocks + 1)
    logs = []
    for first in range(start, end + 1, chunk):
        last = min(end, first + chunk - 1)
        logs.extend(rpc_call(url, "eth_getLogs", [{
            "address": token, "topics": [TRANSFER],
            "fromBlock": hex(first), "toBlock": hex(last),
        }]))
    return {"token": token, "fromBlock": hex(start),
            "toBlock": hex(end), "logs": logs}


def parse_log(log, token):
    if log.get("removed", False):
        return None
    if log.get("address", "").lower() != token:
        raise ValueError("log address does not match token")
    topics = log.get("topics", [])
    if len(topics) != 3 or topics[0].lower() != TRANSFER:
        raise ValueError("expected a standard three-topic Transfer log")
    for topic in topics[1:]:
        if not HEX_WORD.fullmatch(topic) or int(topic[2:26], 16) != 0:
            raise ValueError("invalid indexed address")
    data = log.get("data", "")
    if not HEX_WORD.fullmatch(data):
        raise ValueError("expected one uint256 value in Transfer data")
    return {
        "from": "0x" + topics[1][-40:].lower(),
        "to": "0x" + topics[2][-40:].lower(),
        "value": int(data, 16),
        "block": int(log["blockNumber"], 16),
        "tx": log["transactionHash"].lower(),
        "index": int(log["logIndex"], 16),
    }


def pct(part, whole):
    return f"{(part * 1000 // whole) / 10:.1f}%" if whole else "0.0%"


def top(counter, volume, limit=3):
    return [{"address": address, "volume_raw": str(amount),
             "share": pct(amount, volume)}
            for address, amount in counter.most_common(limit)]


def summarize(snapshot):
    token = snapshot["token"].lower()
    if not ADDRESS.fullmatch(token):
        raise ValueError("invalid token address")
    start = int(snapshot["fromBlock"], 16)
    end = int(snapshot["toBlock"], 16)
    if end < start:
        raise ValueError("reversed block range")
    seen = set()
    transfers = []
    for raw in snapshot["logs"]:
        item = parse_log(raw, token)
        if item is None:
            continue
        if not start <= item["block"] <= end:
            raise ValueError("log outside declared block range")
        identity = (item["tx"], item["index"])
        if identity not in seen:
            transfers.append(item)
            seen.add(identity)
    sent = Counter()
    received = Counter()
    per_block = Counter()
    volume = 0
    minted = 0
    burned = 0
    self_count = 0
    largest = None
    for item in transfers:
        amount = item["value"]
        volume += amount
        sent[item["from"]] += amount
        received[item["to"]] += amount
        per_block[item["block"]] += 1
        minted += amount if item["from"] == ZERO else 0
        burned += amount if item["to"] == ZERO else 0
        self_count += item["from"] == item["to"]
        if largest is None or amount > largest["value"]:
            largest = item
    count = len(transfers)
    busiest = min(per_block, key=lambda block: (-per_block[block], block)) if per_block else None
    signals = []
    if count >= 5 and volume and largest["value"] * 2 >= volume:
        signals.append("One transfer carried " + pct(largest["value"], volume) + " of volume")
    if count >= 5 and volume and received.most_common(1)[0][1] * 2 >= volume:
        signals.append("One recipient received " + pct(received.most_common(1)[0][1], volume) + " of volume")
    if count >= 5 and per_block[busiest] * 5 >= count * 2:
        signals.append("One block held " + pct(per_block[busiest], count) + " of transfers")
    if minted:
        signals.append("Mint-address transfers appeared")
    if burned:
        signals.append("Burn-address transfers appeared")
    return {
        "token": token, "from_block": start, "to_block": end,
        "transfer_count": count, "volume_raw": str(volume),
        "minted_raw": str(minted), "burned_raw": str(burned),
        "self_transfer_count": self_count,
        "unique_senders": len(sent), "unique_recipients": len(received),
        "largest_transfer": None if largest is None else {
            "value_raw": str(largest["value"]), "share": pct(largest["value"], volume),
            "block": largest["block"], "tx": largest["tx"]},
        "busiest_block": None if busiest is None else {
            "block": busiest, "transfers": per_block[busiest],
            "share": pct(per_block[busiest], count)},
        "top_senders": top(sent, volume), "top_recipients": top(received, volume),
        "signals": signals,
    }


def print_report(report):
    print(f"Token {report['token']}")
    print(f"Blocks {report['from_block']}–{report['to_block']}: "
          f"{report['transfer_count']} transfers; {report['volume_raw']} raw units moved")
    print(f"Senders {report['unique_senders']}; recipients {report['unique_recipients']}; "
          f"self-transfers {report['self_transfer_count']}")
    if report["largest_transfer"]:
        item = report["largest_transfer"]
        print(f"Largest: {item['value_raw']} raw units ({item['share']}) in block {item['block']}")
        item = report["busiest_block"]
        print(f"Busiest block: {item['block']} ({item['transfers']} transfers, {item['share']})")
    for label, key in (("Top sender", "top_senders"), ("Top recipient", "top_recipients")):
        if report[key]:
            item = report[key][0]
            print(f"{label}: {item['address']} ({item['share']} of raw volume)")
    for signal in report["signals"]:
        print("Signal: " + signal)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token", default=ZTO, help="ERC-20 address (default: ZTO)")
    parser.add_argument("--rpc", default=RPC, help="public Ethereum JSON-RPC URL")
    parser.add_argument("--blocks", type=int, default=2000, help="live window length, at most 100000")
    parser.add_argument("--confirmations", type=int, default=12)
    parser.add_argument("--chunk", type=int, default=500, help="blocks per eth_getLogs request")
    parser.add_argument("--input", help="read a saved JSON log snapshot instead of calling RPC")
    parser.add_argument("--json", action="store_true", help="print machine-readable summary")
    args = parser.parse_args()
    if not ADDRESS.fullmatch(args.token):
        parser.error("--token must be a 20-byte hex address")
    if not 1 <= args.blocks <= 100000 or not 1 <= args.chunk <= 2000 or args.confirmations < 0:
        parser.error("invalid block window, chunk size, or confirmations")
    try:
        if args.input:
            with open(args.input, encoding="utf-8") as stream:
                snapshot = json.load(stream)
        else:
            snapshot = live_logs(args.rpc, args.token.lower(), args.blocks,
                                 args.confirmations, args.chunk)
        report = summarize(snapshot)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        parser.exit(1, f"transfer-window: {exc}\n")
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
