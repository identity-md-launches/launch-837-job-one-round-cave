#!/usr/bin/env python3
"""Connect a real ERC-20 Transfer-log window to the call that caused its largest transfer."""

import argparse
import importlib.util
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOGS = ROOT / "line-3/tools/transfer_window/zto_sample.json"
DEFAULT_TX = ROOT / "shared/zto_largest_transfer_tx.json"
sys.dont_write_bytecode = True  # imported line tools remain unchanged


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


window = load_module("transfer_window", ROOT / "line-3/tools/transfer_window/transfer_window.py")
decoder = load_module("calldata_decoder", ROOT / "line-4/tools/calldata_decoder/decode.py")


def explain(snapshot, tx):
    report = window.summarize(snapshot)
    largest = report["largest_transfer"]
    if largest is None:
        raise ValueError("the window has no transfers")
    if tx.get("hash", "").lower() != largest["tx"]:
        raise ValueError("transaction hash does not match the window's largest transfer")
    if tx.get("blockNumber") != largest["block"]:
        raise ValueError("transaction block does not match the Transfer log")
    calldata = tx.get("input", "")
    if not isinstance(calldata, str) or not calldata.startswith("0x"):
        raise ValueError("transaction has no hex calldata")
    try:
        payload = bytes.fromhex(calldata[2:])
    except ValueError as exc:
        raise ValueError("transaction calldata is invalid hex") from exc
    matching = [window.parse_log(log, report["token"]) for log in snapshot["logs"]
                if log.get("transactionHash", "").lower() == largest["tx"]]
    matching = [item for item in matching if item is not None]
    tree = decoder.decode_call(payload)
    return {
        "token": report["token"],
        "window": [report["from_block"], report["to_block"]],
        "window_transfers": report["transfer_count"],
        "window_signals": report["signals"],
        "selected_tx": largest["tx"],
        "selected_block": largest["block"],
        "largest_transfer_raw": largest["value_raw"],
        "selected_tx_transfer_count": len(matching),
        "selected_tx_volume_raw": str(sum(item["value"] for item in matching)),
        "call_to": tx.get("to"),
        "calldata": tree,
        "interpretation": "Transfer logs show observed effects; calldata describes a proposed call. Guessed layouts are uncertain.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs", type=Path, default=DEFAULT_LOGS, help="line-3 log snapshot JSON")
    parser.add_argument("--tx-json", type=Path, help="saved matching transaction JSON; defaults to live RPC")
    parser.add_argument("--rpc", default=decoder.RPC, help="read-only Ethereum JSON-RPC endpoint")
    parser.add_argument("--json", action="store_true", help="print machine-readable result")
    args = parser.parse_args()
    try:
        with args.logs.open(encoding="utf-8") as source:
            snapshot = json.load(source)
        report = window.summarize(snapshot)
        if report["largest_transfer"] is None:
            raise ValueError("the window has no transfers")
        if args.tx_json:
            with args.tx_json.open(encoding="utf-8") as source:
                tx = json.load(source)
        elif args.logs.resolve() == DEFAULT_LOGS and DEFAULT_TX.exists():
            with DEFAULT_TX.open(encoding="utf-8") as source:
                tx = json.load(source)
        else:
            tx = decoder.fetch_tx(args.rpc, report["largest_transfer"]["tx"])
        result = explain(snapshot, tx)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        parser.exit(1, f"transfer-call-bridge: {exc}\n")
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print(f"Token {result['token']} window {result['window'][0]}–{result['window'][1]}: "
          f"{result['window_transfers']} transfers")
    print(f"Largest transfer: {result['largest_transfer_raw']} raw units in "
          f"{result['selected_tx']} (block {result['selected_block']})")
    print(f"This transaction emitted {result['selected_tx_transfer_count']} token transfers, "
          f"totalling {result['selected_tx_volume_raw']} raw units.")
    print(f"Call target: {result['call_to']}")
    print("\n".join(decoder.render(result["calldata"])))
    print(result["interpretation"])


if __name__ == "__main__":
    main()
