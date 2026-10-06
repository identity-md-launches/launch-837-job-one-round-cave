#!/usr/bin/env python3
"""Read common ERC-20 identity fields through read-only Ethereum JSON-RPC."""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request


ZTO = "0xd782bdea4ef02a0bd391eb9089470c8080f0a68e"
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"
SELECTORS = {
    "name": "0x06fdde03",
    "symbol": "0x95d89b41",
    "decimals": "0x313ce567",
    "total_supply_raw": "0x18160ddd",
}


class RpcError(Exception):
    pass


def rpc(url, method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Pepeolithic-TokenIdentity/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise RpcError(str(exc)) from exc
    if "error" in result:
        error = result["error"]
        raise RpcError(error.get("message", str(error)) if isinstance(error, dict) else str(error))
    if "result" not in result:
        raise RpcError("JSON-RPC response has no result")
    return result["result"]


def decoded_text(hex_data):
    raw = bytes.fromhex(hex_data.removeprefix("0x"))
    if len(raw) == 32:
        text = raw.rstrip(b"\0")
    elif len(raw) >= 64:
        offset = int.from_bytes(raw[:32], "big")
        if offset + 32 > len(raw):
            raise ValueError("invalid ABI string offset")
        length = int.from_bytes(raw[offset:offset + 32], "big")
        if offset + 32 + length > len(raw):
            raise ValueError("truncated ABI string")
        text = raw[offset + 32:offset + 32 + length]
    else:
        raise ValueError("response is too short for string or bytes32")
    return text.decode("utf-8")


def decoded_uint(hex_data):
    raw = bytes.fromhex(hex_data.removeprefix("0x"))
    if len(raw) != 32:
        raise ValueError("expected one uint256 word")
    return int.from_bytes(raw, "big")


def decimal_units(raw_units, decimals):
    """Render integer base units exactly, without floating point rounding."""
    digits = str(raw_units)
    if decimals == 0:
        return digits
    padded = digits.zfill(decimals + 1)
    whole, fraction = padded[:-decimals], padded[-decimals:].rstrip("0")
    return whole + ("." + fraction if fraction else "")


def inspect(url, address):
    chain_id = int(rpc(url, "eth_chainId", []), 16)
    block_hex = rpc(url, "eth_blockNumber", [])
    code = rpc(url, "eth_getCode", [address, block_hex])
    if not isinstance(code, str) or not code.startswith("0x") or len(code) % 2:
        raise RpcError("invalid code response")
    result = {
        "address": address.lower(),
        "chain_id": chain_id,
        "block_number": int(block_hex, 16),
        "runtime_code_bytes": (len(code) - 2) // 2,
        "name": None,
        "symbol": None,
        "decimals": None,
        "total_supply_raw": None,
        "total_supply": None,
        "field_errors": {},
    }
    if code == "0x":
        result["field_errors"]["contract"] = "no code at this address at the observed block"
        return result
    for field, selector in SELECTORS.items():
        try:
            answer = rpc(url, "eth_call", [{"to": address, "data": selector}, block_hex])
            if not isinstance(answer, str) or not answer.startswith("0x"):
                raise ValueError("invalid call response")
            value = decoded_text(answer) if field in ("name", "symbol") else decoded_uint(answer)
            result[field] = str(value) if field == "total_supply_raw" else value
        except (RpcError, ValueError, UnicodeDecodeError) as exc:
            result["field_errors"][field] = str(exc)
    if result["total_supply_raw"] is not None and result["decimals"] is not None:
        if result["decimals"] <= 255:
            result["total_supply"] = decimal_units(result["total_supply_raw"], result["decimals"])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", default=ZTO, help="Ethereum token contract address (default: ZTO)")
    parser.add_argument("--rpc", default=DEFAULT_RPC, help="public Ethereum JSON-RPC endpoint")
    args = parser.parse_args()
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", args.address):
        parser.error("--address must be a 20-byte hex address")
    try:
        result = inspect(args.rpc, args.address)
    except RpcError as exc:
        print(f"RPC error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
