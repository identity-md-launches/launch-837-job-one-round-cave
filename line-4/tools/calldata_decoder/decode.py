#!/usr/bin/env python3
"""Explain raw Ethereum calldata without the target contract's ABI.

Known selectors come from a bundled signature list whose selectors are
computed here with a pure-Python Keccak-256. Byte arguments that hold further
calls (multicalls, smart-account executes, ERC-4337 bundles, Uniswap Universal
Router commands and v4 actions) are opened and decoded in turn. Unknown
selectors are laid out structurally from the ABI encoding alone and marked as
guesses. Read-only: it never signs, sends or reads secrets.
"""

import argparse
import hashlib
import json
import re
import sys
import time
from urllib import request

RPC = "https://ethereum-rpc.publicnode.com"
FALLBACK_RPCS = ["https://eth.drpc.org"]
UA = "IdentityMD-calldata-decoder/1.0"
ZTO = "0xd782bdea4ef02a0bd391eb9089470c8080f0a68e"
IMD = "0xd34a99bc0f67ae1bbd63c660e6d0b0dd03e263b7"
ZTO_HOOK = "0x784ff9a3ac5d88a30bfff6f7f2a270161fbe6000"
ZTO_POOL_ID = "0x888b07bd282f587d3c6b0fcb23e7fc55bbb33abe8910dd7492db815dc8dc5592"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
MAX_DEPTH = 8


# --- Keccak-256 (the pre-NIST padding Ethereum uses) -------------------------

def _keccak_f(lanes):
    r = 1
    mask = (1 << 64) - 1

    def rol(v, n):
        n %= 64
        return ((v << n) | (v >> (64 - n))) & mask

    for _ in range(24):
        c = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4]
             for x in range(5)]
        d = [c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
        lanes = [[lanes[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        x, y = 1, 0
        cur = lanes[x][y]
        for t in range(24):
            x, y = y, (2 * x + 3 * y) % 5
            cur, lanes[x][y] = lanes[x][y], rol(cur, (t + 1) * (t + 2) // 2)
        for y in range(5):
            row = [lanes[x][y] for x in range(5)]
            for x in range(5):
                lanes[x][y] = row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
        for j in range(7):
            r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
            if r & 2:
                lanes[0][0] ^= 1 << ((1 << j) - 1)
    return lanes


def keccak256(data, pad=0x01):
    rate = 136
    msg = bytearray(data) + bytes([pad])
    msg += b"\x00" * (-len(msg) % rate)
    msg[-1] |= 0x80
    lanes = [[0] * 5 for _ in range(5)]
    for block in range(0, len(msg), rate):
        for i in range(rate // 8):
            lanes[i % 5][i // 5] ^= int.from_bytes(msg[block + 8 * i:block + 8 * i + 8], "little")
        lanes = _keccak_f(lanes)
    out = b"".join(lanes[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


# --- ABI types ---------------------------------------------------------------

class DecodeError(ValueError):
    pass


def _split_top(s):
    parts, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def parse_type(s):
    s = s.strip()
    depth = 0
    for i, ch in enumerate(s):  # drop a parameter name such as "address to"
        depth += ch == "("
        depth -= ch == ")"
        if ch == " " and depth == 0:
            s = s[:i]
            break
    if s.endswith("]"):
        i = s.rindex("[")
        n = s[i + 1:-1]
        return ("array", parse_type(s[:i]), int(n) if n else None)
    if s.startswith("tuple("):
        s = s[5:]
    if s.startswith("("):
        return ("tuple", [parse_type(p) for p in _split_top(s[1:-1])])
    if s in ("uint", "int"):
        s += "256"
    if not re.fullmatch(r"address|bool|string|bytes([0-9]+)?|u?int[0-9]+|function", s):
        raise DecodeError(f"unsupported type {s!r}")
    return ("base", s)


def type_str(node):
    if node[0] == "base":
        return node[1]
    if node[0] == "tuple":
        return "(" + ",".join(type_str(c) for c in node[1]) + ")"
    return type_str(node[1]) + "[" + ("" if node[2] is None else str(node[2])) + "]"


def parse_sig(sig):
    sig = sig.strip()
    i = sig.index("(")
    if not sig.endswith(")"):
        raise DecodeError(f"bad signature {sig!r}")
    types = [parse_type(p) for p in _split_top(sig[i + 1:-1])]
    canon = sig[:i] + "(" + ",".join(type_str(t) for t in types) + ")"
    return canon, types


def selector(canon):
    return "0x" + keccak256(canon.encode()).hex()[:8]


def is_dynamic(node):
    if node[0] == "base":
        return node[1] in ("bytes", "string")
    if node[0] == "tuple":
        return any(is_dynamic(c) for c in node[1])
    return node[2] is None or is_dynamic(node[1])


def head_size(node):
    if is_dynamic(node):
        return 32
    if node[0] == "tuple":
        return sum(head_size(c) for c in node[1])
    if node[0] == "array":
        return node[2] * head_size(node[1])
    return 32


def _word(data, pos):
    if pos < 0 or pos + 32 > len(data):
        raise DecodeError("read past end of data")
    return int.from_bytes(data[pos:pos + 32], "big")


def _static(name, raw):
    v = int.from_bytes(raw, "big")
    if name == "address":
        if v >> 160:
            raise DecodeError("address has dirty high bytes")
        return "0x" + raw[12:].hex()
    if name == "bool":
        if v > 1:
            raise DecodeError("bool is not 0 or 1")
        return bool(v)
    m = re.fullmatch(r"(u?)int([0-9]+)", name)
    if m:
        bits = int(m.group(2))
        if m.group(1):
            if v >> bits:
                raise DecodeError(f"value does not fit {name}")
            return v
        if v >= 1 << 255:
            v -= 1 << 256
        if not -(1 << (bits - 1)) <= v < 1 << (bits - 1):
            raise DecodeError(f"value does not fit {name}")
        return v
    m = re.fullmatch(r"bytes([0-9]+)", name)
    if m:
        n = int(m.group(1))
        if any(raw[n:]):
            raise DecodeError(f"{name} has dirty padding")
        return "0x" + raw[:n].hex()
    return "0x" + raw.hex()  # function


def _decode_seq(children, data, start):
    out, pos = [], start
    for c in children:
        if is_dynamic(c):
            loc = start + _word(data, pos)
            if loc > len(data):
                raise DecodeError("offset points past end of data")
            out.append(_decode_tail(c, data, loc))
        else:
            out.append(_decode_static(c, data, pos))
        pos += head_size(c)
    return out


def _decode_static(node, data, pos):
    if node[0] == "base":
        if pos + 32 > len(data):
            raise DecodeError("read past end of data")
        return _static(node[1], data[pos:pos + 32])
    if node[0] == "tuple":
        return _decode_seq(node[1], data, pos)
    return _decode_seq([node[1]] * node[2], data, pos)


def _decode_tail(node, data, loc):
    if node[0] == "base":
        n = _word(data, loc)
        if loc + 32 + n > len(data):
            raise DecodeError("byte string runs past end of data")
        raw = data[loc + 32:loc + 32 + n]
        if any(data[loc + 32 + n:loc + 32 + n + (-n % 32)]):
            raise DecodeError("byte string has dirty padding")
        if node[1] == "string":
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise DecodeError("string is not UTF-8") from exc
        return raw
    if node[0] == "tuple":
        return _decode_seq(node[1], data, loc)
    count = node[2]
    if count is None:
        count = _word(data, loc)
        loc += 32
        if count * 32 > len(data) - loc:
            raise DecodeError("array length runs past end of data")
    return _decode_seq([node[1]] * count, data, loc)


def abi_decode(types, data):
    return _decode_seq(types, data, 0)


# --- What the bundled table knows --------------------------------------------

POOL_KEY = "(address,address,uint24,int24,address)"
PATH_KEY = "(address,uint24,int24,address,bytes)"
SIGNATURES = [
    # ERC-20 / ERC-721 / WETH / Permit2
    "transfer(address to,uint256 amount)",
    "approve(address spender,uint256 amount)",
    "transferFrom(address from,address to,uint256 amount)",
    "increaseAllowance(address spender,uint256 added)",
    "decreaseAllowance(address spender,uint256 subtracted)",
    "permit(address owner,address spender,uint256 value,uint256 deadline,uint8 v,bytes32 r,bytes32 s)",
    "safeTransferFrom(address from,address to,uint256 tokenId)",
    "safeTransferFrom(address from,address to,uint256 tokenId,bytes data)",
    "setApprovalForAll(address operator,bool approved)",
    "deposit()",
    "withdraw(uint256 amount)",
    "approve(address token,address spender,uint160 amount,uint48 expiration)",
    "permit(address owner,((address,uint160,uint48,uint48),address,uint256) permitSingle,bytes signature)",
    "transferFrom(address from,address to,uint160 amount,address token)",
    "lockdown((address,address)[] approvals)",
    # Multicall
    "aggregate((address,bytes)[] calls)",
    "tryAggregate(bool requireSuccess,(address,bytes)[] calls)",
    "aggregate3((address,bool,bytes)[] calls)",
    "aggregate3Value((address,bool,uint256,bytes)[] calls)",
    "multicall(bytes[] data)",
    "multicall(uint256 deadline,bytes[] data)",
    "multicall(bytes32 previousBlockhash,bytes[] data)",
    # Smart accounts and ERC-4337
    "execute(address dest,uint256 value,bytes func)",
    "executeBatch(address[] dest,bytes[] func)",
    "executeBatch(address[] dest,uint256[] value,bytes[] func)",
    "executeBatch((address,uint256,bytes)[] calls)",
    "execute(bytes32 mode,bytes executionCalldata)",
    "execTransaction(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,bytes signatures)",
    "multiSend(bytes transactions)",
    "handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[] ops,address beneficiary)",
    "handleOps((address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[] ops,address beneficiary)",
    # Uniswap routers
    "execute(bytes commands,bytes[] inputs,uint256 deadline)",
    "execute(bytes commands,bytes[] inputs)",
    "modifyLiquidities(bytes unlockData,uint256 deadline)",
    "modifyLiquiditiesWithoutUnlock(bytes actions,bytes[] params)",
    "unlock(bytes data)",
    "initialize(" + POOL_KEY + " key,uint160 sqrtPriceX96)",
    "swap(" + POOL_KEY + " key,(bool,int256,uint160) params,bytes hookData)",
    "modifyLiquidity(" + POOL_KEY + " key,(int24,int24,int256,bytes32) params,bytes hookData)",
    "settle()",
    "sync(address currency)",
    "take(address currency,address to,uint256 amount)",
    "swapExactTokensForTokens(uint256 amountIn,uint256 amountOutMin,address[] path,address to,uint256 deadline)",
    "swapTokensForExactTokens(uint256 amountOut,uint256 amountInMax,address[] path,address to,uint256 deadline)",
    "swapExactETHForTokens(uint256 amountOutMin,address[] path,address to,uint256 deadline)",
    "swapExactTokensForETH(uint256 amountIn,uint256 amountOutMin,address[] path,address to,uint256 deadline)",
    "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256 amountIn,uint256 amountOutMin,address[] path,address to,uint256 deadline)",
    "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256 amountOutMin,address[] path,address to,uint256 deadline)",
    "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256 amountIn,uint256 amountOutMin,address[] path,address to,uint256 deadline)",
    "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160) params)",
    "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160) params)",
    "exactInput((bytes,address,uint256,uint256,uint256) params)",
    "exactInput((bytes,address,uint256,uint256) params)",
    "unwrapWETH9(uint256 amountMinimum,address recipient)",
    "refundETH()",
]

# Uniswap Universal Router command byte -> (name, input types)
UR_COMMANDS = {
    0x00: ("V3_SWAP_EXACT_IN", "address recipient,uint256 amountIn,uint256 amountOutMin,bytes path,bool payerIsUser"),
    0x01: ("V3_SWAP_EXACT_OUT", "address recipient,uint256 amountOut,uint256 amountInMax,bytes path,bool payerIsUser"),
    0x02: ("PERMIT2_TRANSFER_FROM", "address token,address recipient,uint160 amount"),
    0x03: ("PERMIT2_PERMIT_BATCH", "((address,uint160,uint48,uint48)[],address,uint256) permitBatch,bytes signature"),
    0x04: ("SWEEP", "address token,address recipient,uint256 amountMin"),
    0x05: ("TRANSFER", "address token,address recipient,uint256 value"),
    0x06: ("PAY_PORTION", "address token,address recipient,uint256 bips"),
    0x08: ("V2_SWAP_EXACT_IN", "address recipient,uint256 amountIn,uint256 amountOutMin,address[] path,bool payerIsUser"),
    0x09: ("V2_SWAP_EXACT_OUT", "address recipient,uint256 amountOut,uint256 amountInMax,address[] path,bool payerIsUser"),
    0x0a: ("PERMIT2_PERMIT", "((address,uint160,uint48,uint48),address,uint256) permitSingle,bytes signature"),
    0x0b: ("WRAP_ETH", "address recipient,uint256 amount"),
    0x0c: ("UNWRAP_WETH", "address recipient,uint256 amountMin"),
    0x0d: ("PERMIT2_TRANSFER_FROM_BATCH", "(address,address,uint160,address)[] transfers"),
    0x0e: ("BALANCE_CHECK_ERC20", "address owner,address token,uint256 minBalance"),
    0x10: ("V4_SWAP", "bytes actions,bytes[] params"),
    0x11: ("V3_POSITION_MANAGER_PERMIT", None),
    0x12: ("V3_POSITION_MANAGER_CALL", None),
    0x13: ("V4_INITIALIZE_POOL", POOL_KEY + " poolKey,uint160 sqrtPriceX96"),
    0x14: ("V4_POSITION_MANAGER_CALL", None),
    0x21: ("EXECUTE_SUB_PLAN", "bytes commands,bytes[] inputs"),
}

# Uniswap v4 periphery action byte -> (name, [alternative parameter layouts])
V4_ACTIONS = {
    0x00: ("INCREASE_LIQUIDITY", ["uint256 tokenId,uint256 liquidity,uint128 amount0Max,uint128 amount1Max,bytes hookData"]),
    0x01: ("DECREASE_LIQUIDITY", ["uint256 tokenId,uint256 liquidity,uint128 amount0Min,uint128 amount1Min,bytes hookData"]),
    0x02: ("MINT_POSITION", [POOL_KEY + " poolKey,int24 tickLower,int24 tickUpper,uint256 liquidity,uint128 amount0Max,uint128 amount1Max,address owner,bytes hookData"]),
    0x03: ("BURN_POSITION", ["uint256 tokenId,uint128 amount0Min,uint128 amount1Min,bytes hookData"]),
    0x04: ("INCREASE_LIQUIDITY_FROM_DELTAS", ["uint256 tokenId,uint128 amount0Max,uint128 amount1Max,bytes hookData"]),
    0x05: ("MINT_POSITION_FROM_DELTAS", [POOL_KEY + " poolKey,int24 tickLower,int24 tickUpper,uint128 amount0Max,uint128 amount1Max,address owner,bytes hookData"]),
    0x06: ("SWAP_EXACT_IN_SINGLE", ["(" + POOL_KEY + ",bool,uint128,uint128,bytes) params",
                                    "(" + POOL_KEY + ",bool,uint128,uint128,uint256,bytes) params"]),
    0x07: ("SWAP_EXACT_IN", ["(address," + PATH_KEY + "[],uint128,uint128) params",
                             "(address," + PATH_KEY + "[],uint256[],uint128,uint128) params"]),
    0x08: ("SWAP_EXACT_OUT_SINGLE", ["(" + POOL_KEY + ",bool,uint128,uint128,bytes) params",
                                     "(" + POOL_KEY + ",bool,uint128,uint128,uint256,bytes) params"]),
    0x09: ("SWAP_EXACT_OUT", ["(address," + PATH_KEY + "[],uint128,uint128) params",
                              "(address," + PATH_KEY + "[],uint256[],uint128,uint128) params"]),
    0x0a: ("DONATE", [POOL_KEY + " poolKey,uint256 amount0,uint256 amount1,bytes hookData"]),
    0x0b: ("SETTLE", ["address currency,uint256 amount,bool payerIsUser"]),
    0x0c: ("SETTLE_ALL", ["address currency,uint256 maxAmount"]),
    0x0d: ("SETTLE_PAIR", ["address currency0,address currency1"]),
    0x0e: ("TAKE", ["address currency,address recipient,uint256 amount"]),
    0x0f: ("TAKE_ALL", ["address currency,uint256 minAmount"]),
    0x10: ("TAKE_PORTION", ["address currency,address recipient,uint256 bips"]),
    0x11: ("TAKE_PAIR", ["address currency0,address currency1,address recipient"]),
    0x12: ("CLOSE_CURRENCY", ["address currency"]),
    0x13: ("CLEAR_OR_TAKE", ["address currency,uint256 amountMax"]),
    0x14: ("SWEEP", ["address currency,address recipient"]),
    0x15: ("WRAP", ["uint256 amount"]),
    0x16: ("UNWRAP", ["uint256 amount"]),
    0x17: ("MINT_6909", ["address currency,address recipient,uint256 amount"]),
    0x18: ("BURN_6909", ["address currency,address owner,uint256 amount"]),
}

LABELS = {
    ZTO: "ZTO (Zero To One)",
    IMD: "IMD",
    ZTO_HOOK: "hook of the ZTO/IMD v4 pool",
    "0x0000000000000000000000000000000000000000": "zero address / native ETH",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
    "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
    "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
    "0x000000000004444c5dc75cb358380d2e3de08a90": "Uniswap v4 PoolManager",
    "0xbd216513d74c8cf14cf4747e6aaa6420ff64ee9e": "Uniswap v4 PositionManager",
    "0x66a9893cc07d91d95644aedd05d03f95e1dba8af": "Uniswap Universal Router (v4)",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router (v1.2)",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap v2 Router02",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap v3 SwapRouter02",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap v3 SwapRouter",
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Permit2",
    "0xca11bde05977b3631167028862be2a173976ca11": "Multicall3",
    "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789": "ERC-4337 EntryPoint v0.6",
    "0x0000000071727de22e5e9d8baf0edac6f37da032": "ERC-4337 EntryPoint v0.7",
    "0x4337084d9e255ff0702461cf8895ce9e3b5ff108": "ERC-4337 EntryPoint v0.8",
}


def build_table(extra=()):
    table = {}
    for sig in list(SIGNATURES) + list(extra):
        canon, types = parse_sig(sig)
        table.setdefault(selector(canon), []).append((sig, canon, types))
    return table


TABLE = build_table()


# --- Turning bytes into an annotated tree ------------------------------------

def _hex(raw):
    return "0x" + raw.hex()


def pool_id(key):
    enc = b"".join(int(str(v), 0).to_bytes(32, "big", signed=True) if i in (2, 3)
                   else int(v, 16).to_bytes(32, "big") for i, v in enumerate(key))
    return _hex(keccak256(enc))


def _param_names(sig):
    inner = sig[sig.index("(") + 1:-1]
    names = []
    for part in _split_top(inner):
        bits = part.strip().rsplit(" ", 1)
        names.append(bits[1] if len(bits) == 2 and not bits[1].endswith(")") else "")
    return names


def annotate(node, value, depth):
    """Wrap a decoded value with its type, labels and any nested decoding."""
    out = {"type": type_str(node)}
    if node[0] == "tuple":
        out["items"] = [annotate(c, v, depth) for c, v in zip(node[1], value)]
        if type_str(node) == POOL_KEY:
            pid = pool_id(value)
            out["poolId"] = pid
            if pid == ZTO_POOL_ID:
                out["note"] = "this is the ZTO/IMD Uniswap v4 pool"
        return out
    if node[0] == "array":
        out["items"] = [annotate(node[1], v, depth) for v in value]
        return out
    name = node[1]
    if isinstance(value, (bytes, bytearray)):
        out["value"] = _hex(value)
        inner = decode_call(bytes(value), depth + 1) if len(value) >= 4 and depth < MAX_DEPTH else None
        if inner and (not inner.get("guessed") or (len(value) - 4) % 32 == 0):
            out["call"] = inner
        return out
    out["value"] = value if not isinstance(value, int) or isinstance(value, bool) else str(value)
    if name == "address" and value in LABELS:
        out["label"] = LABELS[value]
    return out


def _named(sig, types, values, depth):
    names = _param_names(sig)
    return [dict(annotate(t, v, depth), name=n) if n else annotate(t, v, depth)
            for t, v, n in zip(types, values, names)]


def _try_layouts(layouts, data, depth):
    for layout in layouts:
        sig = "f(" + layout + ")"
        _, types = parse_sig(sig)
        try:
            values = abi_decode(types, data)
        except DecodeError:
            continue
        return _named(sig, types, values, depth)
    return None


def _plan(commands, inputs, depth):
    steps = []
    for i, cmd in enumerate(commands):
        code = cmd & 0x3f
        name, layout = UR_COMMANDS.get(code, (f"UNKNOWN_0x{code:02x}", None))
        step = {"command": name, "allowRevert": bool(cmd & 0x80)}
        raw = inputs[i] if i < len(inputs) else b""
        args = _try_layouts([layout], raw, depth) if layout else None
        if args is None:
            step["input"] = _hex(raw)
            if layout:
                step["note"] = "input did not match the expected layout"
        else:
            step["args"] = args
            if code == 0x10:  # V4_SWAP
                step["actions"] = _v4_actions(bytes.fromhex(args[0]["value"][2:]),
                                              [bytes.fromhex(p["value"][2:]) for p in args[1]["items"]],
                                              depth)
            elif code == 0x21:
                step["plan"] = _plan(bytes.fromhex(args[0]["value"][2:]),
                                     [bytes.fromhex(p["value"][2:]) for p in args[1]["items"]], depth)
        steps.append(step)
    return steps


def _v4_actions(actions, params, depth):
    out = []
    for i, code in enumerate(actions):
        name, layouts = V4_ACTIONS.get(code, (f"UNKNOWN_0x{code:02x}", []))
        raw = params[i] if i < len(params) else b""
        args = _try_layouts(layouts, raw, depth)
        item = {"action": name}
        if args is None:
            item["input"] = _hex(raw)
        else:
            item["args"] = args
        out.append(item)
    return out


def _special(canon, values, depth):
    """Extra structure for calls whose byte arguments are their own language."""
    if canon in ("execute(bytes,bytes[],uint256)", "execute(bytes,bytes[])"):
        return {"plan": _plan(values[0], values[1], depth)}
    if canon == "modifyLiquidities(bytes,uint256)":
        try:
            actions, params = abi_decode(parse_sig("f(bytes,bytes[])")[1], values[0])
        except DecodeError:
            return {}
        return {"actions": _v4_actions(actions, params, depth)}
    if canon == "modifyLiquiditiesWithoutUnlock(bytes,bytes[])":
        return {"actions": _v4_actions(values[0], values[1], depth)}
    if canon == "multiSend(bytes)":
        txs, data, pos = [], values[0], 0
        while pos + 85 <= len(data):
            n = int.from_bytes(data[pos + 53:pos + 85], "big")
            call = data[pos + 85:pos + 85 + n]
            to = _hex(data[pos + 1:pos + 21])
            tx = {"operation": "delegatecall" if data[pos] else "call", "to": to,
                  "value": str(int.from_bytes(data[pos + 21:pos + 53], "big"))}
            if to in LABELS:
                tx["label"] = LABELS[to]
            if call:
                tx["call"] = decode_call(call, depth + 1)
            txs.append(tx)
            pos += 85 + n
        return {"transactions": txs}
    if canon == "execute(bytes32,bytes)" and values[0][2:4] == "00":
        try:  # ERC-7579 single call: abi.encodePacked(target, value, callData)
            target, data = values[1][:20], values[1][52:]
            return {"single": {"to": _hex(target), "value": str(int.from_bytes(values[1][20:52], "big")),
                               "call": decode_call(data, depth + 1) if len(data) >= 4 else None}}
        except (ValueError, IndexError):
            return {}
    if canon == "execute(bytes32,bytes)" and values[0][2:4] == "01":
        node = parse_type("(address,uint256,bytes)[]")
        try:  # ERC-7579 batch: abi.encode(Execution[])
            return {"batch": dict(annotate(node, abi_decode([node], values[1])[0], depth), name="executions")}
        except DecodeError:
            return {}
    return {}


def decode_call(data, depth=0, sigs=None):
    if len(data) < 4:
        return {"error": "calldata shorter than a 4-byte selector", "data": _hex(data)}
    sel = _hex(data[:4])
    candidates = sigs if sigs is not None else TABLE.get(sel, [])
    for sig, canon, types in candidates:
        try:
            values = abi_decode(types, data[4:])
        except DecodeError:
            continue
        out = {"selector": sel, "function": canon, "args": _named(sig, types, values, depth)}
        if selector(canon) != sel:
            out["warning"] = f"signature selector {selector(canon)} differs from calldata"
        out.update(_special(canon, values, depth))
        return out
    return {"selector": sel, "guessed": True, "args": guess_args(data[4:], depth)}


# --- Structural guessing for unknown selectors -------------------------------

def guess_word(raw):
    v = int.from_bytes(raw, "big")
    if v == 0:
        return {"guess": "zero", "value": "0"}
    if v >> 160 == 0 and v >= 1 << 100:
        addr = _hex(raw[12:])
        out = {"guess": "address", "value": addr}
        if addr in LABELS:
            out["label"] = LABELS[addr]
        return out
    if v < 1 << 100:
        return {"guess": "uint", "value": str(v)}
    if v >> 248 == 0xff:
        return {"guess": "int (negative)", "value": str(v - (1 << 256))}
    return {"guess": "bytes32", "value": _hex(raw)}


def _guess_bytes(raw, depth):
    out = {"guess": "bytes", "value": _hex(raw)}
    if len(raw) >= 4 and depth < MAX_DEPTH and ((len(raw) - 4) % 32 == 0 or _hex(raw[:4]) in TABLE):
        out["call"] = decode_call(raw, depth + 1)
    elif raw and all(32 <= b < 127 for b in raw):
        out = {"guess": "string", "value": raw.decode()}
    return out


def _guess_dynamic(data, loc, end, depth):
    """Guess the value whose encoding fills data[loc:end]."""
    region = data[loc:end]
    n = _word(region, 0)
    body = region[32:]
    if 0 < n and n * 32 <= len(body) and _word(body, 0) == n * 32:
        offs = [_word(body, 32 * i) for i in range(n)]
        if offs == sorted(offs) and all(o % 32 == 0 and o < len(body) for o in offs):
            ends = offs[1:] + [len(body)]
            return {"guess": f"dynamic[{n}]",
                    "items": [_guess_dynamic(body, o, e, depth) for o, e in zip(offs, ends)]}
    padded = n <= len(body) and not any(body[n:n + (-n % 32)])
    if padded and n + (-n % 32) == len(body):
        return _guess_bytes(bytes(body[:n]), depth)
    if n * 32 == len(body):
        return {"guess": f"word[{n}]", "items": [guess_word(body[32 * i:32 * i + 32]) for i in range(n)]}
    if n > len(body) or not padded:
        return {"guess": "tuple", "items": guess_args(region, depth)}
    return _guess_bytes(bytes(body[:n]), depth)


def _mark_pool_keys(items):
    """Point out runs shaped like a Uniswap v4 PoolKey and give their pool id."""
    for i in range(len(items) - 4):
        c0, c1, fee, spacing, hooks = items[i:i + 5]
        if (c0.get("guess") in ("address", "zero") and c1.get("guess") == "address"
                and fee.get("guess") in ("uint", "zero") and int(fee["value"]) <= 1_000_000
                and spacing.get("guess") == "uint" and 0 < int(spacing["value"]) < 32768
                and hooks.get("guess") in ("address", "zero")):
            key = [c0["value"] if c0["guess"] == "address" else "0x" + "0" * 40, c1["value"],
                   int(fee["value"]), int(spacing["value"]),
                   hooks["value"] if hooks["guess"] == "address" else "0x" + "0" * 40]
            if int(key[0], 16) < int(key[1], 16):
                pid = pool_id(key)
                c0["poolId"] = pid
                c0["note"] = ("starts the ZTO/IMD v4 pool key" if pid == ZTO_POOL_ID
                              else "starts a v4 pool key?")
    return items


def guess_args(data, depth=0):
    if len(data) % 32:
        return [{"guess": "packed or non-ABI bytes", "value": _hex(data)}]
    heads, head_end, pos = [], len(data), 0
    while pos < head_end:
        v = _word(data, pos)
        if v % 32 == 0 and pos + 32 <= v < len(data) and _word(data, v) <= len(data) - v - 32 or \
                v % 32 == 0 and pos + 32 <= v < len(data) and _word(data, v) >> 160 == 0 and \
                _word(data, v) >= 1 << 100:  # a struct whose first field is an address
            heads.append(v)
            head_end = min(head_end, v)
        else:
            heads.append(None)
        pos += 32
    offsets = sorted(v for v in heads if v is not None)
    out = []
    for i, v in enumerate(heads):
        if v is None:
            out.append(guess_word(data[32 * i:32 * i + 32]))
            continue
        end = min([o for o in offsets if o > v] + [len(data)])
        try:
            item = _guess_dynamic(data, v, end, depth)
        except DecodeError:
            item = {"guess": "unreadable"}
        out.append(dict(item, offset=v))
    return _mark_pool_keys(out)


# --- Output ------------------------------------------------------------------

def render(tree, indent=0):
    pad = "  " * indent
    lines = []
    if "function" in tree or "guessed" in tree:
        title = tree.get("function") or f"unknown function {tree['selector']} (layout guessed)"
        lines.append(f"{pad}{title}" + (f"   [{tree['selector']}]" if "function" in tree else ""))
        if tree.get("warning"):
            lines.append(f"{pad}  ! {tree['warning']}")
        for arg in tree.get("args", []):
            lines += _render_value(arg, indent + 1)
        if "plan" in tree:
            lines.append(f"{pad}  Universal Router plan:")
            lines += _render_plan(tree["plan"], indent + 2)
        if "actions" in tree:
            lines.append(f"{pad}  v4 actions:")
            lines += _render_actions(tree["actions"], indent + 2)
        for tx in tree.get("transactions", []):
            lines.append(f"{pad}  {tx['operation']} {tx['to']} value {tx['value']}"
                         + (f"  ({tx['label']})" if tx.get("label") else ""))
            if tx.get("call"):
                lines += render(tx["call"], indent + 2)
        if tree.get("batch"):
            lines.append(f"{pad}  ERC-7579 batch:")
            lines += _render_value(tree["batch"], indent + 2)
        if tree.get("single"):
            s = tree["single"]
            lines.append(f"{pad}  call {s['to']} value {s['value']}")
            if s.get("call"):
                lines += render(s["call"], indent + 2)
        return lines
    lines.append(f"{pad}{tree.get('error', tree)}")
    return lines


def _render_plan(plan, indent):
    pad, lines = "  " * indent, []
    for i, step in enumerate(plan):
        lines.append(f"{pad}{i + 1}. {step['command']}" + (" (may revert)" if step["allowRevert"] else ""))
        for arg in step.get("args", []):
            if step["command"] == "V4_SWAP":
                continue
            lines += _render_value(arg, indent + 1)
        if "input" in step:
            lines.append(f"{pad}   raw input {_short(step['input'])}")
        if "actions" in step:
            lines += _render_actions(step["actions"], indent + 1)
        if "plan" in step:
            lines += _render_plan(step["plan"], indent + 1)
    return lines


def _render_actions(actions, indent):
    pad, lines = "  " * indent, []
    for a in actions:
        lines.append(f"{pad}- {a['action']}")
        for arg in a.get("args", []):
            lines += _render_value(arg, indent + 1)
        if "input" in a:
            lines.append(f"{pad}  raw input {_short(a['input'])}")
    return lines


def _short(h, n=74):
    return h if len(h) <= n else f"{h[:n]}... ({(len(h) - 2) // 2} bytes)"


def _render_value(v, indent):
    pad = "  " * indent
    head = f"{pad}{v['name']}: " if v.get("name") else f"{pad}"
    kind = v.get("type") or v.get("guess")
    extra = "".join(f"  ({v[k]})" for k in ("label", "note") if v.get(k))
    if v.get("poolId"):
        extra += f"  poolId {v['poolId']}"
    if "items" in v:
        lines = [f"{head}{kind}{extra}"]
        for item in v["items"]:
            lines += _render_value(item, indent + 1)
        return lines
    if "call" in v:
        return [f"{head}{kind} carrying a call:"] + render(v["call"], indent + 1)
    return [f"{head}{kind} {_short(str(v.get('value', '')))}{extra}"]


# --- Chain access (read only) ------------------------------------------------

def _rpc_once(url, method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = request.Request(url, payload, headers={"Content-Type": "application/json", "User-Agent": UA})
    opener = request.build_opener(request.ProxyHandler({}))  # ignore proxy env vars
    with opener.open(req, timeout=30) as resp:
        reply = json.load(resp)
    if "error" in reply:
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply["result"]


def rpc_call(url, method, params):
    """Ask `url`; on a network failure try once more, then the fallback endpoint."""
    errors = []
    for attempt in [url, url] + [u for u in FALLBACK_RPCS if u != url]:
        try:
            return _rpc_once(attempt, method, params)
        except (OSError, ValueError) as exc:  # URLError/HTTPError are OSErrors
            errors.append(f"{attempt}: {exc}")
            time.sleep(1)
    raise RuntimeError(f"{method} failed: " + "; ".join(errors))


def latest_zto_tx(url, blocks):
    head = int(rpc_call(url, "eth_blockNumber", []), 16)
    logs = rpc_call(url, "eth_getLogs", [{"address": ZTO, "topics": [TRANSFER_TOPIC],
                                          "fromBlock": hex(max(0, head - blocks)), "toBlock": hex(head)}])
    if not logs:
        raise RuntimeError(f"no ZTO transfers in the last {blocks} blocks")
    return logs[-1]["transactionHash"]


def fetch_tx(url, tx_hash):
    tx = rpc_call(url, "eth_getTransactionByHash", [tx_hash])
    if not tx:
        raise RuntimeError(f"transaction {tx_hash} not found")
    return {"hash": tx["hash"], "blockNumber": int(tx["blockNumber"], 16) if tx.get("blockNumber") else None,
            "from": tx["from"], "to": tx.get("to"), "value": str(int(tx["value"], 16)), "input": tx["input"]}


# --- Self test ---------------------------------------------------------------

def selftest():
    checks = []

    def check(name, ok):
        checks.append((name, bool(ok)))

    check("keccak256('')", keccak256(b"").hex() ==
          "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    check("keccak256('hello')", keccak256(b"hello").hex() ==
          "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
    # Same permutation with NIST padding must match hashlib's SHA3-256 across block sizes.
    check("permutation matches hashlib.sha3_256", all(
        keccak256(bytes(range(256))[:n] * 3, 0x06) == hashlib.sha3_256(bytes(range(256))[:n] * 3).digest()
        for n in (0, 1, 45, 46, 135, 136, 200)))
    known = {"transfer(address,uint256)": "0xa9059cbb", "approve(address,uint256)": "0x095ea7b3",
             "execute(bytes,bytes[],uint256)": "0x3593564c", "aggregate3Value((address,bool,uint256,bytes)[])": "0x174dea71",
             "handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)": "0x765e827f",
             "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)": "0x6a761202"}
    for canon, sel in known.items():
        check(f"selector {canon[:30]}", selector(canon) == sel)
    zto_key = sorted([ZTO, IMD]) + [12500, 60, ZTO_HOOK]
    check("ZTO/IMD pool key hashes to the ZTO pool id", pool_id(zto_key) == ZTO_POOL_ID)
    # A ZTO transfer wrapped in a smart-account execute(), built by hand.
    transfer = bytes.fromhex("a9059cbb") + bytes(12) + bytes.fromhex("11" * 20) + (10 ** 18).to_bytes(32, "big")
    execute = (bytes.fromhex(selector("execute(address,uint256,bytes)")[2:]) + bytes(12) + bytes.fromhex(ZTO[2:])
               + bytes(32) + (96).to_bytes(32, "big") + len(transfer).to_bytes(32, "big")
               + transfer + bytes(-len(transfer) % 32))
    tree = decode_call(execute)
    inner = tree["args"][2].get("call", {})
    check("nested execute -> transfer", tree.get("function") == "execute(address,uint256,bytes)"
          and tree["args"][0].get("label", "").startswith("ZTO") and inner.get("function") == "transfer(address,uint256)"
          and inner["args"][1]["value"] == str(10 ** 18))
    guessed = decode_call(bytes.fromhex("deadbeef") + execute[4:])
    check("unknown selector still exposes the inner transfer",
          guessed.get("guessed") and guessed["args"][2].get("call", {}).get("function") == "transfer(address,uint256)")
    check("dirty address padding is rejected", decode_call(bytes.fromhex("a9059cbb") + b"\x01" * 64).get("guessed"))
    for name, ok in checks:
        print(("PASS " if ok else "FAIL ") + name)
    return all(ok for _, ok in checks)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("calldata", nargs="?", help="0x-prefixed calldata")
    src.add_argument("--tx", help="decode the input of this mainnet transaction hash")
    src.add_argument("--latest-zto", action="store_true", help="decode the newest transaction that moved ZTO")
    src.add_argument("--file", help="JSON file with an 'input' field (e.g. a saved transaction)")
    src.add_argument("--selftest", action="store_true", help="run offline checks")
    p.add_argument("--sig", action="append", default=[], help="extra function signature to try, e.g. 'foo(address,uint256)'")
    p.add_argument("--blocks", type=int, default=300, help="window for --latest-zto (default 300)")
    p.add_argument("--rpc", default=RPC, help="public read-only JSON-RPC endpoint")
    p.add_argument("--json", action="store_true", help="print the decoded tree as JSON")
    a = p.parse_args(argv)

    if a.selftest:
        return 0 if selftest() else 1
    global TABLE
    if a.sig:
        TABLE = build_table(a.sig)
    meta = None
    if a.calldata:
        hexdata = a.calldata
    elif a.file:
        with open(a.file) as fh:
            meta = json.load(fh)
        hexdata = meta["input"]
    else:
        try:
            tx_hash = a.tx or latest_zto_tx(a.rpc, a.blocks)
            meta = fetch_tx(a.rpc, tx_hash)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        hexdata = meta["input"]
    if not re.fullmatch(r"0x([0-9a-fA-F]{2})*", hexdata):
        p.error("calldata must be 0x-prefixed hex with whole bytes")
    data = bytes.fromhex(hexdata[2:])
    tree = decode_call(data)
    if a.sig and tree.get("guessed"):  # let a supplied signature override the selector
        forced = decode_call(data, sigs=[(s,) + parse_sig(s) for s in a.sig])
        if not forced.get("guessed"):
            tree = forced
    if a.json:
        print(json.dumps({"tx": {k: v for k, v in (meta or {}).items() if k != "input"}, "decoded": tree}, indent=1))
        return 0
    if meta:
        to = (meta.get("to") or "").lower()
        print(f"tx {meta.get('hash')}  block {meta.get('blockNumber')}")
        print(f"from {meta.get('from')}  to {to}" + (f" ({LABELS[to]})" if to in LABELS else "")
              + f"  value {meta.get('value')} wei")
    print("\n".join(render(tree)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
