# Calldata decoder

`decode.py` takes raw Ethereum calldata and works out what the call will do, even when you don't have the target contract's ABI. It uses only the Python standard library and contains its own Keccak-256, so selectors and Uniswap v4 pool ids are computed locally.

- **Known calls.** It has a bundled list of about 60 signatures: ERC-20, ERC-721, WETH, Permit2, Multicall3, smart-account `execute`/`executeBatch`, ERC-7579 `execute(bytes32,bytes)` (single and batch modes), Safe `execTransaction`/`multiSend`, ERC-4337 `handleOps` (v0.6 and v0.7/v0.8), Uniswap v2/v3 routers, the v4 PoolManager and PositionManager, and the Universal Router. Each signature's selector is computed from its text, so the table can't contain a wrong selector. Decoding is strict: dirty address padding, a bool that isn't 0 or 1, an out-of-range offset or bad byte padding all reject a candidate signature.
- **Nested calls.** Any `bytes` argument that holds a call is decoded too, up to 8 levels deep. Universal Router `commands` are expanded into a step-by-step plan (`PERMIT2_PERMIT`, `V4_SWAP`, …). The v4 `actions` inside `V4_SWAP` and `modifyLiquidities` are expanded as well (`SWAP_EXACT_IN_SINGLE`, `SETTLE_ALL`, `TAKE_PAIR`, …).
- **Unknown selectors.** The layout is guessed from the ABI encoding alone: offsets, byte strings, arrays, structs, addresses, negative ints and printable strings. Guessed output is labelled `(layout guessed)` and is not a fact. Calls nested inside guessed arguments are still found and decoded.
- **Labels.** Known addresses are named: ZTO, IMD, the hook on the ZTO/IMD pool, WETH, USDC, Uniswap contracts, Permit2, EntryPoints. Every v4 `PoolKey` is shown with its pool id, and the ZTO/IMD pool is flagged by name.

It never signs, sends, or reads keys, environment variables or files outside what you pass it. Live mode only calls the read-only JSON-RPC methods `eth_getTransactionByHash`, `eth_blockNumber` and `eth_getLogs`. It sends its own User-Agent, retries once, and then falls back to `https://eth.drpc.org`.

## See it working (offline, from the repository root)

```sh
python3 line-4/tools/calldata_decoder/decode.py --file line-4/tools/calldata_decoder/zto_swap_tx.json
```

`zto_swap_tx.json` is a real mainnet transaction: 0xc2b99333…6de0 in block 26,134,661, fetched with `eth_getTransactionByHash`. The decoder turns its 1,508 bytes of calldata into a two-step Universal Router plan:
1. `PERMIT2_PERMIT` for ZTO.
2. `V4_SWAP` = `SWAP_EXACT_IN_SINGLE`, selling 232,369.25 ZTO (raw units; ZTO has 18 decimals) for at least 0.0112 ETH in the native-ETH/ZTO pool (fee 90000, tick spacing 900, no hook; pool id `0x39f2…cc7a`), then `SETTLE_ALL` ZTO and `TAKE_ALL` ETH.

Other modes:

```sh
python3 line-4/tools/calldata_decoder/decode.py --selftest            # offline checks, all PASS
python3 line-4/tools/calldata_decoder/decode.py --latest-zto          # newest tx that moved ZTO (live)
python3 line-4/tools/calldata_decoder/decode.py --tx 0xHASH [--json]  # any mainnet tx (live)
python3 line-4/tools/calldata_decoder/decode.py 0xa9059cbb...         # raw calldata, e.g. an unsigned tx before signing
python3 line-4/tools/calldata_decoder/decode.py --sig "foo(address to,uint256 n)" 0x...   # add or force a signature
```

## What happened when I tried it (2026-10-06, live mainnet)

- `--selftest` passed 13 of 13 checks: Keccak vectors; the permutation matches `hashlib.sha3_256` under NIST padding across block sizes; six known selectors; the ZTO/IMD pool key hashes to the pool id `0x888b07bd…5592` given in the task; a nested ZTO transfer is found inside both a known and an unknown wrapper; dirty padding is rejected.
- **Finding:** the ZTO/IMD pool key is (IMD, ZTO, 12500, 60, hook `0x784ff9a3ac5d88a30bfff6f7f2a270161fbe6000`). It is *not* hookless. I first assumed no hook and the pool id did not match. The hook address came from a decoded aggregator route, and the id now matches.
- Sampling 50 recent ZTO-moving transactions:
  - **EntryPoint v0.8 `handleOps`:** opened down to a smart account's `executeBatch` → ZTO `approve` → an unknown router call whose guessed layout showed a ZTO→USDC route plus its embedded JSON quote metadata.
  - **Multicall3 `aggregate3Value`:** decoded.
  - **PositionManager `modifyLiquidities`:** `DECREASE_LIQUIDITY` + `TAKE_PAIR` USDC/ZTO.
  - **ERC-7579 batch `execute`:** decoded.
  - **Unknown aggregator `0x39ecce49`:** its guessed structs showed a ZTO → IMD → USDC → WETH route, with fee 12500 / spacing 60 and the hook above on the first hop.
- Public RPC endpoints sometimes reset connections or refuse wide `eth_getLogs` ranges. That is why the tool retries and falls back to a second endpoint, and why `--latest-zto` only looks back 300 blocks by default.

## Limits

- Guessed layouts are heuristics: a small integer can look like an offset, and `bytes` can look like an array.
- Packed (non-ABI) encodings are shown as raw hex, except for Safe `multiSend` and ERC-7579 single mode.
- Only Ethereum mainnet labels are bundled.
- Amounts are raw integer units; no decimals are applied.
