# Token identity

`token_identity.py` reads an Ethereum token contract's runtime code and common ERC-20 metadata directly from public JSON-RPC, without an ABI, key, or explorer. It handles both ABI strings and older `bytes32` text responses. The default address is ZTO. An unknown or reverting field is reported as an error rather than guessed.

Run from the repository root:

```sh
python3 line-1/tools/token_identity/token_identity.py
```

Pass another address with `--address 0x...` or use `--rpc https://eth.drpc.org`. This is a read-only call; it does not need a wallet. The output is JSON containing the chain ID, observed block, code size, metadata, and any field errors. Name and symbol come from the contract itself and are not proof of authenticity.

Tried on 2026-10-06 against live Ethereum at block 26,135,243: ZTO returned `Zero To One`, `ZTO`, 18 decimals, 1,000,000,000 total tokens, and 1,287 bytes of runtime code, with no field errors. The public endpoint must be reachable when the command is run.
