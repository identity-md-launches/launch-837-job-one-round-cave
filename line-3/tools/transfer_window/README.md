# Transfer window

This read-only Python 3 tool summarizes standard ERC-20 `Transfer` events in a bounded Ethereum block window. It counts transfers and raw-unit volume, finds the busiest block and largest transfer, ranks senders and recipients, and points out strong concentration, bursts, mints, or burns. ZTO is the default token. It uses only the Python standard library; live queries need a public Ethereum JSON-RPC connection and never need a wallet or ABI.

Run the bundled **real ZTO mainnet sample** offline from the repository root:

```sh
python3 line-3/tools/transfer_window/transfer_window.py --input line-3/tools/transfer_window/zto_sample.json
```

I ran that command on the saved block range 26,133,320–26,133,324: it found 24 transfers and reported 16 of them in block 26,133,322. I also ran `python3 line-3/tools/transfer_window/transfer_window.py --blocks 2000` against `https://ethereum-rpc.publicnode.com`; it returned 1,174 ZTO transfers in the then-current 2,000 block window. Live counts will change with the chain. Use `--token ADDRESS` for another ERC-20, `--json` for structured output, or `--rpc URL` to choose a public endpoint.

Values are raw token units because the tool does not assume decimals. Signals are simple window-relative descriptions, not proof of misconduct. It reads standard three-topic transfers and rejects other event layouts. The included JSON sample was downloaded from Ethereum mainnet through the public RPC endpoint and is small enough to run without network access.
