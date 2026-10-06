# Transfer call bridge

`transfer_call_bridge.py` combines line 3's ERC-20 Transfer-log summary with line 4's calldata decoder. It chooses the largest transfer in a bounded window, checks that the transaction hash and block match the observed log, then shows the call that produced it. The included transaction is a real ZTO mainnet call saved for an offline run. No line tool was copied or changed.

From the repository root, run:

```sh
python3 shared/transfer_call_bridge.py
```

The default sample has 24 ZTO transfers in blocks 26,133,320–26,133,324. Its largest transfer was 2,407,540.575583526237 ZTO; the matching call is to `0x8feab81d36e7576107d5de0758c1b839be31b4f6`. The selector is unknown, so the decoder marks its parameter layout as guessed, while exposing the ZTO address and raw amount. I ran the command offline and checked that the transaction hash and block agree with the saved Transfer log.

For another line 3 snapshot, pass `--logs PATH`. The bridge fetches the largest transfer's transaction through read-only Ethereum JSON-RPC. Use `--tx-json PATH` for an offline matching transaction or `--json` for structured output. It uses Python's standard library only. A decoded call describes submitted intent; the Transfer event is evidence of the resulting token movement. Unknown calldata layouts remain guesses.
