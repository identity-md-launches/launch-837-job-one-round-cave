# Fee Budget

A Python standard-library, read-only Ethereum fee planner. It compares a chosen gas allowance against an exact ETH cap using current mainnet base fee and suggested priority fee. Optional recipient and raw amount arguments prepare unsigned ZTO ERC-20 transfer calldata. It never accesses a wallet, signs, or sends.

Run from the repository root:

```sh
python3 line-2/tools/fee-budget/budget.py --gas-limit 65000 --cap-eth 0.001
```

Requires public network access to ethereum-rpc.publicnode.com, no installed dependencies. The command sends only three read-only JSON-RPC requests with its own User-Agent. Network failures are reported; it does not substitute cached fees.

Tried on Ethereum block 26135272: base fee 814211598 wei, suggested tip 51389 wei, maximum budget 105850848025000 wei (0.000105850848025 ETH); within the 0.001 ETH cap. Arithmetic boundary and invalid cap checks also passed.

For an unsigned transfer, append `--recipient 0x0000000000000000000000000000000000000001 --amount-raw 1`. Recipient and amount are explicit; token decimals are not guessed. Review every field before using another tool to submit anything.

The 65000 default is an illustrative allowance, not an estimate or a guarantee of successful execution. No balance, nonce, token transfer restrictions, recipient safety, or execution is checked. Fee data may change immediately; the cap covers execution gas only, not transfer value. The policy doubles the current base fee and adds the tip; a future base fee can exceed it. ETH pays Ethereum gas; ZTO is the first-choice transfer token.
