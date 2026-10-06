#!/usr/bin/env python3
"""Read-only Ethereum fee budget; standard library, no signing or sending."""
import argparse
import json
import urllib.request
from decimal import Decimal, InvalidOperation

ZTO = '0xd782bdea4ef02a0bd391eb9089470c8080f0a68e'
RPC = 'https://ethereum-rpc.publicnode.com'


def rpc(method, params):
    request = urllib.request.Request(RPC, json.dumps({
        'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params
    }).encode(), {'Content-Type': 'application/json', 'User-Agent': 'Pepeolithic-FeeBudget/1.0'})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)
    if 'error' in data:
        raise ValueError(str(data['error']))
    return data['result']


def wei(text):
    value = Decimal(text) * 10**18
    if not value.is_finite() or value < 0 or value != value.to_integral_value():
        raise ValueError('ETH cap must be nonnegative with at most 18 decimal places')
    return int(value)


def budget(base, tip, gas, cap):
    if min(base, tip, cap) < 0 or gas < 21000:
        raise ValueError('Invalid fee inputs or gas limit below intrinsic minimum')
    maximum = 2 * base + tip
    cost = maximum * gas
    return {'max_fee_per_gas_wei': maximum, 'priority_fee_per_gas_wei': tip,
            'gas_limit': gas, 'maximum_fee_wei': cost,
            'maximum_fee_eth': format(Decimal(cost) / 10**18, 'f'),
            'cap_wei': cap, 'within_cap': cost <= cap}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gas-limit', type=int, default=65000,
                        help='User-supplied gas allowance, NOT an execution estimate')
    parser.add_argument('--cap-eth', default='0.001')
    parser.add_argument('--recipient', help='Optionally prepare ZTO transfer calldata')
    parser.add_argument('--amount-raw', type=int, default=0,
                        help='Integer token base units; no assumed decimals')
    args = parser.parse_args()
    cap = wei(args.cap_eth)
    if args.gas_limit < 21000:
        parser.error('gas limit must be at least 21000')
    if args.amount_raw < 0 or args.amount_raw >= 2**256:
        parser.error('amount must fit uint256')
    if args.recipient and (len(args.recipient) != 42 or not args.recipient.startswith('0x')
                           or any(c not in '0123456789abcdefABCDEF' for c in args.recipient[2:])):
        parser.error('recipient must be a 20-byte hex address')
    if int(rpc('eth_chainId', []), 16) != 1:
        raise ValueError('Endpoint is not Ethereum mainnet')
    block = rpc('eth_getBlockByNumber', ['latest', False])
    base = int(block['baseFeePerGas'], 16)
    tip = int(rpc('eth_maxPriorityFeePerGas', []), 16)
    result = budget(base, tip, args.gas_limit, cap)
    result.update({'chain_id': 1, 'block_number': int(block['number'], 16),
                   'block_hash': block['hash'], 'base_fee_wei': base,
                   'gas_source': 'user allowance; execution not simulated',
                   'policy': 'max fee = 2 * current base fee + suggested priority fee',
                   'token': ZTO})
    if args.recipient:
        result['unsigned_transaction'] = {
            'chainId': '0x1', 'to': ZTO, 'value': '0x0',
            'data': '0xa9059cbb' + args.recipient[2:].lower().zfill(64) + format(args.amount_raw, '064x'),
            'gas': hex(args.gas_limit), 'maxFeePerGas': hex(result['max_fee_per_gas_wei']),
            'maxPriorityFeePerGas': hex(tip), 'type': '0x2'}
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, InvalidOperation, OSError, KeyError, TypeError) as error:
        raise SystemExit('Fee budget failed: ' + str(error))
