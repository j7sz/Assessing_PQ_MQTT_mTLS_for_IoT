#!/usr/bin/env python3
"""Generate a reproducible, balanced TLS benchmark flashing schedule."""

import argparse
import csv
import random
import sys

SCHEMES = [
    "plain",
    "ecdsa_p256",
    "rsa2048",
    "mldsa44",
    "hawk512",
    "falcon512",
    "mayo1",
    "snova_24_5_16_4",
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaigns", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20260715)
    parser.add_argument("--boards", default="pico_w,pico2_w")
    parser.add_argument("--csv", metavar="OUT")
    args = parser.parse_args()
    if args.campaigns < 1:
        parser.error("--campaigns must be positive")

    rng = random.Random(args.seed)
    base = SCHEMES.copy()
    rng.shuffle(base)
    rows = []
    boards = [board.strip() for board in args.boards.split(",") if board.strip()]
    for board_index, board in enumerate(boards):
        for campaign in range(1, args.campaigns + 1):
            shift = (campaign - 1 + board_index * (len(base) // 2)) % len(base)
            order = base[shift:] + base[:shift]
            if (campaign % 2 == 0):
                order.reverse()
            for position, scheme in enumerate(order, 1):
                rows.append({
                    "board": board,
                    "campaign": campaign,
                    "position": position,
                    "scheme": scheme,
                    "target": f"mqtt_client_{scheme}",
                })

    handle = open(args.csv, "w", newline="") if args.csv else sys.stdout
    try:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if args.csv:
            handle.close()


if __name__ == "__main__":
    main()
