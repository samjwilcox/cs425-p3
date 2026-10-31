# CS 425 P3 — Subnetting and Forwarding

## Overview
This C program parses IPv4/CIDR addresses, calculates subnet information, divides networks into equal-size subnets, and simulates a router's longest-prefix-match forwarding lookup.

## Build
Run `make all` on Linux (GCC/Clang-compatible), including GitHub Codespaces or Onyx.

## Usage
```
./build/release/myapp info 132.178.227.11/25
./build/release/myapp split 192.168.1.0/24 4
./build/release/myapp lookup tables/example.txt 132.178.227.50 8.8.8.8 10.1.2.5 10.1.2.200
```
The CLI exits with status 0 for success, 1 for malformed arguments, 2 for failed table loading, and 3 for an unmatched destination (unless another requested address was malformed, in which case 1 takes precedence).

## Design
All IPv4 addresses are 32-bit integers in host byte order with the first dotted octet in the most significant byte. Parsers validate digits and separators directly; unlike `inet_aton` they reject leading-zero octets, and they do not silently accept trailing data. Parsed output parameters are only assigned after complete validation.

The network mask is derived by bit shifting, with explicit handling of `/0` to avoid shifting by 32 bits. Prefixes `/31` and `/32` preserve both point-to-point hosts and the single-host address respectively; all other prefix sizes reserve the first and last address. Host counts use 64-bit arithmetic so `/0` works safely. Subnet splitting checks power-of-two counts and uses 64-bit intermediate arithmetic.

The forwarding table is a dynamically grown array of copied routes (with `realloc`), rejecting duplicate destination blocks and non-network destinations. Lookup scans every entry and retains the matching route with the greatest prefix length; table insertion order therefore does not affect longest-prefix selection. Default routes are normal `/0` entries. File loading strips comments and blank lines and reports the first bad line while retaining prior successful routes. Every allocated resource is freed.

## Testing
`make check` runs the unit suite. `make report` generates coverage with gcovr (install `gcovr` if it is missing). `make leak` runs the AddressSanitizer CLI build; `make leak-test` runs the sanitized Unity tests. Run `make all` first. For Valgrind on Onyx, run `valgrind --leak-check=full ./build/release/myapp`.

## Continuous integration and submission
This project preserves both original instructor workflows in `.github/workflows/`. Push to the `master` branch (or update CI branch configuration if your default branch is different), confirm CI, then run **Create Submission Report Via GitHub Action** and download the generated `submission-report.docx` for Canvas.
