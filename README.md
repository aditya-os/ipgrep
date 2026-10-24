# ipgrep

`ipgrep` scans input for IPv4 addresses and prints them with their line and
character position. Optional IP/CIDR filters can restrict the output.

## Build

```sh
make
```

This creates the `ipgrep` executable.

## Usage

```sh
./ipgrep [-f <input-file>] [-n <ip-or-cidr>[,<ip-or-cidr>...] | -nf <cidr-file>]
```

If `-f` is omitted, input is read from standard input. `-f -` is also
accepted as an explicit standard-input argument. If neither `-n` nor `-nf`
is supplied, every detected IPv4 address is printed.

Use `-n` for an inline filter list. It may contain:

- A single IPv4 address, treated as `/32`.
- A CIDR range such as `192.168.10.0/24`.
- Multiple addresses or ranges separated by commas.

Use `-nf` when the filter list is stored in a file. The two options are
mutually exclusive.

The filter file must be smaller than 1 MiB (1,048,576 bytes). Its reported
size is used to allocate the input buffer up front. The file is expected to
remain unchanged while it is being read.

Examples:

```sh
./ipgrep -f capture.txt -n 192.168.10.45
./ipgrep -f capture.txt -n 192.168.10.0/24
./ipgrep -f capture.txt -n '192.168.10.0/24,10.240.12.0/24,172.16.4.12'
./ipgrep -f capture.txt -nf cidr-ranges.txt
```

For a filter file, entries may be written one per line or separated by
commas. Whitespace is ignored, so this is valid:

```text
10.2.3.4/30, 10.2.3.12/29,
10.2.3.32/28
10.2.3.48/28
```

The program exits with an error if the `-n` value or `-nf` file contains an
invalid IPv4 address or CIDR range. CIDR prefixes must be between `0` and
`32`. The `-n` and `-nf` options are mutually exclusive.

## CIDR matching semantics

Configured filters are treated as networks. A detected address is matched
using its raw IPv4 address, even if the text includes a CIDR suffix.

For example:

```text
Filter: 172.16.4.12/30
Input:  172.16.4.12/24
Result: match
```

The detected token contributes the address `172.16.4.12`; its `/24` suffix is
not used as the lookup mask. Conversely:

```text
Filter: 172.16.4.0/30
Input:  172.16.4.12/24
Result: no match
```

This is host-address filtering, not CIDR-range intersection. In standard CIDR
notation, `172.16.4.12/24` normalizes to the network `172.16.4.0/24`; ipgrep
does not currently perform range-to-range matching for detected CIDR tokens.

## Output

Each matching address is printed as:

```text
line:position:address
```

Line and position numbers are 1-based. For example:

```text
33:42:10.240.12.102
```

The matcher also understands tcpdump-style endpoint text, such as:

```text
192.168.10.45.49152 > 10.240.12.102.8080
```

In this case, `192.168.10.45` and `10.240.12.102` are treated as the IP
addresses; the port suffixes are not included in the matches.

## Project structure

- `main.c` — command-line handling, file streaming, line/position tracking,
  and output.
- `ip_matcher.c/.h` — character-by-character IPv4 and CIDR token matcher.
- `ip_cidr.c/.h` — CIDR parsing, normalization, list management, and range
  membership checks.
- `ip_cidr_trie.c/.h` — separate binary-trie construction and numeric IPv4
  lookup. It accepts parsed `ip_cidr_t` values and does not parse text while
  inserting entries.
- `Makefile` — build and cleanup targets.

The CIDR lookup logic is isolated in `ip_cidr.c`, so it can later be replaced
with another lookup implementation without changing the text scanner. The
parser estimates the initial CIDR-list capacity from the input length, and the
list grows geometrically only if the estimate is too small.

The trie module is compiled with the application but is currently independent
of the executable's list-based lookup path. This keeps the existing behavior
unchanged while allowing trie lookup to be benchmarked or integrated later.

## Cleanup

```sh
make clean
```
