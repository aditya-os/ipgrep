# ipgrep

`ipgrep` scans a text file for IPv4 addresses and prints only the addresses
that belong to one or more IP/CIDR ranges passed as input parameter.

## Build

```sh
make
```

This creates the `ipgrep` executable.

## Usage

```sh
./ipgrep -f <input-file> -n <ip-or-cidr>[,<ip-or-cidr>...]
```

The `-n` argument is required and may contain:

- A single IPv4 address, treated as `/32`.
- A CIDR range such as `192.168.10.0/24`.
- Multiple addresses or ranges separated by commas.

Examples:

```sh
./ipgrep -f capture.txt -n 192.168.10.45
./ipgrep -f capture.txt -n 192.168.10.0/24
./ipgrep -f capture.txt -n '192.168.10.0/24,10.240.12.0/24,172.16.4.12'
```

The program exits with an error if the `-n` value is not a valid IPv4 address
or CIDR range. CIDR prefixes must be between `0` and `32`.

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
- `Makefile` — build and cleanup targets.

The CIDR lookup logic is isolated in `ip_cidr.c`, so it can later be replaced
with another lookup implementation without changing the text scanner.

## Cleanup

```sh
make clean
```
