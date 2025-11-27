# strbin

Extract and classify strings from binaries and text files.

## Installation

```bash
cargo build --release
```

Binary will be at `target/release/strbin`

## Usage

```bash
strings binary | strbin
cat file.txt | strbin
strbin < input.txt
```

## What it does

Reads strings from stdin and classifies them into types:
- Network: URLs, IPs, emails
- Hashes: MD5, SHA1, SHA256, SHA512
- Security: SSH keys, API tokens
- Code: C++ templates, error messages
- Data: JSON, XML, Base64, timestamps
- Identifiers: UUIDs, MAC addresses, git hashes

Each line can match multiple types. For example, a log line with both a URL and an IP will extract both separately.

## Examples

### Extract only URLs
```bash
strings binary | strbin --with url
```

### Extract URLs and emails
```bash
strings binary | strbin --with url --with email
```

### Find SSH keys and secrets
```bash
strings binary | strbin --with ssh-key --with secret
```

### Find hashes
```bash
strings binary | strbin --with md5 --with sha256
```

### Show only counts (fast overview)
```bash
strings binary | strbin --analyze
```

### Limit output per type
```bash
strings binary | strbin --max-items 10
```

### Exclude noisy types
```bash
strings binary | strbin --without cpp --without errors
```

### See everything (disable defaults)
```bash
strings binary | strbin --no-defaults
```

By default, these types are hidden because they generate too many false positives:
- Error messages (Rust/Python/Java/JavaScript/Go panics, C++ exceptions)
- Base64, Hex, JSON, GitHash, SQL (too many false matches)

## Available Types

Individual types:
```
junk, regular, ipv4, ipv6, path, format-message, secret, url, email,
uuid, mac-address, base64, hex, git-hash, json, xml, timestamp, sem-ver,
cpp-template, cpp-exception, cpp-rtti, python-traceback, java-stack-trace,
javascript-error, go-panic, rust-panic, sql-query, ssh-key, md5, sha1,
sha256, sha512
```

Group types:
```
cpp              - All C++ related (templates, exceptions, RTTI)
errors           - All error types
network          - IPs, URLs, emails
identifiers      - UUIDs, MAC addresses, git hashes
data-formats     - JSON, XML, Base64, Hex
```

## Real-world Examples

Find all URLs in a binary:
```bash
strings /bin/ls | strbin --with url
```

Extract IP addresses from logs:
```bash
cat access.log | strbin --with ipv4 --with ipv6
```

Find potential secrets in a binary:
```bash
strings suspicious_binary | strbin --with secret --with ssh-key --with md5
```

Quick overview of what's in a binary:
```bash
strings binary | strbin --analyze
```

Extract network-related strings:
```bash
strings binary | strbin --with network
```
