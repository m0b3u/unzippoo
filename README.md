# unzippoo

A fast, parallel Rust CLI for brute forcing password-protected ZIP archives using a wordlist.

## Building

```bash
cargo build --release
```

## Usage

Provide the target archive and a wordlist containing one candidate per line:

```bash
cargo run --release -- --zip secret.zip --wordlist rockyou.txt
```

Options:

- `--threads <N>`: Number of worker threads (defaults to the available logical cores).
- `--target <PATH>`: Specific file path inside the archive to validate (defaults to first non-directory entry).

The program exits with status `0` when the password is found and `1` when the wordlist is exhausted without a hit.
