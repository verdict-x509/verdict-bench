Verified X.509 Certificate Validation
---

This is the main repo of Verdict, a formally verified X.509 certificate validator.
For all evaluations, see [https://github.com/verdict-x509/verdict-bench](https://github.com/verdict-x509/verdict-bench).

### Dependencies

Build dependencies in Ubuntu 24.04 (other systems are similar):
- Cargo >= 1.76.0
- build-essential, git, unzip, curl

### Verify and Build

To build, first run (Bash or Zsh)
```
. tools/activate.sh
```
This will first compile a vendored version of Verus, and then
provide a command `vargo` with the same usage as `cargo`.

To verify and build the entire project, run
```
vargo build --release
```
Then use `target/release/frontend` to validate certificate chains or run benchmarks.
See `target/release/frontend --help` for details.

By default, we only use crypto primitives that are verified from [libcrux](https://github.com/cryspen/libcrux) and [aws-lc-rs](https://github.com/aws/aws-lc-rs).
To use primitives entirely from `aws-lc-rs` which might have better performance but include unverified signature checking for RSA and ECDSA P-256,
compile with
```
vargo build --release --features aws-lc
```

To run some sanity checks
```
vargo test --workspace
```

## Build without verification

If your system does not support Verus, or for some reason Verus is not working,
an alternative is to just build the project without invoking Verus for formal verification.

To do this, simply run (without running `. tools/activate.sh`)
```
git submodule update --init
cargo build --release
```
which should work like in a normal Rust package, with all verification annotations stripped.

## Tracing

Use
```
RUSTFLAGS="--cfg trace" vargo build [--release]
```
to build a version with tracing enabled.
This will print out every successfully parsed construct and the result of each predicate in the policy DSL.
