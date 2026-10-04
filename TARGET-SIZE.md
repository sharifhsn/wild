# Compact Rust artifacts in Wild

This branch adds the `compact-artifact` format crate and direct compact artifact reads in Wild.
The Rust compiler uses the same format crate from a sibling Wild checkout.
Objects and metadata remain compressed until a consumer needs their payload.
Library manifests and incremental work products can refer to the same encoded bytes.

Read the [measurement summary, limitations, and compiler links](https://github.com/sharifhsn/rust/blob/codex/target-size-research/TARGET-SIZE.md).
The [format crate](compact-artifact/README.md) describes the representation.
The [Rust reproduction guide](https://github.com/sharifhsn/rust/blob/codex/target-size-research/tools/compressed-artifacts/COMPACT-WILD.md) gives build and benchmark commands.

The September 28 measured snapshot remains on `codex/compact-artifacts-2026-09-28`.
The later ordinary ELF content-hash store has no equivalent full end-to-end comparison.
This is an LLM-assisted research prototype with LLM-assisted documentation, not an upstream submission.
