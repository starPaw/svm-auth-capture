# TypeScript reference integration

This package connects the SVM Auth-Capture program to x402 v2 HTTP payment
transport and a restaurant-style metered demo. It is a project-specific binding;
compatibility with arbitrary x402 clients is not claimed.

## Components

`program.ts` mirrors the Rust wire ABI. `facilitator.ts` verifies and relays
operations through a ledger adapter. `rpc-ledger.ts` checks network identity and
deployment bytes before a live adapter is usable. `resource-server.ts` protects
a handler with an authorization and terminal payment flow.

The restaurant flow has its own durable orders and action locks. It is distinct
from the protected-handler `OperationStore`. Submission journals preserve exact
signed wires and observations; they are not permission to blindly retry an
uncertain operation. Reconciliation requires attributable finalized observations
and preserves unresolved state when evidence is missing or inconsistent.

`operators/` contains executable reference provisioning tools. `test/fixtures/`
contains explicitly synthetic offline data. Neither directory supplies a live
approval, wallet credential or authoritative deployment record.

## Development

```sh
npm ci
npm run typecheck
npm run build:wallet
npm test
```

Build `../target/deploy/svm_auth_capture.so` first with the root Rust scripts.
LiteSVM tests load that compiled program rather than substituting a native
implementation. Linux routing/crash coverage uses nginx and strace in CI.

Live entrypoints require environment configuration, a separately approved
deployment record, and role-appropriate credentials. Keep credentials in local
protected configuration. The runtime acceptance pin is intentionally unchanged
by public-history sanitization; a schema-valid synthetic record cannot replace
it. Existing release and recovery tools retain their original approval and
uncertainty boundaries. No deployment is performed by this repository's CI.

Read the root [README](../README.md) and [SECURITY.md](../SECURITY.md) before
adapting the reference flows.
