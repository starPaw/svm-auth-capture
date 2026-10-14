# SVM Auth-Capture

A Solana escrow program and TypeScript reference integration for authorizing a
spending ceiling, capturing portions of it, releasing unused funds, and issuing
merchant-funded refunds. The HTTP integration uses x402 v2 transport with a
project-specific SVM Auth-Capture binding.

## Payment lifecycle

| Operation | Authority | Effect |
| --- | --- | --- |
| Authorize | Payer | Deposit a fixed ceiling in a payment vault |
| Capture | Merchant | Transfer part of the held amount to the merchant |
| Capture and release | Merchant | Capture an amount and release the remaining hold |
| Void | Merchant | Release unused held funds |
| Refund | Merchant | Return previously captured funds from merchant liquidity |
| Reclaim | Payer | Recover an unused hold after its capture deadline |

Each payment has a permanent, one-use PDA. Its spending ceiling cannot be topped
up or reopened. A refund reduces the captured, unrefunded amount; it does not
restore spending capacity. Reclaim and rent cleanup are separate operations.
The v1 program supports classic SPL Token assets, with separate capture and
refund deadlines. Transaction fees and rent remain separate from token amounts.

## Repository layout

- `src/lib.rs`: on-chain program, account layout and instruction encodings.
- `tests/`: Rust suites that execute the compiled SBF in LiteSVM.
- `integration/src/`: wire codec, facilitator, RPC adapter, durable application
  stores, reconciliation, restaurant demo and browser-facing servers.
- `integration/test/`: integration, crash, concurrency and adversarial tests.
- `integration/browser/` and `integration/web/`: wallet bridge and demo UI.
- `integration/operators/`: reference provisioning and reconciliation tools.
- `ops/`: release, recovery and validation utilities.

See the [integration guide](integration/README.md) and
[security policy](SECURITY.md).

## Build and test

Use Rust 1.90.0, `cargo-build-sbf` 2.2.14 with platform-tools v1.53, and Node 24.
The Rust and npm lockfiles pin dependencies. The build commands compile and test
locally; they do not deploy a program or submit a payment.

```sh
./scripts/test-sac003.sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
npm ci --prefix integration
npm run typecheck --prefix integration
npm run build:wallet --prefix integration
npm test --prefix integration
python3 -B -m unittest discover -s ops -p 'test_*.py'
```

Some routing and crash tests require Linux, nginx or strace. CI supplies these
dependencies and exercises disposable systemd fixtures separately. A local skip
does not establish acceptance of a Linux-only behavior.

## Runtime boundaries

The public repository supplies offline synthetic deployment fixtures for tests.
They cannot pass the runtime's immutable accepted-deployment hash check. The
original deployment records, operational histories and release approvals remain
private. Live entrypoints therefore require the separately approved deployment
record and configuration; publishing or compiling this source does not authorize
deployment, signing, recovery or movement of funds.

The browser demo and its historical explorer links are examples. This is a
reference implementation, not a production security audit or a hosted billing
service. The binding is not an upstream-approved SVM x402 standard. Default
library sponsorship limits are process-local; durable admission and application
state require the corresponding configured stores. Uncertain submissions must
remain unresolved until attributable finalized evidence settles them.

## History and contributions

The public history preserves dated product changes and contributor attribution.
Internal-only documents and private evidence were removed during publication;
rewritten commit identities differ from the original private history. Future
changes should start from this public history rather than merging an old private
branch into it.

## Development and publication

Owner development, accepted operational records and both website deployment
sources remain in private `starPaw/capture402`. This public repository publishes
reviewed source and dated product history. It does not select a deployed release.

The main site is [capture402.xyz](https://capture402.xyz); its code and integration
links point here. The [isolated development demo](https://e2e.capture402.xyz/customer)
uses a separately accepted private revision. Private test records and reviews are
labelled as access required; contact [starPaw](https://github.com/starPaw) to request
access before relying on those records.

Public contributions start from this repository's `main` and use a task branch
and PR. Maintainer publications transfer selected reviewed changes while retaining
contributor attribution and original author dates. Neither direction merges the
other repository's history. Public CI and history/privacy checks must pass before
publication. Private instructions, evidence, credentials and runtime deployment
records stay private; public tests retain their synthetic fixtures.

Repository synchronization is reviewed per change; no automatic mirroring,
publication or deployment pipeline connects the two repositories. Each merge and
each live deployment requires its own owner authorization.

Licensed under [Apache-2.0](LICENSE). Existing third-party notices, including the
generated wallet bundle's legal notices, retain their original terms.
