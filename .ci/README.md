# CPSD acceptance source

The original complete Actions suite remains authoritative: one fresh root and
fuzz lock, native tests, actual browser vectors and timing, strict line/branch
coverage, original fuzz execution, advisory/license checks and original graph checks.

The fixed `acceptance` selector executes the entire original union and compares
actual native/browser deterministic v3 proof hashes. It never resolves and checks
both locks before and after every phase. `.ci/resolve.toml` declares the two
original graphs for the maintained ccid inventory resolver. The canonical resolver
must supply both exact retained locks and the frozen candidate source. Reports,
runner binaries, coverage, corpus and fuzz execution copies stay outside source.
The original 100% parser and original fuzz target are unchanged.

The `acceptance-preflight` selector checks qualified tooling and original source
policy before resolution; the resolver owns baseline metadata/compatibility.
The matching upstream wasm-bindgen CLI and sibling test runner are acquired from
the actual candidate lock, with archive and executable hashes retained. Browser
compilation alone never satisfies the browser phase.

This source is not a completed or dispatched full acceptance run. A fixed Crow
workflow still requires the independently qualified two-lock ccid revision and
its exact artifact receipts. No local builds or independent job dispatch are
permitted. The existing `resolve,native`, `wasm`, and `dependency-policy` selectors
remain diagnostic only; resolve retains files and hashes, never base64 stdout.
