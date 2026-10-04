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

Both browser selectors include the existing `root_board` integration target.
Those vectors exercise the original same-holder blind issuance, authenticated
request refusals, sealed holder restart and joint presentation in actual Wasm.
The native-only hostile private-proof vectors remain part of the native suite.
Selecting these tests does not establish that they compile, meet browser timing
or pass; the complete fixed acceptance execution remains required.

This source is not a completed or dispatched full acceptance run. A fixed Crow
workflow still requires the independently qualified two-lock ccid revision and
its exact artifact receipts. No local builds or independent job dispatch are
permitted. The existing `resolve,native`, `wasm`, and `dependency-policy` selectors
remain diagnostic only; resolve retains files and hashes, never base64 stdout.

`browser-diagnostic` reuses the original matching upstream runner acquisition and
browser selector without invoking the unresolved full-acceptance workflow. It
requires the exact root/fuzz locks and implementation inventory from the retained
executed native vector reference, runs the original release-profile browser tests
(including root-board vectors and existing proof timing assertions), and compares
all three actual browser proof hashes to that native reference. The checked-in
reference contains public deterministic hashes, source identity and lock hashes;
it is not a substitute for executing the browser tests. Any source or lock change
requires a newly reviewed executed native reference.

The diagnostic retains both locks, upstream runner archive/checksum/binary
identities, actual tool versions, browser log and its own distinctly named receipt.
It uses the already-qualified immutable browser supplement and two jobs/threads.
It does not run the full coverage, fuzz or dependency-policy union and cannot
produce an owner/full acceptance receipt.

`coverage-diagnostic` binds the same executed native implementation and both
retained locks, then calls the original coverage selector through the existing
nightly helper. The unchanged parser requires every emitted production line and
branch. The command group is bounded to1800seconds plus15seconds termination grace.
It retains original JSON/LCOV/text reports and logs outside source, with
a distinctly named diagnostic receipt on success or failure; an original gate
failure still exits unsuccessfully. Original instrumented native tests also
write their real public root-board codec seeds into that artifact directory.
Corpus generation alone is not fuzz execution. This selector does not run or
replace the remaining fixed acceptance phases or the aggregate resolver.
