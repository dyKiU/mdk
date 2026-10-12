# Account-wide departure qualification handoff

This is a proposed staged qualification, not executed evidence. No Cargo command
may start until the private25 owner explicitly releases target986 and the parent
confirms the lane. The candidate remains source-only and unqualified.

Use a normal isolated M5 checkout of the exact signed candidate. Preserve the
original source checkpoints and private25 failure/passing logs. Verify full Git
inputs before and after each gate; refresh tracked Rust/Cargo input mtimes before
freezing so reused crate-name artifacts cannot represent another checkout.

Resource environment: pinned Rust1.97.1; RUST_MIN_STACK=4194304;
CARGO_BUILD_JOBS=1; CARGO_INCREMENTAL=0; CARGO_PROFILE_DEV_DEBUG=0;
CARGO_PROFILE_TEST_DEBUG=0; the explicitly loaned target directory only. Require
at least20GiB free initially and before every expensive Cargo gate, plus a fresh
process scan and lsof check of the target lock for compilers writing that exact
target. Verify the private25 runner is terminal before accepting its lane. Do not stop another target's compiler or
clean shared caches. Use --locked and --lib to avoid unused integration harnesses.
Retain raw logs, exact exit/counts/duration and source/artifact hashes.

## First SQL compilation and focused gates

Package name is `storage-sqlite` (not cgka-storage-sqlite). Proposed commands:

```sh
cargo test --locked -p storage-sqlite --lib --features experimental-device-sync account_chat_departure::tests:: -- --test-threads=1
cargo test --locked -p storage-sqlite --lib --features experimental-device-sync account_chat_origin_observation::tests::retained_origin_observation_is_exactly_owner_source_and_group_bound -- --exact --test-threads=1
cargo test --locked -p storage-sqlite --lib --features experimental-device-sync migrations::private_migration_ledger_tests::private_revision26_replaces_known25_view_and_rejects_old_fingerprint_after_upgrade -- --exact --test-threads=1
cargo test --locked -p storage-sqlite --lib --features experimental-device-sync account_chat_source::tests::accepted_origin_reader_tracks_only_actual_current_accepted_lineage -- --exact --test-threads=1
```

Departure source declares15 tests; observer1; revision26 upgrade1; shared source
reader1. Discover the authoritative full migration test name from the actual
compiled --list output before --exact (the module nesting must not be guessed).
Require actual nonzero execution and these expected counts; a filtered/ignored
zero does not qualify anything. Controls cover rollback, scope, offline/reopen,
old/current lineage progress, simultaneous operations, local vs peer awaiting
sources, live disclosure/late records/fresh lineage, and raw replacement guards
under default/off/on recursive triggers. Then run affected private-ledger,
catalog/messages/presentation/source/send-queue tests under experimental and
appropriate default gates; enumerate actual counts, not projected totals.

## Genuine App and native C gates

Build the App lib test executable with experimental-device-sync and
test-policy-overrides. Execute the genuine two-source account-wide test and the
unchanged device-only survivor test with their actual full compiled test names,
--exact --test-threads=1. Each should execute1 actual test. The account-wide gate
must demonstrate C is mirrored-only, B offline implies Pending, actual D removes
both A/B ordinary leaves, all participants receive completion, and normal fresh
token sends fail with the specific departure denial. Additional genuine rejoin,
replay/offline/reopen and refusal coverage remains required; synthetic SQL alone
cannot qualify authenticated intent/receipt behavior.

The FFI fixture requires a matching App producer and C consumer compiled from
identical frozen source/feature inputs with compile-time
MARMOT_ACCEPTANCE_SOURCE_COMMIT=<full40hexSHA>. First build the App producer with
`cargo test --locked -p marmot-app --lib --features experimental-device-sync,test-policy-overrides --no-run --message-format=json` and derive the actual App
lib-test executable from Cargo's artifact record; retain its SHA256.

Build/run C with `experimental-device-sync,alloc-audit,marmot-app/test-policy-overrides`.
The C consumer is deliberately ignored outside this explicit pinned invocation:

```sh
cargo test --locked -p marmot-c --lib --features experimental-device-sync,alloc-audit,marmot-app/test-policy-overrides account_chat_departure_acceptance_tests::genuine_two_source_departure_crosses_real_c_and_uniffi_boundaries -- --exact --ignored --nocapture --test-threads=1
```

Set MARMOT_ACCOUNT_DEPARTURE_FIXTURE_EXE to that absolute App executable,
MARMOT_ACCOUNT_DEPARTURE_FIXTURE_SHA256 to its actual64hex hash, and
MARMOT_ACCOUNT_DEPARTURE_FIXTURE_LOG to a fresh absolute private log path.
The consumer invokes the producer's exact ignored test itself, verifies source
and executable identity, and exchanges bounded frames through a mode600 Unix
socket in a mode700 synthetic root. Credentials never go to logs. It opens the
same synthetic account roots through real C constructors/secret callbacks, uses
public departure/state/token functions, checks independent D's canonical leaf
removal, and exercises DTO frees/allocation accounting and positive shutdown.
Require consumer1/0 plus successful positive producer termination; skipped
producer/consumer tests do not count. No SDK package or language promotion is
implied by this native Rust/C boundary gate.

After behavioral gates, qualify affected default/experimental strict compilation,
binding output/preflight/close controls, status133/old ordinal preservation,
static docs/parity and the actually generated C header. Preserve any real RED
and fix its cause before repeating. Parent owns final combined full matrix and
SDK/host promotion; this handoff does not authorize another full runner.
