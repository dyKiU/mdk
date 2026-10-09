# Separate experimental private migration bodies

These bodies are registered only in `../migrations.rs::PRIVATE_MIGRATIONS` and
executed under the separate experimental ledger. Their prefixes are private
revisions, never upstream `cgka_schema_migrations` allocations. Revision9 is the
first body in this directory; revisions1–8 retain frozen historical filenames
103–110 and the unchanged audited old-private bridge.

Expose `apply(&Transaction) -> StorageResult<()>`; preserve strict reference
schema and immutable receipt/audit checks. Negative privacy rows cannot grant
membership, restore verifier consent or enter group snapshot rollback. Default
builds may create empty schemas but must refuse populated private cohorts.
