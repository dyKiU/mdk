//! Aggregate evidence for the real SDK regression fixtures; never shipped.

/// Keep fixed fixture markers outside production library source output paths.
pub(crate) fn emit_line(arguments: std::fmt::Arguments<'_>) {
    eprintln!("{arguments}");
}
