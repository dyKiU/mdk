//! Aggregate fixture output for explicit test-policy builds only.

pub(crate) fn emit_line(arguments: std::fmt::Arguments<'_>) {
    eprintln!("{arguments}");
}
