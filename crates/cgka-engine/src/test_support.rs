/// Emit aggregate fixture evidence only in unit-test builds.
pub(crate) fn emit_line(arguments: std::fmt::Arguments<'_>) {
    eprintln!("{arguments}");
}
