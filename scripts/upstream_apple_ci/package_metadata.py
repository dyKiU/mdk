"""Side-effect-free declared UniFFI dependency metadata; never builds or qualifies an SDK."""


def _checked_version(value):
    # Preserve the declared Cargo version requirement; Cargo owns its semantics.
    if (type(value) is not str or not 1 <= len(value) <= 128 or value != value.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError('UniFFI dependency requires a bounded literal version string')
    return value


def uniffi_version(manifest):
    if type(manifest) is not dict or type(manifest.get('dependencies')) is not dict:
        raise ValueError('UniFFI dependency manifest requires a dependency table')
    dependency = manifest['dependencies'].get('uniffi')
    if type(dependency) is dict:
        dependency = dependency.get('version')
    return _checked_version(dependency)
