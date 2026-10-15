#!/usr/bin/env python3
"""Validate the app's immutable published 0.13.0 pin before building its worker."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--assets', type=Path, required=True)
parser.add_argument('--ios', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
package = args.ios / 'Packages/MarmotKit'
text = (package / 'Package.swift').read_text()
require('let marmotKitReleaseID = "0.13.0"' in text and 'let marmotKitReleaseTag = "marmotkit-v0.13.0"' in text,
        'Expected published app release pin 0.13.0')
checksum = re.search(r'let marmotKitChecksum = "([0-9a-f]{64})"', text)
require(checksum is not None, 'Published package checksum absent')
binary = args.assets / 'MarmotKitFFI-0.13.0.xcframework.zip'
require(digest(binary) == checksum[1] == '06fa55edf8bb77edf0479452b5ec976eaea0298a5e0d07fe07ca176bdba0459e',
        'Published binary differs from qualified release pin')
manifest = json.loads((args.assets / 'marmotkit-ios-0.13.0.manifest.json').read_text())
require(manifest['release_identifier'] == '0.13.0' and manifest['release_tag'] == 'marmotkit-v0.13.0', 'Published release identity mismatch')
require(manifest['source_sha'] == '891ab34980ee9dc2ef45bf690733a6e31d3e6778', 'Published source identity mismatch')
require(manifest['features'] == ['otlp-export', 'product-analytics-export'], 'Published SDK unexpectedly experimental')
swift = args.assets / 'MarmotKit-0.13.0.swift'
require(digest(swift) == manifest['artifacts'][swift.name]['sha256'], 'Published Swift manifest mismatch')
normalize = lambda value: '\n'.join(line.rstrip() for line in value.splitlines()) + '\n'
require(normalize(swift.read_text()) == (package / 'Sources/MarmotKit/MarmotKit.swift').read_text(),
        'Published Swift differs from pinned app source')
require(not args.output.exists(), 'Published extraction output must be fresh')
args.output.mkdir()
seen = set()
with zipfile.ZipFile(binary) as archive:
    for item in archive.infolist():
        path = PurePosixPath(item.filename.rstrip('/'))
        require(not path.is_absolute() and '..' not in path.parts and path.parts[0] == 'MarmotKit.xcframework', 'Unsafe published archive path')
        require(str(path) == item.filename.rstrip('/') and item.filename not in seen, 'Duplicate/noncanonical published member')
        require(not stat.S_ISLNK(item.external_attr >> 16) and len(seen) < 256 and item.file_size < 2 * 1024**3, 'Published archive member refused')
        seen.add(item.filename)
    archive.extractall(args.output)
for name, record in manifest['artifacts'].items():
    if name.startswith('MarmotKit.xcframework/'):
        require(digest(args.output / name) == record['sha256'], 'Published native archive manifest mismatch')
require(manifest['artifacts'][binary.name]['sha256'] == checksum[1], 'Published binary manifest mismatch')
(args.output / 'published-provenance.json').write_text(json.dumps({
    'source_sha': manifest['source_sha'], 'release': 'marmotkit-v0.13.0',
    'binary_sha256': checksum[1], 'swift_sha256': digest(swift),
    'features': manifest['features']}, indent=2) + '\n')
