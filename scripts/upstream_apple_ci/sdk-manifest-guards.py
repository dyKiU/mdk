#!/usr/bin/env python3
"""Exercise exact app SDK scripts using isolated synthetic files, without SDK builds."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

COHORTS = {
    'mac': {'repository': 'whitenoise-mac', 'old': 'ff37f6201fa96a630da0ab3376a670442ddc5768',
            'new': '43917e25f6cbbf163db05ed2af285d80b2607aae', 'package': 'Vendored/MarmotKit',
            'libraries': ['macos-arm64'], 'count_error': 'Matched local manifest must identify the Mac native archive'},
    'ios': {'repository': 'whitenoise-ios', 'old': '59606f8cdf3dfdf86c18e5bf8a15e8177c475df1',
            'new': 'fb8ab84886dcff95f9c81de93b9e67468c1f6bfc', 'package': 'Packages/MarmotKit',
            'libraries': ['ios-arm64', 'ios-arm64-simulator'],
            'count_error': 'Matched local manifest must identify both iOS native archives'},
}
OUT = Path('sdk-manifest-guard-evidence')
OUT.mkdir(mode=0o700)
report = {'tool_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
          'scope': 'Synthetic SDK manifest/files; actual pinned app shell scripts. No compilation, real SDK packaging, app execution or native acceptance.',
          'cohorts': {}, 'cases': [], 'passed': False}


def save():
    (OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def exercise(platform, script, case, expected_error=None, metadata=True, corrupt=None):
    cohort = COHORTS[platform]
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        package = root / cohort['package']
        native = package / 'Artifacts/MarmotKit.xcframework'
        native.mkdir(parents=True)
        (native / 'Info.plist').write_bytes(b'fixture metadata')
        swift = package / 'Sources/MarmotKit/MarmotKit.swift'
        swift.parent.mkdir(parents=True)
        swift.write_bytes(b'fixture binding')
        source = 'a' * 40
        (package / 'MARMOT_VERSION').write_text('mdk-sha: ' + source + '\n')
        records = {}
        libraries = []
        for architecture in cohort['libraries']:
            library = native / architecture / 'libmarmot_uniffi.a'
            library.parent.mkdir(parents=True)
            library.write_bytes(b'fixture archive')
            libraries.append(library)
            records['MarmotKit.xcframework/' + architecture + '/libmarmot_uniffi.a'] = {'sha256': digest(library.read_bytes())}
        if metadata:
            for relative in ['Info.plist', 'Headers/marmot_uniffiFFI.h']:
                path = native / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_bytes(b'fixture header')
                records['MarmotKit.xcframework/' + relative] = {'sha256': digest(path.read_bytes())}
        manifest = dict(source_sha=source, builder_sha=source,
                        features=['otlp-export', 'product-analytics-export', 'experimental-device-sync'],
                        installed_swift_sha256=digest(swift.read_bytes()), artifacts=records)
        if corrupt == 'features':
            manifest['features'] = ['experimental-device-sync']
        elif corrupt == 'builder':
            manifest['builder_sha'] = 'b' * 40
        elif corrupt == 'source':
            manifest['source_sha'] = 'short'
        elif corrupt == 'version':
            (package / 'MARMOT_VERSION').write_text('mdk-sha: ' + 'b' * 40 + '\n')
        elif corrupt == 'swift':
            swift.write_bytes(b'changed binding')
        elif corrupt == 'framework':
            (native / 'Info.plist').unlink()
        elif isinstance(corrupt, int):
            libraries[corrupt].write_bytes(b'changed archive')
        (package / 'LOCAL_BUILD.json').write_text(json.dumps(manifest))
        result = subprocess.run(['bash', '-c', 'set -euo pipefail; repo_root="$1"; source "$2"',
                                 'sdk-preflight-test', str(root), str(script.resolve())],
                                env=dict(os.environ, WN_EXPERIMENTAL_DEVICE_SYNC='1'),
                                text=True, capture_output=True, timeout=20)
        matched = result.returncode == 0 if expected_error is None else result.returncode != 0 and expected_error in result.stderr
        report['cases'].append({'platform': platform, 'case': case, 'expected': 'accept' if expected_error is None else 'reject',
                                'exit_code': result.returncode, 'matched_expected_runtime': matched,
                                'error_category': expected_error if matched and expected_error is not None else None})
        save()
        assert matched, 'actual SDK script runtime did not match ' + platform + ':' + case


try:
    for platform, cohort in COHORTS.items():
        checkout = Path('apps') / cohort['repository']
        assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=checkout, text=True).strip() == cohort['new']
        relative = 'scripts/local-device-sync-settings.sh'
        script = checkout / relative
        original = script.read_bytes()
        committed = subprocess.check_output(['git', 'show', cohort['new'] + ':' + relative], cwd=checkout)
        assert original == committed, 'checked out script differs from committed candidate'
        old = subprocess.check_output(['git', 'show', cohort['old'] + ':' + relative], cwd=checkout)
        report['cohorts'][platform] = dict(cohort, old_script_sha256=digest(old), new_script_sha256=digest(original))
        with tempfile.TemporaryDirectory() as directory:
            old_script = Path(directory) / 'old.sh'
            old_script.write_bytes(old)
            exercise(platform, old_script, 'old-metadata-runtime-RED', expected_error=cohort['count_error'])
        exercise(platform, script, 'library-only-manifest', metadata=False)
        exercise(platform, script, 'metadata-manifest-GREEN')
        for index, architecture in enumerate(cohort['libraries']):
            exercise(platform, script, 'corrupt-native-' + architecture,
                     expected_error='Local native archive changed after matched installation', corrupt=index)
        guards = {'features': 'Experimental app requires the matched local device-sync artifact cohort',
                  'builder': 'Experimental app requires full matching source/builder commits',
                  'source': 'Experimental app requires full matching source/builder commits',
                  'version': 'Local binding source provenance does not match the artifact',
                  'swift': 'Local Swift bindings changed after matched installation',
                  'framework': 'Matched local XCFramework is absent'}
        for corruption, message in guards.items():
            exercise(platform, script, 'guard-' + corruption, expected_error=message, corrupt=corruption)
        anchor = b" and name.endswith('.a')"
        assert original.count(anchor) == 1, 'unique exact mutation anchor required'
        try:
            script.write_bytes(original.replace(anchor, b''))
            exercise(platform, script, 'filter-removal-runtime-mutant', expected_error=cohort['count_error'])
        finally:
            script.write_bytes(original)
            report['cohorts'][platform]['restored_script_sha256'] = digest(script.read_bytes())
            save()
        assert script.read_bytes() == original, 'exact source restoration required'
        exercise(platform, script, 'restored-metadata-GREEN')
    report['executed_shell_subprocesses'] = len(report['cases'])
    report['old_runtime_RED'] = sum(case['case'] == 'old-metadata-runtime-RED' for case in report['cases'])
    report['runtime_mutants_detected'] = sum(case['case'] == 'filter-removal-runtime-mutant' for case in report['cases'])
    report['passed'] = all(case['matched_expected_runtime'] for case in report['cases'])
finally:
    save()
print(json.dumps({'passed': report['passed'], 'executed_shell_subprocesses': len(report['cases']),
                  'scope': report['scope']}))
