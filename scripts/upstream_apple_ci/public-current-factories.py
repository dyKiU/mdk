#!/usr/bin/env python3
"""Require distinct current automatic factory public enrollment; retain all prior downstream guards."""
import collections
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROUTES = {'eu': 'wss://relay.eu.whitenoise.chat', 'us': 'wss://relay.us.whitenoise.chat'}
assert os.environ.get('GITHUB_ACTIONS') == 'true'
route = os.environ['PUBLIC_ROUTE']
assert route in ROUTES
source, run = os.environ['SOURCE_SHA'], os.environ['SDK_RUN_ID']
out = Path(os.environ['RUNNER_TEMP']) / ('public-current-factories-' + route)
proof_dir = Path('public-current-factories-proof')
proof_dir.mkdir(mode=0o700)
agent = Path(os.environ['PUBLIC_AGENT'])
provenance = Path(os.environ['PUBLIC_AGENT_PROVENANCE'])
agent_sha = hashlib.sha256(agent.read_bytes()).hexdigest()
manifest = json.loads(HERE.joinpath('native/SOURCE.json').read_text())
assert manifest['workspace_commit'] == 'be04fc60b6a4c40bd85423fbf9e35e8982ae4b84'
for name, digest in manifest['files'].items():
    assert hashlib.sha256(HERE.joinpath('native', name).read_bytes()).hexdigest() == digest
command = [sys.executable, str(HERE / 'current_factory_one_scan.py'), '--agent', str(agent),
           '--agent-sha256', agent_sha, '--agent-provenance', str(provenance),
           '--public-chat-relay', ROUTES[route], '--sdk-source', source,
           '--output', str(out), '--contacts', '--three-device-chats', '--direct-chats']
report = {'sdk_source': source, 'sdk_run_id': run, 'tools_sha': os.environ['GITHUB_SHA'],
          'frozen_workspace_commit': manifest['workspace_commit'], 'route': ROUTES[route],
          'agent_sha256': agent_sha, 'source_manifest_sha256': hashlib.sha256(HERE.joinpath('native/SOURCE.json').read_bytes()).hexdigest(),
          'automatic_retries': 0, 'sdk_rebuilds': 0, 'qualified': False,
          'current_factory_identity': 'current-automatic-factories-public-existing-roster-v1'}
sdk = Path(os.environ['RUNNER_TEMP']) / 'public-sdk'
qualification = json.loads(Path('packages/qualification.json').read_text())
assert qualification['source_sha'] == qualification['builder_sha'] == source
assert str(qualification['workflow_run_id']) == run
assert qualification['features'] == ['otlp-export','product-analytics-export','experimental-device-sync']
inputs = [agent, provenance, HERE / 'native/SOURCE.json', HERE / 'current_factory_one_scan.py', Path(__file__)]
inputs += [HERE / name for name in ['hosted_one_scan.py','current-factory-commands.swift.txt']]
inputs += [HERE / 'native' / name for name in manifest['files']]
inputs += [p for p in sdk.rglob('*') if p.is_file()]
files = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
report['sdk_qualification_sha256'] = hashlib.sha256(Path('packages/qualification.json').read_bytes()).hexdigest()
report['sdk_input_sha256'] = {str(p.relative_to(sdk)): files[str(p)] for p in sdk.rglob('*') if p.is_file()}

try:
    with (proof_dir / 'controller-private.log').open('x') as private:
        # Original inner90s waits and RPC deadlines remain frozen; this outer
        # process limit covers the complete two-direction history/contact trial.
        result = subprocess.run(command, stdout=private, stderr=subprocess.STDOUT, timeout=2400)
    report['controller_exit_code'] = result.returncode
    value = json.loads(out.joinpath('result.json').read_text())
    proof_dir.joinpath('native-result.json').write_text(json.dumps(value, indent=2) + '\n')
    assert result.returncode == 0 and value['passed'] == 2 and value['failed'] == 0
    assert value['current_factory_identity'] == report['current_factory_identity']
    assert value['derived_agent_source']['current_factory_identity'] == report['current_factory_identity']
    assert value['derived_agent_source']['current_factories'] is True
    assert value['sdk_source'] == source and value['agent_sha256'] == agent_sha
    assert value['public_chat_relay'] == ROUTES[route] and value['relay_port'] is None
    assert value['pairing_relays'] == ['wss://nos.lol', 'wss://relay.primal.net']
    checks = value['checks']
    assert len(checks) == 2 and {row['reverse'] for row in checks} == {False, True}
    required = ['single_bootstrap', 'automatic_encrypted_exchange', 'both_comparisons_required', 'explicit_bilateral_sharing']
    for row in checks:
        assert row['factory_identity'] == report['current_factory_identity'] and row['bootstrap_kind'] == 'wnpair1'
        assert all(row[k] is True for k in required)
        third = row['three_devices']
        assert third['current_existing_display_fresh_scanner'] is True
        assert third['roster_size'] == 3
        assert all(third[k] is True for k in ['single_bootstrap_per_new_device', 'existing_device_explicit_review',
            'stale_review_denied', 'existing_and_later_chats', 'send_from_each_device', 'offline_chat_recovery'])
        contacts = row['public_contacts']
        assert contacts['installations'] == 3 and contacts['peer_invitation_required'] is False
        assert all(contacts[k] is True for k in ['live_add', 'live_remove', 'mutation_from_each_installation', 'offline_restart_recovery'])
    assert len(value['completed_initial_pairings']) == 2
    pairs = value['phase_diagnostics']
    assert collections.Counter(p['scope'] for p in pairs) == {'initial-enrollment': 2, 'third-device-enrollment': 2}
    assert all(p['completed'] and p['waits'] and all(w['completed'] and w['deadline_seconds'] == 90 for w in p['waits']) for p in pairs)
    closed = value['original_process_close_observations']
    expected = {(cohort, slot) for cohort in ['forward', 'reverse'] for slot in ['source', 'companion', 'third', 'contact', 'third-restart']}
    assert len(closed) == 10 and {(p['cohort'], p['slot']) for p in closed} == expected
    assert all(p['positive_close'] and p['exit_code'] == 0 and p['close_calls'] == 1 for p in closed)
    direct = value['direct_lookup_observations']
    assert collections.Counter(p['role'] for p in direct) == {'source-before-pairing': 2, 'second-after-pairing': 2, 'third-after-pairing': 2}
    assert all(all(p[k] is True for k in ['found', 'same_group', 'reusable']) and p['paired_source'] == (not p['role'].startswith('source')) for p in direct)
    report.update(qualified=True, completed_scan_directions=2, initial_enrollments=2, third_device_enrollments=2,
                  positive_original_process_closes=10, direct_reuse_observations=6)
finally:
    private = proof_dir / 'controller-private.log'
    if private.exists():
        report['private_controller_log_sha256'] = hashlib.sha256(private.read_bytes()).hexdigest()
        private.unlink()
    report['source_and_agent_unchanged'] = all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == digest for p, digest in files.items())
    report['qualified'] = report['qualified'] and report['source_and_agent_unchanged']
    proof_dir.joinpath('result.json').write_text(json.dumps(report, indent=2) + '\n')
if not report['qualified']:
    raise SystemExit('Full public enrollment qualification pending')
