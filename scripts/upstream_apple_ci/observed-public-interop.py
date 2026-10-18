#!/usr/bin/env python3
"""Observe the pinned iOS controller's original RPCs; never export their fields."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import time

controller = Path('ios/scripts/public-chat-acceptance/controller.py').resolve(strict=True)
spec = importlib.util.spec_from_file_location('pinned_public_controller', controller)
frozen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(frozen)
original_peer, original_wait = frozen.Peer, frozen.wait_for
peers, waits = [], []


class ObservedPeer(original_peer):
    def __init__(self, binary, device, state, relay, log):
        # The original controller constructs these names from fixed version labels.
        if state.name not in ('published', 'experimental') or state.parent.name not in (
                'sponsor-published', 'sponsor-experimental'):
            raise ValueError('Expected dedicated mixed-version fixture scope')
        self.observation = {'ordinal': len(peers) + 1, 'sdk': state.name,
                            'sponsor': state.parent.name.removeprefix('sponsor-'),
                            'commands': {}, 'closed_successfully': False}
        peers.append(self.observation)
        super().__init__(binary, device, state, relay, log)

    def ask(self, command, allow_error=None, **fields):
        counts = self.observation['commands']
        counts[command] = counts.get(command, 0) + 1
        self.observation['last_command'] = command
        value = super().ask(command, allow_error=allow_error, **fields)
        # Only aggregate existing replies; do not make any additional SDK calls.
        if command == 'invitations':
            self.observation['last_invitation_count'] = len(value['groups'])
        elif command == 'packages':
            self.observation['last_public_package_count'] = value['count']
        elif command == 'publish':
            self.observation['last_published_keypackage_bytes'] = value['published']
        elif command == 'state':
            self.observation['last_group_members'] = value['members']
            self.observation['last_group_current'] = value['current']
        elif command == 'has-message':
            self.observation['last_matching_message_count'] = value['matches']
        return value

    def close(self):
        super().close()
        self.observation['closed_successfully'] = True


def observed_wait(predicate, stage):
    # Keep the original 45-second deadline and 0.2-second polling unchanged.
    row = {'stage': stage, 'polls': 0, 'completed': False}
    waits.append(row)
    started = time.monotonic()

    def observed_predicate():
        row['polls'] += 1
        result = predicate()
        row['last_predicate_matched'] = bool(result)
        return result

    try:
        result = original_wait(observed_predicate, stage)
        row['completed'] = True
        return result
    finally:
        row['elapsed_seconds'] = round(time.monotonic() - started, 3)


frozen.Peer, frozen.wait_for = ObservedPeer, observed_wait
status = frozen.main()
output = Path(sys.argv[sys.argv.index('--output') + 1]) / 'result.json'
result = json.loads(output.read_text())
result['observed_peers'] = peers
result['observed_waits'] = waits
result['workers_created'] = len(peers)
result['workers_closed'] = sum(peer['closed_successfully'] for peer in peers)
result['controller_sha256'] = hashlib.sha256(controller.read_bytes()).hexdigest()
result['observer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
result['diagnostic_scope'] = 'Original commands/replies only; fixed labels and counts, no payloads, identifiers, extra SDK calls or changed deadlines.'
output.write_text(json.dumps(result, indent=2) + '\n')
# The original printed only its aggregate result; these diagnostics are equally bounded.
print(json.dumps({'workers_created': result['workers_created'], 'workers_closed': result['workers_closed'],
                  'last_stage': waits[-1]['stage'] if waits else None}))
raise SystemExit(status)
