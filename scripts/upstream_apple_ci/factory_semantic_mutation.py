"""Four closed reviewed app-factory inverses; no hash override or execution."""
import hashlib

MODES = ('factory-begin-legacy', 'factory-scan-legacy')
SELECTOR = 'GenuineAutomaticHostFactoryTests/testExistingRosterWNPAIR2RequiresSiblingApprovalAndSharesHistory'
DEFINITIONS = {'macos': {'begin': {'path': 'whitenoise-mac/Core/MarmotClient.swift', 'original_sha256': '651a939ef24ed246d8c1fb1c6ef68ebf0d6c2d2eee529705828622e2369e77e4', 'mutant_sha256': 'a0f0e20fb2d0c378986987f0039c4d43b01a693d21ea8c2542d4d66a25e45ca9', 'preimage': 'try await marmot.beginAutomaticDeviceLinkingSession(accountRef: accountRef)', 'inverse': 'try await marmot.beginDeviceLinkingSession(accountRef: accountRef)', 'owner': 'beginDeviceLinkingSession(accountRef:)'}, 'scan': {'path': 'whitenoise-mac/Core/MarmotClient.swift', 'original_sha256': '651a939ef24ed246d8c1fb1c6ef68ebf0d6c2d2eee529705828622e2369e77e4', 'mutant_sha256': '8230faee084b753c97bd8939d1c3720dabb37dbf7a36398f9bc2f9c2e66967fc', 'preimage': 'return try await marmot.scanAutomaticDeviceLinkingSession(\n                    accountRef: accountRef, code: code)', 'inverse': 'return try await marmot.approveAutomaticDeviceLinkingSession(\n                    accountRef: accountRef, code: code, target: target)', 'owner': 'approveDeviceLinkingSession(accountRef:request:target:)'}}, 'ios': {'begin': {'path': 'whitenoise-ios/Core/MarmotClient.swift', 'original_sha256': '6e949a159832d0ace67bac2dc6f5f0460161b0544b267f150088e6348a5c2f9b', 'mutant_sha256': '034a0244c7fe357c64050c0f62addd95c6ce61b39180cdb88df446951d55c3b3', 'preimage': 'try await marmot.beginAutomaticDeviceLinkingSession(accountRef: accountRef)', 'inverse': 'try await marmot.beginDeviceLinkingSession(accountRef: accountRef)', 'owner': 'beginDeviceLinkingSession(accountRef:)'}, 'scan': {'path': 'whitenoise-ios/Core/MarmotClient.swift', 'original_sha256': '6e949a159832d0ace67bac2dc6f5f0460161b0544b267f150088e6348a5c2f9b', 'mutant_sha256': '3fb3bd8bade03b4b36fed34715e8946cb06338c8b93b4729ace9aa11c3e4cc40', 'preimage': 'return try await marmot.scanAutomaticDeviceLinkingSession(\n                    accountRef: accountRef, code: code)', 'inverse': 'return try await marmot.approveAutomaticDeviceLinkingSession(\n                    accountRef: accountRef, code: code, target: target)', 'owner': 'approveDeviceLinkingSession(accountRef:request:target:)'}}}


def transform(committed, platform, mode):
    if mode not in MODES or platform not in DEFINITIONS:
        raise ValueError('Closed reviewed factory inverse required')
    case = 'begin' if mode == MODES[0] else 'scan'
    entry = DEFINITIONS[platform][case]
    if hashlib.sha256(committed).hexdigest() != entry['original_sha256']:
        raise ValueError('Exact reviewed factory adapter source required')
    text = committed.decode('utf-8')
    if text.count(entry['preimage']) != 1:
        raise ValueError('Exactly one reviewed delegated operation required')
    owner = ('        func beginDeviceLinkingSession(accountRef: String)' if case == 'begin'
             else '        func approveDeviceLinkingSession(accountRef: String, request: Data, target: Data?)')
    start = text.find(owner)
    finish = text.find('\n        }', start) + len('\n        }')
    at = text.index(entry['preimage'])
    if start < 0 or finish < start or not start < at < finish:
        raise ValueError('Reviewed wrapper function owner required')
    mutant = text.replace(entry['preimage'], entry['inverse'], 1).encode()
    if mutant.count(b'\n') != committed.count(b'\n'):
        raise ValueError('Inverse must preserve line count')
    if hashlib.sha256(mutant).hexdigest() != entry['mutant_sha256']:
        raise ValueError('Exact frozen counterfactual bytes required')
    return mutant
