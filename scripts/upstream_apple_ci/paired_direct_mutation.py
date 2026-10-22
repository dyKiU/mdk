"""One reviewed source-only direct-lookup mutant, never a general hash override."""
import hashlib

MODE = 'old-direct-lookup'
SELECTOR = 'GenuinePairedDirectConversationTests/testRealMarmotClientReusesPairedSourceWithoutLocalMembershipOrInvitation'
DEFINITIONS = {
    'macos': ('whitenoise-mac/Core/MarmotClient.swift',
              'ada63677eb0b461a272a288bf16433d3b61d29b80f8285b08d07d67d56b53319',
              '60099dd28073fd9c0bbf5a51d1a45b8cae96a140ef0765929dcbc5a9f7d10297'),
    'ios': ('whitenoise-ios/Core/MarmotClient.swift',
            '0bb7cbca3c85c3e389db2df549995bd6b8f3c1943ca43cc8c8bc6ddfde9637c3',
            'a61be614fbc3a2701f990862eb956445a37881048dfad76b8088f73e3cb7fe9a'),
}


def transform(committed, platform):
    relative, original_hash, mutant_hash = DEFINITIONS[platform]
    if hashlib.sha256(committed).hexdigest() != original_hash:
        raise ValueError('Reviewed app adapter source changed; mutation requires review')
    text = committed.decode()
    needle = 'marmot.existingAccountDirectConversation('
    if text.count(needle) != 1:
        raise ValueError('Exactly one reviewed account direct lookup required')
    at = text.index(needle)
    start = text.rfind('#if WN_EXPERIMENTAL_DEVICE_SYNC', 0, at)
    line = text.rfind('\n', 0, start) + 1
    alternative = text.index('#else', at)
    old_start = text.index('\n', alternative) + 1
    end = text.index('#endif', old_start)
    end_line = text.rfind('\n', old_start, end) + 1
    after = text.index('\n', end) + 1
    old_body = text[old_start:end_line]
    if ('marmot.existingDirectConversation(' not in old_body
            or '.map(DirectConversationDestination.localMls)' not in old_body):
        raise ValueError('Exact original local-only adapter body required')
    mutant = (text[:line] + old_body + text[after:]).encode()
    if hashlib.sha256(mutant).hexdigest() != mutant_hash:
        raise ValueError('Whole-old-body mutant differs from independently frozen hash')
    return mutant


def expected_bytes(relative, committed, mode):
    if mode is None:
        return committed
    if mode != MODE:
        raise ValueError('Unknown paired direct mutation')
    for platform, (path, _, _) in DEFINITIONS.items():
        if relative == path:
            return transform(committed, platform)
    return committed


def identity(platform, mode):
    if mode is None:
        return None
    if mode != MODE:
        raise ValueError('Unknown paired direct mutation')
    path, original, mutant = DEFINITIONS[platform]
    return {'mode': mode, 'path': path, 'original_source_sha256': original,
            'intentional_mutant_source_sha256': mutant,
            'scope': 'Runtime mutation evidence only; not the qualified app source tree.'}
