"""One reviewed source-only direct-lookup mutant, never a general hash override."""
import hashlib

MODE = 'old-direct-lookup'
SELECTOR = 'GenuinePairedDirectConversationTests/testRealMarmotClientReusesPairedSourceWithoutLocalMembershipOrInvitation'
DEFINITIONS = {
    'macos': ('whitenoise-mac/Core/MarmotClient.swift',
              '267f4bbebc7adc30006ea51e562fd0071f5aee43c1e5855cec4afe1d05fc9f8b',
              '96f021cdd5fbbdf392309996b577ba7542d114d1a397a5356c40c6386f8a8047'),
    'ios': ('whitenoise-ios/Core/MarmotClient.swift',
            'e104f358bb4ebb20ee2f922037261801bd2c8b475c3aa55b359a120499ce3c3a',
            'c18391b267d1a160641e73e02dc74b1d858bab47d1f135756087803e57de0f93'),
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
