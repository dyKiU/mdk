"""One reviewed source-only direct-lookup mutant, never a general hash override."""
import hashlib
import factory_semantic_mutation as factory

MODE = 'old-direct-lookup'
MODES = (MODE,) + factory.MODES
SELECTOR = 'GenuinePairedDirectConversationTests/testRealMarmotClientReusesPairedSourceWithoutLocalMembershipOrInvitation'
DEFINITIONS = {
    'macos': ('whitenoise-mac/Core/MarmotClient.swift',
              '651a939ef24ed246d8c1fb1c6ef68ebf0d6c2d2eee529705828622e2369e77e4',
              '3f9c4a9643909cdea0f1b50dbba45109cd1c0e37849dc17959f86d62faefd0f1'),
    'ios': ('whitenoise-ios/Core/MarmotClient.swift',
            '6e949a159832d0ace67bac2dc6f5f0460161b0544b267f150088e6348a5c2f9b',
            '436e3d20972b0ee90ff8b5aeb11ff6fdcfaf82aeb63fe1cb0abfd6eaf1eb464d'),
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
    if mode in factory.MODES:
        for platform, cases in factory.DEFINITIONS.items():
            if relative == cases['begin']['path']:
                return factory.transform(committed, platform, mode)
        return committed
    if mode is None:
        return committed
    if mode != MODE:
        raise ValueError('Unknown paired direct mutation')
    for platform, (path, _, _) in DEFINITIONS.items():
        if relative == path:
            return transform(committed, platform)
    return committed


def identity(platform, mode):
    if mode in factory.MODES:
        case = 'begin' if mode == factory.MODES[0] else 'scan'
        entry = factory.DEFINITIONS[platform][case]
        return {'mode': mode, 'path': entry['path'],
                'original_source_sha256': entry['original_sha256'],
                'intentional_mutant_source_sha256': entry['mutant_sha256'],
                'scope': 'Exact factory semantic counterfactual only; not qualified app source.'}
    if mode is None:
        return None
    if mode != MODE:
        raise ValueError('Unknown paired direct mutation')
    path, original, mutant = DEFINITIONS[platform]
    return {'mode': mode, 'path': path, 'original_source_sha256': original,
            'intentional_mutant_source_sha256': mutant,
            'scope': 'Runtime mutation evidence only; not the qualified app source tree.'}
