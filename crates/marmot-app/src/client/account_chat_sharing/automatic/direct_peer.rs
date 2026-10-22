//! Presentation identity derived only from an actual direct chat and canonical roster.
use std::collections::BTreeSet;

pub(super) fn catalog_name(
    group_name: String,
    profile: Option<&crate::UserProfileMetadata>,
) -> String {
    if crate::chat_presentation::safe_name(&group_name).is_some() {
        return group_name;
    }
    let Some(mut name) = profile.and_then(crate::chat_presentation::public_profile_name) else {
        return group_name;
    };
    // The catalog bounds titles by UTF-8 bytes; never split a character.
    while name.len() > 1024 {
        name.pop();
    }
    name
}

pub(super) fn observed_peer<'a>(
    account: [u8; 32],
    reusable_direct: bool,
    members: impl Iterator<Item = &'a [u8]>,
) -> Option<[u8; 32]> {
    if !reusable_direct || account == [0; 32] {
        return None;
    }
    let mut accounts = BTreeSet::new();
    for member in members {
        let member: [u8; 32] = member.try_into().ok()?;
        if member == [0; 32] {
            return None;
        }
        accounts.insert(member);
        if accounts.len() > 2 {
            return None;
        }
    }
    if accounts.len() != 2 || !accounts.remove(&account) {
        return None;
    }
    accounts.into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_title_uses_the_same_public_name_fallback_as_native_chats() {
        let profile = crate::UserProfileMetadata {
            display_name: Some(" \u{202e}\n".into()),
            name: Some(" Known contact ".into()),
            ..Default::default()
        };
        assert_eq!(catalog_name(String::new(), Some(&profile)), "Known contact");
        assert_eq!(
            catalog_name("Custom title".into(), Some(&profile)),
            "Custom title"
        );
        assert_eq!(catalog_name(String::new(), None), "");
    }

    #[test]
    fn catalog_public_title_preserves_the_utf8_wire_bound() {
        let profile = crate::UserProfileMetadata {
            display_name: Some("🦊".repeat(400)),
            ..Default::default()
        };
        let name = catalog_name(String::new(), Some(&profile));
        assert_eq!(name, "🦊".repeat(256));
        assert_eq!(name.len(), 1024);
    }

    #[test]
    fn direct_peer_collapses_real_device_leaves_to_exactly_two_accounts() {
        let members = [[1; 32], [2; 32], [1; 32], [2; 32]];
        assert_eq!(
            observed_peer([1; 32], true, members.iter().map(|v| v.as_slice())),
            Some([2; 32])
        );
        assert_eq!(
            observed_peer([2; 32], true, members.iter().map(|v| v.as_slice())),
            Some([1; 32])
        );
    }

    #[test]
    fn direct_peer_never_infers_from_a_group_or_incomplete_roster() {
        for members in [
            vec![[1; 32]],
            vec![[2; 32], [3; 32]],
            vec![[1; 32], [2; 32], [3; 32]],
        ] {
            assert_eq!(
                observed_peer([1; 32], true, members.iter().map(|v| v.as_slice())),
                None
            );
        }
        let members = [[1; 32], [2; 32]];
        assert_eq!(
            observed_peer([1; 32], false, members.iter().map(|v| v.as_slice())),
            None
        );
    }

    #[test]
    fn direct_peer_rejects_malformed_or_zero_accounts() {
        for invalid in [vec![], vec![1; 31], vec![1; 33], vec![0; 32]] {
            let members = [vec![1; 32], invalid];
            assert_eq!(
                observed_peer([1; 32], true, members.iter().map(|v| v.as_slice())),
                None
            );
        }
    }
}
