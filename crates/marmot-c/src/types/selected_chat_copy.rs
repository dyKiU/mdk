//! Selected-chat observation mirrors; these are not membership or consent grants.
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, free_vec, owned_vec};
use marmot_uniffi::conversions::*;

c_enum! { MarmotSelectedChatCopyPhase from SelectedChatCopyPhaseFfi { AwaitingSiblingConsent, Cancelled, Expired, Closed, InviteConfirmed } }
c_enum! { MarmotSelectedChatConsentPhase from SelectedChatConsentPhaseFfi { AwaitingApproval, Approved, Cancelled, Expired, Closed } }
c_mirror! { MarmotSelectedChatCopySnapshot from SelectedChatCopySnapshotFfi, free marmot_selected_chat_copy_snapshot_free { copy revision: u64, copy phase: MarmotSelectedChatCopyPhase, copy sibling_count: u32, copy consenting_sibling_count: u32, copy offered_sibling_count: u32, } }
c_mirror! { MarmotSelectedChatConsentSnapshot from SelectedChatConsentSnapshotFfi, free marmot_selected_chat_consent_snapshot_free { copy revision: u64, copy phase: MarmotSelectedChatConsentPhase, bytes chat_selector/chat_selector_len, } }

/// Owned bounded observation/offer packet. Release with its matching free.
#[repr(C)]
pub struct MarmotSelectedChatBytes {
    pub bytes: *mut u8,
    pub bytes_len: usize,
}
impl From<Vec<u8>> for MarmotSelectedChatBytes {
    fn from(value: Vec<u8>) -> Self {
        let (bytes, bytes_len) = owned_vec(value);
        Self { bytes, bytes_len }
    }
}
impl CFree for MarmotSelectedChatBytes {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.bytes, self.bytes_len) };
    }
}
/// Release an owned selected-chat packet. NULL is a no-op.
/// # Safety
/// ptr must be NULL or a library-owned result released exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_bytes_free(ptr: *mut MarmotSelectedChatBytes) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(ptr) });
}
