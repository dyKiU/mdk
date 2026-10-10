//! Blocking aliases of the exact original UniFFI history owners.
#[cfg(feature = "experimental-device-sync")]
use crate::client_ref;
use crate::memory::{CFree, boxed, free_vec};
#[cfg(feature = "experimental-device-sync")]
use crate::memory::{owned_vec, required_str};
use crate::status::status_from_error;
use crate::types::history_transfer::{
    MarmotHistoryTransferRecipientList, MarmotHistoryTransferSnapshot,
};
use crate::{MarmotClient, MarmotStatus, block_on_handle, ffi_guard, preflight_out_ptr};
use std::{ffi::c_char, sync::Arc};

pub struct MarmotHistoryTransfer {
    inner: Arc<marmot_uniffi::HistoryTransfer>,
    runtime: tokio::runtime::Handle,
}
pub struct MarmotHistoryConsent {
    inner: Arc<marmot_uniffi::HistoryConsent>,
    runtime: tokio::runtime::Handle,
}
/// List-owned alias. Clone its handle before releasing the parent list.
#[repr(C)]
pub struct MarmotHistoryConsentEntry {
    pub handle: *mut MarmotHistoryConsent,
}
impl CFree for MarmotHistoryConsentEntry {
    unsafe fn free_in_place(&mut self) {
        unsafe { crate::subscriptions::free_plain(self.handle) };
    }
}
/// Owned list of original consent aliases. Its deep free releases every alias.
#[repr(C)]
pub struct MarmotHistoryConsentList {
    pub items: *mut MarmotHistoryConsentEntry,
    pub items_len: usize,
}
impl CFree for MarmotHistoryConsentList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.items_len) };
    }
}
macro_rules! arg {
    ($value:expr) => {
        match $value {
            Ok(value) => value,
            Err(status) => return status,
        }
    };
}
fn unit(result: Result<(), marmot_uniffi::MarmotKitError>) -> MarmotStatus {
    match result {
        Ok(()) => MarmotStatus::Ok,
        Err(error) => status_from_error(&error),
    }
}

/// Observe current linked-recipient choices; creates no transfer or consent.
/// # Safety
/// Live client, borrowed NUL-terminated strings and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_history_transfer_recipients(
    client: *const MarmotClient,
    account: *const c_char,
    group: *const c_char,
    out: *mut *mut MarmotHistoryTransferRecipientList,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (client, account, group);
            MarmotStatus::HistoryTransferUnsupported
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let client = arg!(unsafe { client_ref(client) });
            let account = arg!(unsafe { required_str(account) });
            let group = arg!(unsafe { required_str(group) });
            match client.block_on(client.marmot.history_transfer_recipients(account, group)) {
                Ok(recipients) => {
                    unsafe { *out = boxed(MarmotHistoryTransferRecipientList::from(recipients)) };
                    MarmotStatus::Ok
                }
                Err(error) => status_from_error(&error),
            }
        }
    })
}

/// Begin a bounded history action. Recipient is an exact 32-byte device identity.
/// # Safety
/// Live client, borrowed NUL-terminated strings, recipient readable for len and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_begin_history_transfer(
    client: *const MarmotClient,
    account: *const c_char,
    group: *const c_char,
    recipient: *const u8,
    recipient_len: usize,
    out: *mut *mut MarmotHistoryTransfer,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (client, account, group, recipient, recipient_len);
            MarmotStatus::HistoryTransferUnsupported
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            if recipient_len != 32 {
                return MarmotStatus::HistoryTransferNotReady;
            }
            if recipient.is_null() {
                return MarmotStatus::NullPointer;
            }
            let client = arg!(unsafe { client_ref(client) });
            let account = arg!(unsafe { required_str(account) });
            let group = arg!(unsafe { required_str(group) });
            let bytes = unsafe { std::slice::from_raw_parts(recipient, recipient_len) }.to_vec();
            match client.block_on(client.marmot.begin_history_transfer(account, group, bytes)) {
                Ok(inner) => {
                    unsafe {
                        *out = boxed(MarmotHistoryTransfer {
                            inner,
                            runtime: client.runtime.handle().clone(),
                        })
                    };
                    MarmotStatus::Ok
                }
                Err(error) => status_from_error(&error),
            }
        }
    })
}
/// Poll authenticated original requests. It never approves any returned action.
/// # Safety
/// Live client, borrowed NUL-terminated account and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_pending_history_requests(
    client: *const MarmotClient,
    account: *const c_char,
    out: *mut *mut MarmotHistoryConsentList,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (client, account);
            MarmotStatus::HistoryTransferUnsupported
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let client = arg!(unsafe { client_ref(client) });
            let account = arg!(unsafe { required_str(account) });
            match client.block_on(client.marmot.pending_history_requests(account)) {
                Ok(values) => {
                    let handles = values
                        .into_iter()
                        .map(|inner| MarmotHistoryConsentEntry {
                            handle: boxed(MarmotHistoryConsent {
                                inner,
                                runtime: client.runtime.handle().clone(),
                            }),
                        })
                        .collect();
                    let (items, items_len) = owned_vec(handles);
                    unsafe { *out = boxed(MarmotHistoryConsentList { items, items_len }) };
                    MarmotStatus::Ok
                }
                Err(error) => status_from_error(&error),
            }
        }
    })
}
/// Deep-free the list and all original aliases. NULL is a no-op.
/// # Safety
/// NULL or a library-owned result released exactly once with no concurrent calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_history_consent_list_free(list: *mut MarmotHistoryConsentList) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(list) });
}

/// Retain the same original action; releasing one alias does not cancel other aliases.
/// # Safety
/// Live handle and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_history_transfer_clone(
    handle: *const MarmotHistoryTransfer,
    out: *mut *mut MarmotHistoryTransfer,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe {
            *out = boxed(MarmotHistoryTransfer {
                inner: h.inner.clone(),
                runtime: h.runtime.clone(),
            })
        };
        MarmotStatus::Ok
    })
}
/// Release an alias. Last original-owner release cancels unfinished work.
/// # Safety
/// NULL or a library-owned handle released exactly once with no concurrent calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_history_transfer_free(handle: *mut MarmotHistoryTransfer) {
    crate::memory::free_guard(|| unsafe { crate::subscriptions::free_plain(handle) });
}
/// Read the original authenticated review and committed completion observation.
/// # Safety
/// Live handle and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_history_transfer_snapshot(
    handle: *const MarmotHistoryTransfer,
    out: *mut *mut MarmotHistoryTransferSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        match block_on_handle(&h.runtime, h.inner.snapshot()) {
            Ok(value) => {
                unsafe { *out = boxed(value.into()) };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}
/// Forward the displayed revision to the original action; no new authority is created.
/// # Safety
/// Live handle; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_history_transfer_continue_transfer(
    handle: *const MarmotHistoryTransfer,
    revision: u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unit(block_on_handle(
            &h.runtime,
            h.inner.continue_transfer(revision),
        ))
    })
}
/// Cancel the original action. Completed imported history is retained.
/// # Safety
/// Live handle; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_history_transfer_cancel(
    handle: *const MarmotHistoryTransfer,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        h.inner.cancel();
        MarmotStatus::Ok
    })
}

/// Retain the same original action; releasing one alias does not cancel other aliases.
/// # Safety
/// Live handle and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_history_consent_clone(
    handle: *const MarmotHistoryConsent,
    out: *mut *mut MarmotHistoryConsent,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe {
            *out = boxed(MarmotHistoryConsent {
                inner: h.inner.clone(),
                runtime: h.runtime.clone(),
            })
        };
        MarmotStatus::Ok
    })
}
/// Release an alias. Last original-owner release cancels unfinished work.
/// # Safety
/// NULL or a library-owned handle released exactly once with no concurrent calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_history_consent_free(handle: *mut MarmotHistoryConsent) {
    crate::memory::free_guard(|| unsafe { crate::subscriptions::free_plain(handle) });
}
/// Read the original authenticated review and committed completion observation.
/// # Safety
/// Live handle and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_history_consent_snapshot(
    handle: *const MarmotHistoryConsent,
    out: *mut *mut MarmotHistoryTransferSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        match block_on_handle(&h.runtime, h.inner.snapshot()) {
            Ok(value) => {
                unsafe { *out = boxed(value.into()) };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}
/// Forward the displayed revision to the original action; no new authority is created.
/// # Safety
/// Live handle; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_history_consent_approve(
    handle: *const MarmotHistoryConsent,
    revision: u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unit(block_on_handle(&h.runtime, h.inner.approve(revision)))
    })
}
/// Cancel the original action. Completed imported history is retained.
/// # Safety
/// Live handle; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_history_consent_cancel(
    handle: *const MarmotHistoryConsent,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        h.inner.cancel();
        MarmotStatus::Ok
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn history_required_outputs_preflight_before_foreign_inputs() {
        unsafe {
            assert_eq!(
                marmot_history_transfer_recipients(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_begin_history_transfer(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    usize::MAX,
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_pending_history_requests(ptr::null(), ptr::null(), ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_history_transfer_clone(ptr::null(), ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_history_consent_clone(ptr::null(), ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_history_transfer_snapshot(ptr::null(), ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_history_consent_snapshot(ptr::null(), ptr::null_mut()),
                MarmotStatus::NullPointer
            );
        }
    }

    #[test]
    fn history_null_originals_clear_outputs_and_null_frees_are_safe() {
        let mut transfer = ptr::dangling_mut();
        let mut consent = ptr::dangling_mut();
        let mut snapshot = ptr::dangling_mut();
        unsafe {
            assert_eq!(
                marmot_history_transfer_clone(ptr::null(), &mut transfer),
                MarmotStatus::NullPointer
            );
            assert!(transfer.is_null());
            assert_eq!(
                marmot_history_consent_clone(ptr::null(), &mut consent),
                MarmotStatus::NullPointer
            );
            assert!(consent.is_null());
            assert_eq!(
                marmot_history_transfer_snapshot(ptr::null(), &mut snapshot),
                MarmotStatus::NullPointer
            );
            assert!(snapshot.is_null());
            snapshot = ptr::dangling_mut();
            assert_eq!(
                marmot_history_consent_snapshot(ptr::null(), &mut snapshot),
                MarmotStatus::NullPointer
            );
            assert!(snapshot.is_null());
            assert_eq!(
                marmot_history_transfer_continue_transfer(ptr::null(), 1),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_history_consent_approve(ptr::null(), 1),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_history_transfer_cancel(ptr::null()),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_history_consent_cancel(ptr::null()),
                MarmotStatus::NullPointer
            );
            marmot_history_transfer_free(ptr::null_mut());
            marmot_history_consent_free(ptr::null_mut());
            marmot_history_consent_list_free(ptr::null_mut());
            crate::types::history_transfer::marmot_history_transfer_snapshot_free(ptr::null_mut());
        }
    }

    #[cfg(not(feature = "experimental-device-sync"))]
    #[test]
    fn default_history_factories_refuse_without_dereferencing_inputs() {
        let mut transfer = ptr::dangling_mut();
        let mut requests = ptr::dangling_mut();
        unsafe {
            assert_eq!(
                marmot_begin_history_transfer(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::dangling(),
                    usize::MAX,
                    &mut transfer
                ),
                MarmotStatus::HistoryTransferUnsupported
            );
            assert!(transfer.is_null());
            assert_eq!(
                marmot_pending_history_requests(ptr::null(), ptr::null(), &mut requests),
                MarmotStatus::HistoryTransferUnsupported
            );
            assert!(requests.is_null());
            let mut recipients = ptr::dangling_mut();
            assert_eq!(
                marmot_history_transfer_recipients(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    &mut recipients
                ),
                MarmotStatus::HistoryTransferUnsupported
            );
            assert!(recipients.is_null());
        }
    }

    #[cfg(feature = "experimental-device-sync")]
    #[test]
    fn history_recipient_query_null_client_clears_required_output() {
        let mut recipients = ptr::dangling_mut();
        unsafe {
            assert_eq!(
                marmot_history_transfer_recipients(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    &mut recipients
                ),
                MarmotStatus::NullPointer
            );
        }
        assert!(recipients.is_null());
    }

    #[cfg(feature = "alloc-audit")]
    #[test]
    fn history_recipient_choice_list_preserves_leaves_and_deep_frees_device_bytes() {
        let _lock = crate::memory::audit::test_lock();
        let before = crate::memory::audit::live_allocations();
        let list = boxed(MarmotHistoryTransferRecipientList::from(vec![
            marmot_uniffi::HistoryTransferRecipientFfi {
                leaf_index: 2,
                device: vec![3; 32],
            },
            marmot_uniffi::HistoryTransferRecipientFfi {
                leaf_index: 7,
                device: vec![8; 32],
            },
        ]));
        assert_eq!(crate::memory::audit::live_allocations(), before + 4);
        unsafe {
            let entries = std::slice::from_raw_parts((*list).items, (*list).len);
            assert_eq!(entries.len(), 2);
            for (entry, index, byte) in [(&entries[0], 2, 3), (&entries[1], 7, 8)] {
                assert_eq!(entry.leaf_index, index);
                assert_eq!(entry.device_len, 32);
                assert_eq!(
                    std::slice::from_raw_parts(entry.device, entry.device_len),
                    &[byte; 32]
                );
            }
            crate::types::history_transfer::marmot_history_transfer_recipient_list_free(list);
            crate::types::history_transfer::marmot_history_transfer_recipient_list_free(
                ptr::null_mut(),
            );
        }
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }

    #[cfg(feature = "alloc-audit")]
    #[test]
    fn history_owned_review_and_nonempty_null_entry_list_deep_free_without_leaks() {
        let _lock = crate::memory::audit::test_lock();
        let before = crate::memory::audit::live_allocations();
        let ffi = marmot_uniffi::HistoryTransferSnapshotFfi {
            revision: 1,
            imported_records: 0,
            complete: false,
            group_id_hex: "ab".repeat(16),
            source_device: vec![1; 32],
            recipient_device: vec![2; 32],
            snapshot_timestamp_ceiling: 120,
            record_count: 2,
            encoded_bytes: 8192,
            fragment_count: 6,
        };
        let snapshot = boxed(MarmotHistoryTransferSnapshot::from(ffi));
        assert!(crate::memory::audit::live_allocations() > before);
        unsafe { crate::types::history_transfer::marmot_history_transfer_snapshot_free(snapshot) };
        assert_eq!(crate::memory::audit::live_allocations(), before);
        let (items, items_len) = crate::memory::owned_vec(vec![
            MarmotHistoryConsentEntry {
                handle: ptr::null_mut(),
            },
            MarmotHistoryConsentEntry {
                handle: ptr::null_mut(),
            },
        ]);
        let list = boxed(MarmotHistoryConsentList { items, items_len });
        assert_eq!(crate::memory::audit::live_allocations(), before + 2);
        unsafe { marmot_history_consent_list_free(list) };
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }
}
