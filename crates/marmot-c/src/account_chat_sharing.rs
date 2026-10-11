//! Callback-safe aliases of the exact original UniFFI account-sharing approval.
use crate::{
    MarmotClient, MarmotStatus, block_on_handle, ffi_guard,
    memory::{CFree, boxed, free_vec},
    preflight_out_ptr,
    status::status_from_error,
    types::account_chat_sharing::{MarmotAccountSharingSnapshot, MarmotAccountSharingTargets},
};
#[cfg(feature = "experimental-device-sync")]
use crate::{
    client_ref,
    memory::{owned_vec, required_str},
};
use std::{ffi::c_char, sync::Arc};
pub struct MarmotAccountSharingApproval {
    inner: Arc<marmot_uniffi::AccountSharingApproval>,
    runtime: tokio::runtime::Handle,
}
/// Entry owned by its returned list. Clone the handle before freeing that list.
#[repr(C)]
pub struct MarmotAccountSharingApprovalEntry {
    pub handle: *mut MarmotAccountSharingApproval,
}
impl CFree for MarmotAccountSharingApprovalEntry {
    unsafe fn free_in_place(&mut self) {
        unsafe { crate::subscriptions::free_plain(self.handle) };
    }
}
/// Deep-owned aliases; releasing the last alias cancels unfinished originals.
#[repr(C)]
pub struct MarmotAccountSharingApprovalList {
    pub items: *mut MarmotAccountSharingApprovalEntry,
    pub items_len: usize,
}
impl CFree for MarmotAccountSharingApprovalList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.items_len) };
    }
}
macro_rules! arg {
    ($value:expr) => {
        match $value {
            Ok(v) => v,
            Err(status) => return status,
        }
    };
}
/// Observe current actual same-account Completed protected peers; never approve.
/// # Safety
/// Live client, borrowed account and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_chat_sharing_targets(
    client: *const MarmotClient,
    account: *const c_char,
    out: *mut *mut MarmotAccountSharingTargets,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (client, account);
            MarmotStatus::AccountSharingUnsupported
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let client = arg!(unsafe { client_ref(client) });
            let account = arg!(unsafe { required_str(account) });
            match client.block_on(client.marmot.account_chat_sharing_targets(account)) {
                Ok(v) => {
                    unsafe { *out = boxed(v.into()) };
                    MarmotStatus::Ok
                }
                Err(e) => status_from_error(&e),
            }
        }
    })
}
/// Begin one broad original review with an exact32-byte current protected peer.
/// # Safety
/// Live client, borrowed account/recipient and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_begin_account_chat_sharing(
    client: *const MarmotClient,
    account: *const c_char,
    recipient: *const u8,
    recipient_len: usize,
    out: *mut *mut MarmotAccountSharingApproval,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (client, account, recipient, recipient_len);
            MarmotStatus::AccountSharingUnsupported
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            if recipient_len != 32 {
                return MarmotStatus::AccountSharingNotReady;
            }
            if recipient.is_null() {
                return MarmotStatus::NullPointer;
            }
            let client = arg!(unsafe { client_ref(client) });
            let account = arg!(unsafe { required_str(account) });
            let recipient =
                unsafe { std::slice::from_raw_parts(recipient, recipient_len) }.to_vec();
            match client.block_on(client.marmot.begin_account_chat_sharing(account, recipient)) {
                Ok(inner) => {
                    unsafe {
                        *out = boxed(MarmotAccountSharingApproval {
                            inner,
                            runtime: client.runtime.handle().clone(),
                        })
                    };
                    MarmotStatus::Ok
                }
                Err(e) => status_from_error(&e),
            }
        }
    })
}
/// Observe addressed authenticated originals; polling never approves.
/// # Safety
/// Live client, borrowed account and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_pending_account_chat_sharing(
    client: *const MarmotClient,
    account: *const c_char,
    out: *mut *mut MarmotAccountSharingApprovalList,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (client, account);
            MarmotStatus::AccountSharingUnsupported
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let client = arg!(unsafe { client_ref(client) });
            let account = arg!(unsafe { required_str(account) });
            match client.block_on(client.marmot.pending_account_chat_sharing(account)) {
                Ok(values) => {
                    let handles = values
                        .into_iter()
                        .map(|inner| MarmotAccountSharingApprovalEntry {
                            handle: boxed(MarmotAccountSharingApproval {
                                inner,
                                runtime: client.runtime.handle().clone(),
                            }),
                        })
                        .collect();
                    let (items, items_len) = owned_vec(handles);
                    unsafe { *out = boxed(MarmotAccountSharingApprovalList { items, items_len }) };
                    MarmotStatus::Ok
                }
                Err(e) => status_from_error(&e),
            }
        }
    })
}
/// Retain the same original owner; this does not create new consent.
/// # Safety
/// Live handle and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_sharing_approval_clone(
    handle: *const MarmotAccountSharingApproval,
    out: *mut *mut MarmotAccountSharingApproval,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe {
            *out = boxed(MarmotAccountSharingApproval {
                inner: h.inner.clone(),
                runtime: h.runtime.clone(),
            })
        };
        MarmotStatus::Ok
    })
}
/// Release one alias. NULL is a no-op; the last alias cancels unfinished work.
/// # Safety
/// NULL or a library-owned handle freed exactly once; no concurrent calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_sharing_approval_free(
    handle: *mut MarmotAccountSharingApproval,
) {
    crate::memory::free_guard(|| unsafe { crate::subscriptions::free_plain(handle) });
}
/// Release the deep-owned list and its aliases. Clone retained entries first.
/// # Safety
/// NULL or a library-owned list freed exactly once; no concurrent calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_sharing_approval_list_free(
    list: *mut MarmotAccountSharingApprovalList,
) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(list) });
}
/// Observe this held original's authenticated review and completion.
/// # Safety
/// Live handle and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_sharing_approval_snapshot(
    handle: *const MarmotAccountSharingApproval,
    out: *mut *mut MarmotAccountSharingSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        match h.inner.snapshot() {
            Ok(v) => {
                unsafe { *out = boxed(v.into()) };
                MarmotStatus::Ok
            }
            Err(e) => status_from_error(&e),
        }
    })
}
/// Explicitly approve this exact original's displayed revision, callback-safe.
/// # Safety
/// Live handle; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_sharing_approval_approve(
    handle: *const MarmotAccountSharingApproval,
    displayed_revision: u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        match block_on_handle(&h.runtime, h.inner.approve(displayed_revision)) {
            Ok(()) => MarmotStatus::Ok,
            Err(e) => status_from_error(&e),
        }
    })
}
/// Cancel the unfinished original; completed broad policy requires revocation.
/// # Safety
/// Live handle; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_sharing_approval_cancel(
    handle: *const MarmotAccountSharingApproval,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        h.inner.cancel();
        MarmotStatus::Ok
    })
}

#[cfg(test)]
#[path = "account_chat_sharing/tests.rs"]
pub(crate) mod tests;
