//! Thin selected-chat ABI; shared opaque handles retain the exact original App owner.
use crate::memory::{boxed, required_str};
use crate::status::{set_last_error, status_from_error};
use crate::types::selected_chat_copy::*;
use crate::{
    MarmotClient, MarmotStatus, block_on_handle, client_ref, ffi_guard, preflight_out_ptr,
};
use std::{ffi::c_char, sync::Arc};

/// Concurrent methods are supported; free only when no call uses this handle.
pub struct MarmotSelectedChatCopy {
    inner: Arc<marmot_uniffi::SelectedChatCopy>,
    runtime: tokio::runtime::Handle,
}
/// Clones share one original consent action; release all handles before their client.
pub struct MarmotSelectedChatConsent {
    inner: Arc<marmot_uniffi::SelectedChatConsent>,
    runtime: tokio::runtime::Handle,
}
macro_rules! arg {
    ($value:expr) => {
        match $value {
            Ok(value) => value,
            Err(status) => return status,
        }
    };
}
unsafe fn packet(p: *const u8, len: usize) -> Result<Vec<u8>, MarmotStatus> {
    if len > 16384 {
        set_last_error("selected-chat packet exceeds limit");
        return Err(MarmotStatus::SelectedChatCopyInvalidPacket);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    if p.is_null() {
        return Err(MarmotStatus::NullPointer);
    }
    Ok(unsafe { std::slice::from_raw_parts(p, len) }.to_vec())
}
fn unit(result: Result<(), marmot_uniffi::MarmotKitError>) -> MarmotStatus {
    match result {
        Ok(()) => MarmotStatus::Ok,
        Err(error) => status_from_error(&error),
    }
}
unsafe fn deliver<T: From<U>, U>(
    result: Result<U, marmot_uniffi::MarmotKitError>,
    out: *mut *mut T,
) -> MarmotStatus {
    match result {
        Ok(value) => {
            unsafe { *out = boxed(value.into()) };
            MarmotStatus::Ok
        }
        Err(error) => status_from_error(&error),
    }
}
/// Request one ordinary chat under a fresh protected-roster selector; no sibling consent is implied.
/// # Safety
/// client/account/group must be live; selector readable for len; out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_begin_selected_chat_copy(
    client: *const MarmotClient,
    account: *const c_char,
    group_id_hex: *const c_char,
    selector: *const u8,
    selector_len: usize,
    out: *mut *mut MarmotSelectedChatCopy,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let client = arg!(unsafe { client_ref(client) });
        let account = arg!(unsafe { required_str(account) });
        let group = arg!(unsafe { required_str(group_id_hex) });
        let selector = arg!(unsafe { packet(selector, selector_len) });
        match client.block_on(
            client
                .marmot
                .begin_selected_chat_copy(account, group, selector),
        ) {
            Ok(inner) => {
                unsafe {
                    *out = boxed(MarmotSelectedChatCopy {
                        inner,
                        runtime: client.runtime.handle().clone(),
                    })
                };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}
/// Import bounded metadata into an opaque original consent action; importing is not approval.
/// # Safety
/// client/account live; packet readable for len; out writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_receive_selected_chat_copy_request(
    client: *const MarmotClient,
    account: *const c_char,
    bytes: *const u8,
    len: usize,
    out: *mut *mut MarmotSelectedChatConsent,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let client = arg!(unsafe { client_ref(client) });
        let account = arg!(unsafe { required_str(account) });
        let bytes = arg!(unsafe { packet(bytes, len) });
        match client.block_on(
            client
                .marmot
                .receive_selected_chat_copy_request(account, bytes),
        ) {
            Ok(inner) => {
                unsafe {
                    *out = boxed(MarmotSelectedChatConsent {
                        inner,
                        runtime: client.runtime.handle().clone(),
                    })
                };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}

/// Retain an alias of the same original action. Releasing one alias does not cancel others.
/// # Safety
/// handle must be live and out writable; never free concurrently with a call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_copy_clone(
    handle: *const MarmotSelectedChatCopy,
    out: *mut *mut MarmotSelectedChatCopy,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe {
            *out = boxed(MarmotSelectedChatCopy {
                inner: h.inner.clone(),
                runtime: h.runtime.clone(),
            })
        };
        MarmotStatus::Ok
    })
}
/// Release an opaque alias. The last alias drops the original action; NULL is a no-op.
/// # Safety
/// handle must be NULL or a live library-owned handle released exactly once; no concurrent calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_copy_free(handle: *mut MarmotSelectedChatCopy) {
    crate::memory::free_guard(|| unsafe { crate::subscriptions::free_plain(handle) });
}

/// Perform snapshot on this exact original action; App revalidates displayed revisions.
/// # Safety
/// handle must be live; byte inputs readable for len and any output writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_copy_snapshot(
    handle: *const MarmotSelectedChatCopy,
    out: *mut *mut MarmotSelectedChatCopySnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe { deliver(block_on_handle(&h.runtime, h.inner.snapshot()), out) }
    })
}

/// Perform request packet on this exact original action; App revalidates displayed revisions.
/// # Safety
/// handle must be live; byte inputs readable for len and any output writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_copy_request_packet(
    handle: *const MarmotSelectedChatCopy,
    revision: u64,
    out: *mut *mut MarmotSelectedChatBytes,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe {
            deliver(
                block_on_handle(&h.runtime, h.inner.request_packet(revision)),
                out,
            )
        }
    })
}

/// Perform receive consent packet on this exact original action; App revalidates displayed revisions.
/// # Safety
/// handle must be live; byte inputs readable for len and any output writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_copy_receive_consent_packet(
    handle: *const MarmotSelectedChatCopy,
    revision: u64,
    bytes: *const u8,
    len: usize,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        let bytes = arg!(unsafe { packet(bytes, len) });
        unit(block_on_handle(
            &h.runtime,
            h.inner.receive_consent_packet(revision, bytes),
        ))
    })
}

/// Perform receive offer packet on this exact original action; App revalidates displayed revisions.
/// # Safety
/// handle must be live; byte inputs readable for len and any output writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_copy_receive_offer_packet(
    handle: *const MarmotSelectedChatCopy,
    revision: u64,
    bytes: *const u8,
    len: usize,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        let bytes = arg!(unsafe { packet(bytes, len) });
        unit(block_on_handle(
            &h.runtime,
            h.inner.receive_offer_packet(revision, bytes),
        ))
    })
}

/// Perform continue on this exact original action; App revalidates displayed revisions.
/// # Safety
/// handle must be live; byte inputs readable for len and any output writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_copy_continue(
    handle: *const MarmotSelectedChatCopy,
    revision: u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unit(block_on_handle(&h.runtime, h.inner.continue_copy(revision)))
    })
}

/// Perform cancel on this exact original action; App revalidates displayed revisions.
/// # Safety
/// handle must be live; byte inputs readable for len and any output writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_copy_cancel(
    handle: *const MarmotSelectedChatCopy,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unit(block_on_handle(&h.runtime, h.inner.cancel()))
    })
}

/// Retain an alias of the same original action. Releasing one alias does not cancel others.
/// # Safety
/// handle must be live and out writable; never free concurrently with a call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_consent_clone(
    handle: *const MarmotSelectedChatConsent,
    out: *mut *mut MarmotSelectedChatConsent,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe {
            *out = boxed(MarmotSelectedChatConsent {
                inner: h.inner.clone(),
                runtime: h.runtime.clone(),
            })
        };
        MarmotStatus::Ok
    })
}
/// Release an opaque alias. The last alias drops the original action; NULL is a no-op.
/// # Safety
/// handle must be NULL or a live library-owned handle released exactly once; no concurrent calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_consent_free(handle: *mut MarmotSelectedChatConsent) {
    crate::memory::free_guard(|| unsafe { crate::subscriptions::free_plain(handle) });
}

/// Perform snapshot on this exact original action; App revalidates displayed revisions.
/// # Safety
/// handle must be live; byte inputs readable for len and any output writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_consent_snapshot(
    handle: *const MarmotSelectedChatConsent,
    out: *mut *mut MarmotSelectedChatConsentSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe { deliver(block_on_handle(&h.runtime, h.inner.snapshot()), out) }
    })
}

/// Perform approve on this exact original action; App revalidates displayed revisions.
/// # Safety
/// handle must be live; byte inputs readable for len and any output writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_consent_approve(
    handle: *const MarmotSelectedChatConsent,
    revision: u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unit(block_on_handle(&h.runtime, h.inner.approve(revision)))
    })
}

/// Perform response packet on this exact original action; App revalidates displayed revisions.
/// # Safety
/// handle must be live; byte inputs readable for len and any output writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_consent_response_packet(
    handle: *const MarmotSelectedChatConsent,
    revision: u64,
    out: *mut *mut MarmotSelectedChatBytes,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe {
            deliver(
                block_on_handle(&h.runtime, h.inner.response_packet(revision)),
                out,
            )
        }
    })
}

/// Perform offer packet on this exact original action; App revalidates displayed revisions.
/// # Safety
/// handle must be live; byte inputs readable for len and any output writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_consent_offer_packet(
    handle: *const MarmotSelectedChatConsent,
    revision: u64,
    out: *mut *mut MarmotSelectedChatBytes,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe {
            deliver(
                block_on_handle(&h.runtime, h.inner.offer_packet(revision)),
                out,
            )
        }
    })
}

/// Perform cancel on this exact original action; App revalidates displayed revisions.
/// # Safety
/// handle must be live; byte inputs readable for len and any output writable; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_selected_chat_consent_cancel(
    handle: *const MarmotSelectedChatConsent,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unit(block_on_handle(&h.runtime, h.inner.cancel()))
    })
}
