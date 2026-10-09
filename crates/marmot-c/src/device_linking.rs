//! Opaque original-action handles. Release handles before their creating client.
use crate::memory::{boxed, required_str};
use crate::status::{set_last_error, status_from_error};
use crate::types::device_linking::*;
use crate::{
    MarmotClient, MarmotStatus, block_on_handle, client_ref, ffi_guard, preflight_out_ptr,
};
use std::{ffi::c_char, sync::Arc};

/// Concurrent methods are supported; never free while a call is active.
pub struct MarmotDeviceLinkingSession {
    inner: Arc<marmot_uniffi::DeviceLinkingSession>,
    runtime: tokio::runtime::Handle,
}
/// Independent closeable observation stream; free before its client.
pub struct MarmotDeviceLinkingSubscription {
    inner: Arc<marmot_uniffi::DeviceLinkingSubscription>,
    runtime: tokio::runtime::Handle,
}
const MAX_PACKET_BYTES: usize = 512 * 1024;

macro_rules! arg {
    ($value:expr) => {
        match $value {
            Ok(value) => value,
            Err(status) => return status,
        }
    };
}
unsafe fn session<'a>(
    p: *const MarmotDeviceLinkingSession,
) -> Result<&'a MarmotDeviceLinkingSession, MarmotStatus> {
    unsafe { p.as_ref() }.ok_or(MarmotStatus::NullPointer)
}
unsafe fn subscription<'a>(
    p: *const MarmotDeviceLinkingSubscription,
) -> Result<&'a MarmotDeviceLinkingSubscription, MarmotStatus> {
    unsafe { p.as_ref() }.ok_or(MarmotStatus::NullPointer)
}
// Bound copying before touching caller bytes; App validates its stricter packet codec limits.
unsafe fn packet(p: *const u8, len: usize, limit: usize) -> Result<Vec<u8>, MarmotStatus> {
    if len > limit {
        set_last_error("device verification packet exceeds limit");
        return Err(MarmotStatus::DeviceLinkingInvalidPacket);
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

/// Read actual runtime capabilities; enrollment support remains false.
/// # Safety
/// client must be live and out writable; release the returned record with its matching free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_capabilities(
    client: *const MarmotClient,
    out: *mut *mut MarmotDeviceLinkingCapabilities,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let client = arg!(unsafe { client_ref(client) });
        unsafe { *out = boxed(client.marmot.device_linking_capabilities().into()) };
        MarmotStatus::Ok
    })
}
/// Reserve an opaque new-device verification session. Default builds return Unsupported.
/// # Safety
/// client/account must remain valid for the call and out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_begin_device_linking_session(
    client: *const MarmotClient,
    account: *const c_char,
    out: *mut *mut MarmotDeviceLinkingSession,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let client = arg!(unsafe { client_ref(client) });
        let account = arg!(unsafe { required_str(account) });
        match client.block_on(client.marmot.begin_device_linking_session(account)) {
            Ok(inner) => {
                unsafe {
                    *out = boxed(MarmotDeviceLinkingSession {
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
/// Approve bounded setup metadata. NULL/zero target means singleton; selected rosters are actor-validated.
/// # Safety
/// Borrowed byte buffers must be valid for their lengths; out/account/client must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_approve_device_linking_session(
    client: *const MarmotClient,
    account: *const c_char,
    request: *const u8,
    request_len: usize,
    target: *const u8,
    target_len: usize,
    out: *mut *mut MarmotDeviceLinkingSession,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let client = arg!(unsafe { client_ref(client) });
        let account = arg!(unsafe { required_str(account) });
        let request = arg!(unsafe { packet(request, request_len, MAX_PACKET_BYTES) });
        let target = if target.is_null() && target_len == 0 {
            None
        } else {
            Some(arg!(unsafe {
                packet(target, target_len, MAX_PACKET_BYTES)
            }))
        };
        match client.block_on(
            client
                .marmot
                .approve_device_linking_session(account, request, target),
        ) {
            Ok(inner) => {
                unsafe {
                    *out = boxed(MarmotDeviceLinkingSession {
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

/// Read verification setup packet; no proof or permission is exported.
/// # Safety
/// handle must be live, out writable; free the returned record with its matching free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_setup_packet(
    handle: *const MarmotDeviceLinkingSession,
    out: *mut *mut MarmotDeviceLinkingBytes,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let session = arg!(unsafe { session(handle) });
        unsafe { deliver(Ok(session.inner.setup_packet()), out) }
    })
}

/// Read verification outgoing packets; no proof or permission is exported.
/// # Safety
/// handle must be live, out writable; free the returned record with its matching free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_outgoing_packets(
    handle: *const MarmotDeviceLinkingSession,
    out: *mut *mut MarmotDeviceLinkingOutgoingPacketList,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let session = arg!(unsafe { session(handle) });
        unsafe {
            deliver(
                block_on_handle(&session.runtime, session.inner.outgoing_packets()),
                out,
            )
        }
    })
}

/// Read verification snapshot; no proof or permission is exported.
/// # Safety
/// handle must be live, out writable; free the returned record with its matching free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_snapshot(
    handle: *const MarmotDeviceLinkingSession,
    out: *mut *mut MarmotDeviceLinkingSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let session = arg!(unsafe { session(handle) });
        unsafe {
            deliver(
                block_on_handle(&session.runtime, session.inner.snapshot()),
                out,
            )
        }
    })
}

/// Deliver bounded original receive setup packet bytes; App authenticates its codec/binding.
/// # Safety
/// handle must be live and bytes valid for len; bytes are copied, never retained or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_receive_setup_packet(
    handle: *const MarmotDeviceLinkingSession,
    bytes: *const u8,
    len: usize,
) -> MarmotStatus {
    ffi_guard(|| {
        let session = arg!(unsafe { session(handle) });
        let bytes = arg!(unsafe { packet(bytes, len, MAX_PACKET_BYTES) });
        unit(block_on_handle(
            &session.runtime,
            session.inner.receive_setup_packet(bytes),
        ))
    })
}

/// Deliver bounded original receive packet bytes; App authenticates its codec/binding.
/// # Safety
/// handle must be live and bytes valid for len; bytes are copied, never retained or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_receive_packet(
    handle: *const MarmotDeviceLinkingSession,
    bytes: *const u8,
    len: usize,
) -> MarmotStatus {
    ffi_guard(|| {
        let session = arg!(unsafe { session(handle) });
        let bytes = arg!(unsafe { packet(bytes, len, MAX_PACKET_BYTES) });
        unit(block_on_handle(
            &session.runtime,
            session.inner.receive_packet(bytes),
        ))
    })
}

/// Apply confirm comparison to the displayed revision; enrollment continuation remains gated.
/// # Safety
/// handle must remain live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_confirm_comparison(
    handle: *const MarmotDeviceLinkingSession,
    displayed_revision: u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let session = arg!(unsafe { session(handle) });
        unit(block_on_handle(
            &session.runtime,
            session.inner.confirm_comparison(displayed_revision),
        ))
    })
}

/// Apply continue linking to the displayed revision; enrollment continuation remains gated.
/// # Safety
/// handle must remain live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_continue_linking(
    handle: *const MarmotDeviceLinkingSession,
    displayed_revision: u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let session = arg!(unsafe { session(handle) });
        unit(block_on_handle(
            &session.runtime,
            session.inner.continue_linking(displayed_revision),
        ))
    })
}

/// Acknowledge bounded UTF-8 transport metadata only; never approves enrollment.
/// # Safety
/// handle must be live and id valid for id_len; bytes are borrowed for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_acknowledge_packet(
    handle: *const MarmotDeviceLinkingSession,
    id: *const u8,
    id_len: usize,
) -> MarmotStatus {
    ffi_guard(|| {
        let session = arg!(unsafe { session(handle) });
        let bytes = arg!(unsafe { packet(id, id_len, 134) });
        let id = match String::from_utf8(bytes) {
            Ok(id) => id,
            Err(_) => return MarmotStatus::InvalidUtf8,
        };
        unit(block_on_handle(
            &session.runtime,
            session.inner.acknowledge_packet(id),
        ))
    })
}
/// Create an independent observation stream. Close wakes concurrent next calls.
/// # Safety
/// handle must be live and out writable; free the stream before its client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_subscribe(
    handle: *const MarmotDeviceLinkingSession,
    out: *mut *mut MarmotDeviceLinkingSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let session = arg!(unsafe { session(handle) });
        unsafe {
            *out = boxed(MarmotDeviceLinkingSubscription {
                inner: session.inner.subscribe(),
                runtime: session.runtime.clone(),
            })
        };
        MarmotStatus::Ok
    })
}
/// Exact cancellation bypasses positive native operation locks; errors never restore permission.
/// # Safety
/// handle must remain live for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_cancel(
    handle: *const MarmotDeviceLinkingSession,
) -> MarmotStatus {
    ffi_guard(|| {
        let session = arg!(unsafe { session(handle) });
        unit(block_on_handle(&session.runtime, session.inner.cancel()))
    })
}
/// Receive a coalesced observation. timeout_ms=0 waits until update/close; timeout consumes no update.
/// # Safety
/// handle must remain live, out writable. One receiver per stream; concurrent close is allowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_subscription_next(
    handle: *const MarmotDeviceLinkingSubscription,
    timeout_ms: u32,
    out: *mut *mut MarmotDeviceLinkingSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let sub = arg!(unsafe { subscription(handle) });
        block_on_handle(&sub.runtime, async {
            if timeout_ms == 0 {
                unsafe { deliver(sub.inner.next().await, out) }
            } else {
                match tokio::time::timeout(
                    std::time::Duration::from_millis(timeout_ms as u64),
                    sub.inner.next(),
                )
                .await
                {
                    Ok(result) => unsafe { deliver(result, out) },
                    Err(_) => MarmotStatus::Timeout,
                }
            }
        })
    })
}
/// Close this observation stream without freeing it or granting any permission.
/// # Safety
/// handle must remain live; concurrent next is allowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_subscription_close(
    handle: *const MarmotDeviceLinkingSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = arg!(unsafe { subscription(handle) });
        sub.inner.close();
        MarmotStatus::Ok
    })
}

/// Free the opaque session; NULL is a no-op. Session destruction schedules exact cancellation.
/// # Safety
/// handle must be NULL or library-owned with no active calls; free before its creating client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_free(
    handle: *mut MarmotDeviceLinkingSession,
) {
    crate::memory::free_guard(|| {
        unsafe { crate::subscriptions::free_plain(handle) };
    });
}

/// Free the opaque subscription; NULL is a no-op. Session destruction schedules exact cancellation.
/// # Safety
/// handle must be NULL or library-owned with no active calls; free before its creating client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_subscription_free(
    handle: *mut MarmotDeviceLinkingSubscription,
) {
    crate::memory::free_guard(|| {
        unsafe { crate::subscriptions::free_plain(handle) };
    });
}

#[cfg(test)]
mod tests;

/// An opaque original existing-device action. Clone to retain a list-borrowed handle.
pub struct MarmotDeviceLinkingApproval {
    inner: Arc<marmot_uniffi::DeviceLinkingApproval>,
    runtime: tokio::runtime::Handle,
}
/// Embedded borrowed handle, valid until its owning list is freed.
#[repr(C)]
pub struct MarmotDeviceLinkingApprovalEntry {
    pub handle: *mut MarmotDeviceLinkingApproval,
}
/// Owned list. Clone selected handles before freeing this list.
#[repr(C)]
pub struct MarmotDeviceLinkingApprovalList {
    pub items: *mut MarmotDeviceLinkingApprovalEntry,
    pub len: usize,
}
impl crate::memory::CFree for MarmotDeviceLinkingApprovalEntry {
    unsafe fn free_in_place(&mut self) {
        unsafe { crate::subscriptions::free_plain(self.handle) };
    }
}
impl crate::memory::CFree for MarmotDeviceLinkingApprovalList {
    unsafe fn free_in_place(&mut self) {
        unsafe { crate::memory::free_vec(self.items, self.len) };
    }
}
unsafe fn approval<'a>(
    handle: *const MarmotDeviceLinkingApproval,
) -> Result<&'a MarmotDeviceLinkingApproval, MarmotStatus> {
    unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer)
}

/// Observe protected roster selectors; selection is revalidated by the actor.
/// # Safety
/// client/account must remain valid and out writable for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_targets(
    client: *const MarmotClient,
    account: *const c_char,
    out: *mut *mut MarmotDeviceLinkingTargetList,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let client = arg!(unsafe { client_ref(client) });
        let account = arg!(unsafe { required_str(account) });
        unsafe {
            deliver(
                client.block_on(client.marmot.device_linking_targets(account)),
                out,
            )
        }
    })
}
/// Return opaque handles sharing original existing-device actions.
/// # Safety
/// client/account must remain valid and out writable. List entries are borrowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_pending_device_linking_approvals(
    client: *const MarmotClient,
    account: *const c_char,
    out: *mut *mut MarmotDeviceLinkingApprovalList,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let client = arg!(unsafe { client_ref(client) });
        let account = arg!(unsafe { required_str(account) });
        match client.block_on(client.marmot.pending_device_linking_approvals(account)) {
            Ok(values) => {
                let entries = values
                    .into_iter()
                    .map(|inner| MarmotDeviceLinkingApprovalEntry {
                        handle: boxed(MarmotDeviceLinkingApproval {
                            inner,
                            runtime: client.runtime.handle().clone(),
                        }),
                    })
                    .collect();
                let (items, len) = crate::memory::owned_vec(entries);
                unsafe { *out = boxed(MarmotDeviceLinkingApprovalList { items, len }) };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}
/// Retain a handle independently of its original list; no new approval action is created.
/// # Safety
/// handle must remain valid and out writable; free the returned clone separately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_approval_clone(
    handle: *const MarmotDeviceLinkingApproval,
    out: *mut *mut MarmotDeviceLinkingApproval,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let source = arg!(unsafe { approval(handle) });
        unsafe {
            *out = boxed(MarmotDeviceLinkingApproval {
                inner: source.inner.clone(),
                runtime: source.runtime.clone(),
            })
        };
        MarmotStatus::Ok
    })
}
/// Read finite observation of the same original action, never enrollment permission.
/// # Safety
/// handle must remain valid and out writable for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_approval_snapshot(
    handle: *const MarmotDeviceLinkingApproval,
    out: *mut *mut MarmotDeviceLinkingApprovalSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let handle = arg!(unsafe { approval(handle) });
        unsafe {
            deliver(
                block_on_handle(&handle.runtime, handle.inner.snapshot()),
                out,
            )
        }
    })
}
/// Explicit human approval bound to the displayed revision.
/// # Safety
/// handle must remain valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_approval_approve(
    handle: *const MarmotDeviceLinkingApproval,
    displayed_revision: u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let handle = arg!(unsafe { approval(handle) });
        unit(block_on_handle(
            &handle.runtime,
            handle.inner.approve(displayed_revision),
        ))
    })
}
/// Validate the complete packet through the same original existing-device action.
/// # Safety
/// handle and borrowed bytes must remain valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_approval_receive_enrollment_packet(
    handle: *const MarmotDeviceLinkingApproval,
    displayed_revision: u64,
    bytes: *const u8,
    len: usize,
) -> MarmotStatus {
    ffi_guard(|| {
        let handle = arg!(unsafe { approval(handle) });
        let bytes = arg!(unsafe { packet(bytes, len, MAX_PACKET_BYTES) });
        unit(block_on_handle(
            &handle.runtime,
            handle
                .inner
                .receive_enrollment_packet(displayed_revision, bytes),
        ))
    })
}
/// Revoke the exact original action; late packets cannot restore it.
/// # Safety
/// handle must remain valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_approval_cancel(
    handle: *const MarmotDeviceLinkingApproval,
) -> MarmotStatus {
    ffi_guard(|| {
        let handle = arg!(unsafe { approval(handle) });
        unit(block_on_handle(&handle.runtime, handle.inner.cancel()))
    })
}
/// Export complete all-leaf bytes before the original approver lease transfers.
/// # Safety
/// handle must remain valid and out writable for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_enrollment_packet(
    handle: *const MarmotDeviceLinkingSession,
    displayed_revision: u64,
    out: *mut *mut MarmotDeviceLinkingBytes,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let handle = arg!(unsafe { session(handle) });
        unsafe {
            deliver(
                block_on_handle(
                    &handle.runtime,
                    handle.inner.enrollment_packet(displayed_revision),
                ),
                out,
            )
        }
    })
}
/// Validate the complete packet under the original recipient purpose.
/// # Safety
/// handle and borrowed bytes must remain valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_receive_enrollment_packet(
    handle: *const MarmotDeviceLinkingSession,
    displayed_revision: u64,
    bytes: *const u8,
    len: usize,
) -> MarmotStatus {
    ffi_guard(|| {
        let handle = arg!(unsafe { session(handle) });
        let bytes = arg!(unsafe { packet(bytes, len, MAX_PACKET_BYTES) });
        unit(block_on_handle(
            &handle.runtime,
            handle
                .inner
                .receive_enrollment_packet(displayed_revision, bytes),
        ))
    })
}
/// Finalize original Add publication after explicit recipient packet handling.
/// # Safety
/// handle must remain valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_session_finalize_linking(
    handle: *const MarmotDeviceLinkingSession,
    displayed_revision: u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let handle = arg!(unsafe { session(handle) });
        unit(block_on_handle(
            &handle.runtime,
            handle.inner.finalize_linking(displayed_revision),
        ))
    })
}
/// Free a standalone or cloned approval handle; never free a list-borrowed entry.
/// # Safety
/// handle must be NULL or library-owned, with no active calls; free before its client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_approval_free(
    handle: *mut MarmotDeviceLinkingApproval,
) {
    crate::memory::free_guard(|| unsafe { crate::subscriptions::free_plain(handle) });
}
/// Deep-free the list and every borrowed entry; retained clones stay valid.
/// # Safety
/// list must be NULL or a live library-owned list, released exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_approval_list_free(
    list: *mut MarmotDeviceLinkingApprovalList,
) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(list) });
}
