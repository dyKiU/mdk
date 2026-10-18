//! C aliases of the held original UniFFI device action.
use crate::memory::boxed;
use crate::status::status_from_error;
use crate::types::device_revocation::MarmotDeviceRevocationSnapshot;
use crate::{MarmotClient, MarmotStatus, block_on_handle, ffi_guard, preflight_out_ptr};
#[cfg(feature = "experimental-device-sync")]
use crate::{client_ref, memory::required_str};
use std::{ffi::c_char, sync::Arc};

pub struct MarmotDeviceRevocation {
    inner: Arc<marmot_uniffi::DeviceRevocation>,
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

/// Capture an exact device's fresh groups. No removal occurs before explicit approval.
/// # Safety
/// Live client, borrowed account, target readable for len and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_begin_device_revocation(
    client: *const MarmotClient,
    account: *const c_char,
    target: *const u8,
    target_len: usize,
    out: *mut *mut MarmotDeviceRevocation,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (client, account, target, target_len);
            MarmotStatus::DeviceRevocationUnsupported
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            if target_len != 32 {
                return MarmotStatus::DeviceRevocationInvalidSelection;
            }
            if target.is_null() {
                return MarmotStatus::NullPointer;
            }
            let client = arg!(unsafe { client_ref(client) });
            let account = arg!(unsafe { required_str(account) });
            let target = unsafe { std::slice::from_raw_parts(target, target_len) }.to_vec();
            match client.block_on(client.marmot.begin_device_revocation(account, target)) {
                Ok(inner) => {
                    unsafe {
                        *out = boxed(MarmotDeviceRevocation {
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
/// Retain an alias of the exact original; dropping one alias does not cancel the others.
/// # Safety
/// Live original and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_revocation_clone(
    handle: *const MarmotDeviceRevocation,
    out: *mut *mut MarmotDeviceRevocation,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        unsafe {
            *out = boxed(MarmotDeviceRevocation {
                inner: h.inner.clone(),
                runtime: h.runtime.clone(),
            })
        };
        MarmotStatus::Ok
    })
}
/// Release one alias; the last alias retires the original App action.
/// # Safety
/// NULL or owned handle; no concurrent use/free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_revocation_free(handle: *mut MarmotDeviceRevocation) {
    ffi_guard(|| {
        unsafe { crate::subscriptions::free_plain(handle) };
        MarmotStatus::Ok
    });
}
/// Observe the exact original captured groups and confirmed progress.
/// # Safety
/// Live handle and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_revocation_snapshot(
    handle: *const MarmotDeviceRevocation,
    out: *mut *mut MarmotDeviceRevocationSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        match block_on_handle(&h.runtime, h.inner.snapshot()) {
            Ok(snapshot) => {
                unsafe { *out = boxed(snapshot.into()) };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}
/// Approve only this original action at the exact displayed revision.
/// # Safety
/// Live handle; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_revocation_approve(
    handle: *const MarmotDeviceRevocation,
    revision: u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let h = arg!(unsafe { handle.as_ref() }.ok_or(MarmotStatus::NullPointer));
        match block_on_handle(&h.runtime, h.inner.approve(revision)) {
            Ok(()) => MarmotStatus::Ok,
            Err(error) => status_from_error(&error),
        }
    })
}
/// Permanently cancel the exact original across all aliases.
/// # Safety
/// Live handle; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_revocation_cancel(
    handle: *const MarmotDeviceRevocation,
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
    fn revocation_required_outputs_preflight_and_clear_before_inputs() {
        unsafe {
            assert_eq!(
                marmot_begin_device_revocation(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    usize::MAX,
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_device_revocation_clone(ptr::null(), ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_device_revocation_snapshot(ptr::null(), ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            let mut handle = ptr::dangling_mut();
            assert_eq!(
                marmot_device_revocation_clone(ptr::null(), &mut handle),
                MarmotStatus::NullPointer
            );
            assert!(handle.is_null());
            let mut snapshot = ptr::dangling_mut();
            assert_eq!(
                marmot_device_revocation_snapshot(ptr::null(), &mut snapshot),
                MarmotStatus::NullPointer
            );
            assert!(snapshot.is_null());
            assert_eq!(
                marmot_device_revocation_cancel(ptr::null()),
                MarmotStatus::NullPointer
            );
            marmot_device_revocation_free(ptr::null_mut());
        }
    }
    #[cfg(not(feature = "experimental-device-sync"))]
    #[test]
    fn default_revocation_refuses_before_foreign_inputs() {
        let mut out = ptr::dangling_mut();
        unsafe {
            assert_eq!(
                marmot_begin_device_revocation(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    usize::MAX,
                    &mut out
                ),
                MarmotStatus::DeviceRevocationUnsupported
            );
        }
        assert!(out.is_null());
    }
    #[cfg(feature = "experimental-device-sync")]
    #[test]
    fn revocation_target_length_is_bounded_before_pointer_read() {
        let mut out = ptr::dangling_mut();
        unsafe {
            assert_eq!(
                marmot_begin_device_revocation(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    usize::MAX,
                    &mut out
                ),
                MarmotStatus::DeviceRevocationInvalidSelection
            );
        }
        assert!(out.is_null());
    }
}
