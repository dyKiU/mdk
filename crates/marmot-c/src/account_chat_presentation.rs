//! Thin bounded read adapters; policies are selected and validated inside App.
use crate::types::account_chat_presentation::{
    MarmotPairedChatListPage, MarmotPairedChatMessageCursor, MarmotPairedChatMessagePage,
};
use crate::{MarmotClient, MarmotStatus, ffi_guard, preflight_out_ptr};
#[cfg(feature = "experimental-device-sync")]
use crate::{
    client_ref,
    memory::{boxed, optional_str, required_str},
    status::status_from_error,
};
use std::ffi::c_char;
macro_rules! arg {
    ($value:expr) => {
        match $value {
            Ok(value) => value,
            Err(status) => return status,
        }
    };
}
/// Read one bounded paired chat catalog page. Nullable after_group starts at the beginning.
/// # Safety
/// Live client, readable borrowed strings and writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_paired_chat_list_page(
    client: *const MarmotClient,
    account: *const c_char,
    after_group: *const c_char,
    limit: u32,
    out: *mut *mut MarmotPairedChatListPage,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (client, account, after_group, limit);
            MarmotStatus::AccountSharingUnsupported
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let client = arg!(unsafe { client_ref(client) });
            let account = arg!(unsafe { required_str(account) });
            let after = arg!(unsafe { optional_str(after_group) });
            match client.block_on(client.marmot.paired_chat_list_page(account, after, limit)) {
                Ok(page) => {
                    unsafe { *out = boxed(page.into()) };
                    MarmotStatus::Ok
                }
                Err(error) => status_from_error(&error),
            }
        }
    })
}
/// Read chronological paired observations. Nullable after starts at the oldest retained record.
/// A returned cursor can be borrowed here; it remains owned by its page until page_free.
/// # Safety
/// Live client; readable borrowed strings/cursor; writable out; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_paired_chat_message_page(
    client: *const MarmotClient,
    account: *const c_char,
    group: *const c_char,
    after: *const MarmotPairedChatMessageCursor,
    limit: u32,
    out: *mut *mut MarmotPairedChatMessagePage,
) -> MarmotStatus {
    ffi_guard(|| {
        arg!(unsafe { preflight_out_ptr(out) });
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (client, account, group, after, limit);
            MarmotStatus::AccountSharingUnsupported
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let client = arg!(unsafe { client_ref(client) });
            let account = arg!(unsafe { required_str(account) });
            let group = arg!(unsafe { required_str(group) });
            let after = match unsafe { after.as_ref() } {
                Some(cursor) => Some(marmot_uniffi::conversions::PairedChatMessageCursorFfi {
                    created_at: cursor.created_at,
                    message_id_hex: arg!(unsafe { required_str(cursor.message_id_hex) }),
                }),
                None => None,
            };
            match client.block_on(
                client
                    .marmot
                    .paired_chat_message_page(account, group, after, limit),
            ) {
                Ok(page) => {
                    unsafe { *out = boxed(page.into()) };
                    MarmotStatus::Ok
                }
                Err(error) => status_from_error(&error),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn paired_read_preflight_clears_outputs_before_invalid_client() {
        unsafe {
            assert_eq!(
                marmot_paired_chat_list_page(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            let mut out = ptr::dangling_mut::<MarmotPairedChatListPage>();
            let result =
                marmot_paired_chat_list_page(ptr::null(), ptr::null(), ptr::null(), 0, &mut out);
            assert!(out.is_null());
            assert_eq!(
                result,
                if cfg!(feature = "experimental-device-sync") {
                    MarmotStatus::NullPointer
                } else {
                    MarmotStatus::AccountSharingUnsupported
                }
            );
            let mut messages = ptr::dangling_mut::<MarmotPairedChatMessagePage>();
            let result = marmot_paired_chat_message_page(
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                &mut messages,
            );
            assert!(messages.is_null());
            assert_eq!(
                result,
                if cfg!(feature = "experimental-device-sync") {
                    MarmotStatus::NullPointer
                } else {
                    MarmotStatus::AccountSharingUnsupported
                }
            );
        }
    }
}
