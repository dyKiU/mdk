//! Blocking C owners of automatically refreshed account chat views.
use super::*;
use crate::types::account_chat_presentation::MarmotPairedChatMessageCursor;
use crate::types::account_chat_windows::*;

/// Free before its client; commands may run during next, never free during a call.
pub struct MarmotAccountChatListWindowSubscription {
    core: SubscriptionCore,
    inner: Arc<marmot_uniffi::subscriptions::AccountChatListWindowSubscription>,
}
/// Take the initial complete replacement once. A second call returns Closed.
/// # Safety
/// Live handle and writable output; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_chat_list_window_subscription_snapshot(
    sub: *const MarmotAccountChatListWindowSubscription,
    out: *mut *mut MarmotAccountChatListWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        unsafe { deliver_next(Ok(sub.inner.snapshot()), out) }
    })
}
/// Receive one replacement. Zero timeout waits indefinitely; timeout consumes no update.
/// # Safety
/// Live handle and writable output; one receiver and no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_chat_list_window_subscription_next(
    sub: *const MarmotAccountChatListWindowSubscription,
    timeout_ms: u32,
    out: *mut *mut MarmotAccountChatListWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let result = match sub
            .core
            .block_next(timeout_ms, async { Some(sub.inner.next().await) })
        {
            Ok(Some(Ok(item))) => Ok(item),
            Ok(Some(Err(error))) => Err(status_from_error(&error)),
            Ok(None) => Ok(None),
            Err(status) => Err(status),
        };
        unsafe { deliver_next(result, out) }
    })
}
/// Synchronously cancel the original owner and wake a pending receiver. Idempotent.
/// # Safety
/// Live handle; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_chat_list_window_subscription_cancel(
    sub: *const MarmotAccountChatListWindowSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = try_arg!(unsafe { sub_ref(sub) });
        sub.inner.cancel();
        MarmotStatus::Ok
    })
}
/// Cancel and free. NULL is a no-op; previously returned snapshots remain owned by caller.
/// # Safety
/// Library-owned handle with no active calls, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_chat_list_window_subscription_free(
    sub: *mut MarmotAccountChatListWindowSubscription,
) {
    crate::memory::free_guard(|| unsafe { free_plain(sub) });
}

/// Open an account-owned source-qualified view. Take snapshot once, then receive replacements.
/// Default cohorts return Unsupported after output preflight, before reading borrowed inputs.
/// # Safety
/// Live client, readable borrowed strings and writable output; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_open_account_chat_list_window(
    client: *const MarmotClient,
    account_ref: *const c_char,
    initial_rows: u32,
    out: *mut *mut MarmotAccountChatListWindowSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (client, account_ref, initial_rows);
            MarmotStatus::AccountSharingUnsupported
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let client = try_arg!(unsafe { client_ref(client) });
            let account = try_arg!(unsafe { required_str(account_ref) });
            match client.block_on(
                client
                    .marmot
                    .open_account_chat_list_window(account, initial_rows),
            ) {
                Ok(inner) => unsafe {
                    write_handle(
                        MarmotAccountChatListWindowSubscription {
                            core: SubscriptionCore::new(client.runtime.handle().clone()),
                            inner,
                        },
                        out,
                    )
                },
                Err(error) => status_from_error(&error),
            }
        }
    })
}

/// Free before its client; commands may run during next, never free during a call.
pub struct MarmotAccountConversationWindowSubscription {
    core: SubscriptionCore,
    inner: Arc<marmot_uniffi::subscriptions::AccountConversationWindowSubscription>,
}
/// Take the initial complete replacement once. A second call returns Closed.
/// # Safety
/// Live handle and writable output; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_conversation_window_subscription_snapshot(
    sub: *const MarmotAccountConversationWindowSubscription,
    out: *mut *mut MarmotAccountConversationWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        unsafe { deliver_next(Ok(sub.inner.snapshot()), out) }
    })
}
/// Receive one replacement. Zero timeout waits indefinitely; timeout consumes no update.
/// # Safety
/// Live handle and writable output; one receiver and no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_conversation_window_subscription_next(
    sub: *const MarmotAccountConversationWindowSubscription,
    timeout_ms: u32,
    out: *mut *mut MarmotAccountConversationWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let result = match sub
            .core
            .block_next(timeout_ms, async { Some(sub.inner.next().await) })
        {
            Ok(Some(Ok(item))) => Ok(item),
            Ok(Some(Err(error))) => Err(status_from_error(&error)),
            Ok(None) => Ok(None),
            Err(status) => Err(status),
        };
        unsafe { deliver_next(result, out) }
    })
}
/// Synchronously cancel the original owner and wake a pending receiver. Idempotent.
/// # Safety
/// Live handle; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_conversation_window_subscription_cancel(
    sub: *const MarmotAccountConversationWindowSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        let sub = try_arg!(unsafe { sub_ref(sub) });
        sub.inner.cancel();
        MarmotStatus::Ok
    })
}
/// Cancel and free. NULL is a no-op; previously returned snapshots remain owned by caller.
/// # Safety
/// Library-owned handle with no active calls, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_conversation_window_subscription_free(
    sub: *mut MarmotAccountConversationWindowSubscription,
) {
    crate::memory::free_guard(|| unsafe { free_plain(sub) });
}

/// Open an account-owned source-qualified view. Take snapshot once, then receive replacements.
/// Default cohorts return Unsupported after output preflight, before reading borrowed inputs.
/// # Safety
/// Live client, readable borrowed strings and writable output; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_open_account_conversation_window(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    initial_rows: u32,
    out: *mut *mut MarmotAccountConversationWindowSubscription,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (client, account_ref, group_id_hex, initial_rows);
            MarmotStatus::AccountSharingUnsupported
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            let client = try_arg!(unsafe { client_ref(client) });
            let account = try_arg!(unsafe { required_str(account_ref) });
            let group = try_arg!(unsafe { required_str(group_id_hex) });
            match client.block_on(client.marmot.open_account_conversation_window(
                account,
                group,
                initial_rows,
            )) {
                Ok(inner) => unsafe {
                    write_handle(
                        MarmotAccountConversationWindowSubscription {
                            core: SubscriptionCore::new(client.runtime.handle().clone()),
                            inner,
                        },
                        out,
                    )
                },
                Err(error) => status_from_error(&error),
            }
        }
    })
}

/// Read a bounded paired catalog page, conditional on the installed sequence.
/// # Safety
/// Live handle, readable nullable cursor string and writable output; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_chat_list_window_subscription_paired_page(
    sub: *const MarmotAccountChatListWindowSubscription,
    sequence: u64,
    after_group_id_hex: *const c_char,
    out: *mut *mut MarmotAccountChatListWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let after = try_arg!(unsafe { optional_str(after_group_id_hex) });
        match block_on_handle(&sub.core.runtime, sub.inner.paired_page(sequence, after)) {
            Ok(value) => unsafe { deliver_next(Ok(Some(value)), out) },
            Err(error) => status_from_error(&error),
        }
    })
}
/// Read bounded older observations, conditional on the installed sequence.
/// # Safety
/// Live handle, readable nullable borrowed cursor and writable output; no concurrent free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_conversation_window_subscription_older_page(
    sub: *const MarmotAccountConversationWindowSubscription,
    sequence: u64,
    before: *const MarmotPairedChatMessageCursor,
    out: *mut *mut MarmotAccountConversationWindowSnapshot,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out_ptr(out) });
        let sub = try_arg!(unsafe { sub_ref(sub) });
        let before = match unsafe { before.as_ref() } {
            Some(cursor) => Some(marmot_uniffi::conversions::PairedChatMessageCursorFfi {
                created_at: cursor.created_at,
                message_id_hex: try_arg!(unsafe { required_str(cursor.message_id_hex) }),
            }),
            None => None,
        };
        match block_on_handle(&sub.core.runtime, sub.inner.older_page(sequence, before)) {
            Ok(value) => unsafe { deliver_next(Ok(Some(value)), out) },
            Err(error) => status_from_error(&error),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    #[test]
    fn account_window_open_preflights_before_invalid_client_and_default_input_reads() {
        unsafe {
            assert_eq!(
                marmot_open_account_chat_list_window(ptr::null(), ptr::null(), 0, ptr::null_mut()),
                MarmotStatus::NullPointer
            );
            assert_eq!(
                marmot_open_account_conversation_window(
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
            let mut list = ptr::dangling_mut::<MarmotAccountChatListWindowSubscription>();
            let status =
                marmot_open_account_chat_list_window(ptr::null(), ptr::dangling(), 0, &mut list);
            assert!(list.is_null());
            assert_eq!(
                status,
                if cfg!(feature = "experimental-device-sync") {
                    MarmotStatus::NullPointer
                } else {
                    MarmotStatus::AccountSharingUnsupported
                }
            );
            let mut conversation =
                ptr::dangling_mut::<MarmotAccountConversationWindowSubscription>();
            let status = marmot_open_account_conversation_window(
                ptr::null(),
                ptr::dangling(),
                ptr::dangling(),
                0,
                &mut conversation,
            );
            assert!(conversation.is_null());
            assert_eq!(
                status,
                if cfg!(feature = "experimental-device-sync") {
                    MarmotStatus::NullPointer
                } else {
                    MarmotStatus::AccountSharingUnsupported
                }
            );
        }
    }
}
