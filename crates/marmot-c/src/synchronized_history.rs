//! Local source-attested archive query; no reconstructed permission or media acquisition.
use crate::types::synchronized_history::MarmotArchivedHistoryPage;
use crate::{MarmotClient, MarmotStatus, ffi_guard, preflight_out_ptr};
#[cfg(feature = "experimental-device-sync")]
use crate::{
    client_ref,
    memory::{boxed, optional_str, required_str},
    status::status_from_error,
};
use std::ffi::c_char;

/// Read a bounded committed archive page in message-ID keyset order.
/// Default builds refuse before reading inputs. Results attest the source,
/// not independent original-author MLS authentication. No media is acquired.
/// # Safety
/// Live client, borrowed NUL-terminated account/group and optional cursor;
/// writable output. Do not free the client concurrently with this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_synchronized_history_page(
    client: *const MarmotClient,
    account: *const c_char,
    group: *const c_char,
    after_message_id: *const c_char,
    limit: u32,
    out: *mut *mut MarmotArchivedHistoryPage,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            let _ = (client, account, group, after_message_id, limit);
            MarmotStatus::SynchronizedHistoryUnsupported
        }
        #[cfg(feature = "experimental-device-sync")]
        {
            if !(1..=200).contains(&limit) {
                return MarmotStatus::SynchronizedHistoryInvalidQuery;
            }
            macro_rules! arg {
                ($value:expr) => {
                    match $value {
                        Ok(value) => value,
                        Err(status) => return status,
                    }
                };
            }
            let client = arg!(unsafe { client_ref(client) });
            let account = arg!(unsafe { required_str(account) });
            let group = arg!(unsafe { required_str(group) });
            let cursor = arg!(unsafe { optional_str(after_message_id) });
            match client
                .marmot
                .synchronized_history_page(account, group, cursor, limit)
            {
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
    fn archive_query_output_preflight_precedes_foreign_inputs() {
        unsafe {
            assert_eq!(
                marmot_synchronized_history_page(
                    ptr::dangling(),
                    ptr::dangling(),
                    ptr::dangling(),
                    ptr::dangling(),
                    0,
                    ptr::null_mut()
                ),
                MarmotStatus::NullPointer
            );
        }
    }
    #[cfg(not(feature = "experimental-device-sync"))]
    #[test]
    fn default_archive_query_refuses_without_dereferencing_inputs() {
        let mut page = ptr::dangling_mut();
        unsafe {
            assert_eq!(
                marmot_synchronized_history_page(
                    ptr::dangling(),
                    ptr::dangling(),
                    ptr::dangling(),
                    ptr::dangling(),
                    u32::MAX,
                    &mut page
                ),
                MarmotStatus::SynchronizedHistoryUnsupported
            );
        }
        assert!(page.is_null());
    }
    #[cfg(feature = "experimental-device-sync")]
    #[test]
    fn archive_query_bounds_refuse_before_foreign_inputs() {
        for limit in [0, 201, u32::MAX] {
            let mut page = ptr::dangling_mut();
            unsafe {
                assert_eq!(
                    marmot_synchronized_history_page(
                        ptr::dangling(),
                        ptr::dangling(),
                        ptr::dangling(),
                        ptr::dangling(),
                        limit,
                        &mut page
                    ),
                    MarmotStatus::SynchronizedHistoryInvalidQuery
                );
            }
            assert!(page.is_null());
        }
    }
    #[cfg(feature = "alloc-audit")]
    #[test]
    fn archived_page_deep_free_releases_nested_record_tags_and_provenance() {
        use marmot_uniffi::conversions::{
            ArchivedHistoryPageFfi, ArchivedHistoryRecordFfi, MessageTagFfi,
        };
        let _guard = crate::memory::audit::test_lock();
        let before = crate::memory::audit::live_allocations();
        let page = ArchivedHistoryPageFfi {
            records: vec![ArchivedHistoryRecordFfi {
                message_id_hex: "01".repeat(32),
                author_pubkey: "02".repeat(32),
                created_at: 12,
                expires_at: Some(24),
                deleted: false,
                content: "archived allocation fixture".into(),
                tags: vec![MessageTagFfi {
                    values: vec!["e".into(), "03".repeat(32)],
                }],
                media_attachments: vec![],
                transfer_id: vec![4; 32],
                source_device: vec![5; 32],
                manifest_digest: vec![6; 32],
            }],
            next_message_id_hex: Some("01".repeat(32)),
        };
        let owned = crate::memory::boxed(MarmotArchivedHistoryPage::from(page));
        assert!(crate::memory::audit::live_allocations() > before);
        unsafe {
            crate::types::synchronized_history::marmot_archived_history_page_free(owned);
            crate::types::synchronized_history::marmot_archived_history_page_free(ptr::null_mut());
        }
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }
}
