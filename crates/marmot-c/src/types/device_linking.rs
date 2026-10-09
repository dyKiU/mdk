//! Verification display/transport mirrors; no consent or purpose DTO crosses C.
use crate::macros::{c_enum, c_mirror};
use crate::memory::{CFree, free_vec, owned_vec};
use marmot_uniffi::conversions::*;

c_enum! { MarmotDeviceLinkingPhase from DeviceLinkingPhaseFfi { AwaitingSetup, AwaitingPeer, ComparisonAvailable, AwaitingPeerVerification, VerificationCompleteEnrollmentPending, Cancelled, Expired, Failed } }
c_mirror! { MarmotDeviceLinkingCapabilities from DeviceLinkingCapabilitiesFfi, free marmot_device_linking_capabilities_free { copy verification_supported: bool, copy enrollment_supported: bool, } }
c_mirror! { MarmotDeviceLinkingDecimals from DeviceLinkingDecimalsFfi { copy first: u16, copy second: u16, copy third: u16, } }
c_mirror! { MarmotDeviceLinkingSnapshot from DeviceLinkingSnapshotFfi, free marmot_device_linking_snapshot_free { copy revision: u64, copy phase: MarmotDeviceLinkingPhase, opt_rec decimals: MarmotDeviceLinkingDecimals, } }
c_mirror! { MarmotDeviceLinkingOutgoingPacket from DeviceLinkingOutgoingPacketFfi, list(MarmotDeviceLinkingOutgoingPacketList, marmot_device_linking_outgoing_packet_list_free) { str acknowledgement_id, bytes bytes/bytes_len, } }

/// Owned setup bytes. Free with marmot_device_linking_bytes_free.
#[repr(C)]
pub struct MarmotDeviceLinkingBytes {
    pub bytes: *mut u8,
    pub bytes_len: usize,
}
impl From<Vec<u8>> for MarmotDeviceLinkingBytes {
    fn from(value: Vec<u8>) -> Self {
        let (bytes, bytes_len) = owned_vec(value);
        Self { bytes, bytes_len }
    }
}
impl CFree for MarmotDeviceLinkingBytes {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.bytes, self.bytes_len) };
    }
}
/// Release owned setup bytes. NULL is a no-op.
/// # Safety
/// ptr must be NULL or a live library-owned result, released exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_device_linking_bytes_free(ptr: *mut MarmotDeviceLinkingBytes) {
    crate::memory::free_guard(|| unsafe { crate::memory::free_boxed(ptr) });
}
