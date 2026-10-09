//! Export immutable signed metadata without releasing the original lease.
use super::{OwnedLocalEnrollmentProposal, unavailable};
use crate::Engine;
use crate::private_enrollment_endorsement::AuthenticatedEnrollmentEndorsement;
use cgka_traits::{EngineError, StorageProvider};
impl<S: StorageProvider> Engine<S> {
    /// Copies signed bounded public metadata while retaining original SDK custody.
    pub fn export_owned_enrollment_recipient_packet(
        &self,
        proposal: &mut OwnedLocalEnrollmentProposal,
        receipts: &[&AuthenticatedEnrollmentEndorsement],
    ) -> Result<Vec<u8>, EngineError> {
        self.endorse_owned_local_enrollment_proposal(proposal)?;
        self.authenticate_owned_local_enrollment_endorsements(proposal, receipts)?;
        let mut packets = vec![
            proposal
                .own_endorsement
                .as_ref()
                .ok_or_else(unavailable)?
                .as_slice(),
        ];
        packets.extend(receipts.iter().map(|receipt| receipt.wire.as_slice()));
        let bytes = super::super::recipient::encode_packet(&proposal.frame, packets)?;
        self.check_local_enrollment_proposal(proposal)?;
        Ok(bytes)
    }
}
