//! Bounded positive memo of pure public proof verification, owned by one Engine.
//! Every credential, profile, binding and fresh protected-storage check remains
//! with the caller. Entries convey no membership or authorization. Dropping the
//! Engine releases them; closing its storage alone does not promise erasure.
use super::{AccountIdentityProofRequest, SCHNORR_SIGNATURE_LEN, verify_proof_signature};
use cgka_traits::error::EngineError;
use std::collections::VecDeque;
use std::sync::Mutex;

const CAPACITY: usize = 128;
const MAX_MLS_KEY_BYTES: usize = 128;

struct PositiveProof {
    request: AccountIdentityProofRequest,
    signature: [u8; SCHNORR_SIGNATURE_LEN],
}

#[derive(Default)]
pub(crate) struct ProofSignatureMemo {
    entries: Mutex<VecDeque<PositiveProof>>,
    #[cfg(test)]
    cold_verifications: std::sync::atomic::AtomicUsize,
}

impl ProofSignatureMemo {
    pub(crate) fn verify(
        &self,
        request: &AccountIdentityProofRequest,
        signature: &[u8; SCHNORR_SIGNATURE_LEN],
    ) -> Result<(), EngineError> {
        // These are admission limits only. Unsupported shapes use the original
        // verifier with exactly its original success/error behavior.
        let admissible = request.account_identity.len() == 32
            && request.mls_signature_public_key.len() <= MAX_MLS_KEY_BYTES;
        if admissible
            && let Ok(entries) = self.entries.lock()
            && entries
                .iter()
                .any(|entry| entry.request == *request && entry.signature == *signature)
        {
            return Ok(());
        }
        // Neither verification nor any caller's storage work runs under this lock.
        #[cfg(test)]
        self.cold_verifications
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        verify_proof_signature(request, signature)?;
        if admissible
            && let Ok(mut entries) = self.entries.lock()
            && !entries
                .iter()
                .any(|entry| entry.request == *request && entry.signature == *signature)
        {
            if entries.len() == CAPACITY {
                entries.pop_front();
            }
            entries.push_back(PositiveProof {
                request: request.clone(),
                signature: *signature,
            });
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn cold_count(&self) -> usize {
        self.cold_verifications
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
#[path = "account_identity_proof_memo_tests.rs"]
mod tests;
