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
    // PROOF_DIAGNOSTIC_FIELD_BEGIN
    #[cfg(feature = "test-policy-overrides")]
    probe: crate::proof_memo_diagnostics::EngineProbe,
    // PROOF_DIAGNOSTIC_FIELD_END
    #[cfg(test)]
    cold_verifications: std::sync::atomic::AtomicUsize,
}

impl ProofSignatureMemo {
    pub(crate) fn verify(
        &self,
        request: &AccountIdentityProofRequest,
        signature: &[u8; SCHNORR_SIGNATURE_LEN],
    ) -> Result<(), EngineError> {
        // PROOF_DIAGNOSTIC_BEGIN
        #[cfg(feature = "test-policy-overrides")]
        self.probe.event(0);
        // PROOF_DIAGNOSTIC_END
        // These are admission limits only. Unsupported shapes use the original
        // verifier with exactly its original success/error behavior.
        let admissible = request.account_identity.len() == 32
            && request.mls_signature_public_key.len() <= MAX_MLS_KEY_BYTES;
        if admissible
            && let Ok(entries) = {
                // PROOF_DIAGNOSTIC_LOCK_BEGIN
                #[cfg(feature = "test-policy-overrides")]
                let result = crate::proof_memo_diagnostics::observe_lock(
                    self.entries.lock(),
                    &self.probe,
                    true,
                );
                #[cfg(not(feature = "test-policy-overrides"))]
                let result = self.entries.lock();
                // PROOF_DIAGNOSTIC_LOCK_END
                result
            }
            && entries
                .iter()
                .any(|entry| entry.request == *request && entry.signature == *signature)
        {
            // PROOF_DIAGNOSTIC_BEGIN
            #[cfg(feature = "test-policy-overrides")]
            {
                self.probe.event(1);
                self.probe.peak(entries.len());
            }
            // PROOF_DIAGNOSTIC_END
            return Ok(());
        }
        // Neither verification nor any caller's storage work runs under this lock.
        #[cfg(test)]
        self.cold_verifications
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // PROOF_DIAGNOSTIC_BEGIN
        #[cfg(feature = "test-policy-overrides")]
        if !admissible {
            self.probe.event(3);
        }
        #[cfg(feature = "test-policy-overrides")]
        let mut proof_diagnostic = self.probe.verifier();
        // PROOF_DIAGNOSTIC_END
        verify_proof_signature(request, signature)?;
        // PROOF_DIAGNOSTIC_BEGIN
        #[cfg(feature = "test-policy-overrides")]
        {
            proof_diagnostic.success();
            drop(proof_diagnostic);
        }
        // PROOF_DIAGNOSTIC_END

        if admissible
            && let Ok(mut entries) = {
                // PROOF_DIAGNOSTIC_LOCK_BEGIN
                #[cfg(feature = "test-policy-overrides")]
                let result = crate::proof_memo_diagnostics::observe_lock(
                    self.entries.lock(),
                    &self.probe,
                    false,
                );
                #[cfg(not(feature = "test-policy-overrides"))]
                let result = self.entries.lock();
                // PROOF_DIAGNOSTIC_LOCK_END
                result
            }
            && !entries
                .iter()
                .any(|entry| entry.request == *request && entry.signature == *signature)
        {
            if entries.len() == CAPACITY {
                entries.pop_front();
                // PROOF_DIAGNOSTIC_BEGIN
                #[cfg(feature = "test-policy-overrides")]
                self.probe.event(7);
                // PROOF_DIAGNOSTIC_END
            }
            entries.push_back(PositiveProof {
                request: request.clone(),
                signature: *signature,
            });
            // PROOF_DIAGNOSTIC_BEGIN
            #[cfg(feature = "test-policy-overrides")]
            {
                self.probe.event(6);
                self.probe.peak(entries.len());
            }
            // PROOF_DIAGNOSTIC_END
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
