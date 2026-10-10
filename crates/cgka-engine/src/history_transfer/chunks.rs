//! Ordered framing under one original; trusted App import owns receipt semantics.
use super::*;
/// Conservative ceiling for complete signed frame + nested app event + MLS overhead.
pub const MAX_HISTORY_CHUNK_BYTES: usize = 2048;
pub const MAX_HISTORY_CHUNKS: u32 = 128;
pub struct OpenedHistoryChunk {
    pub ordinal: u32,
    pub body: Vec<u8>,
}
pub(super) struct SealedChunk {
    digest: [u8; 32],
    pub(super) wire: Vec<u8>,
}
impl OwnedHistoryChannel {
    fn chunk_binding(
        &self,
        manifest: &[u8; 32],
        ordinal: u32,
        receipt: bool,
    ) -> Result<[u8; 32], EngineError> {
        let mut h = Sha256::new();
        h.update(b"WN-history-original-ordered-v1");
        h.update(self.transcript()?);
        h.update(manifest);
        h.update(ordinal.to_be_bytes());
        h.update([u8::from(receipt)]);
        Ok(h.finalize().into())
    }
}
impl<S: StorageProvider> Engine<S> {
    /// Seal one immutable ordinal. A receipt is issued by the trusted original
    /// actor only after its committed logical import; this layer proves framing.
    pub fn seal_history_chunk(
        &self,
        channel: &mut OwnedHistoryChannel,
        manifest: [u8; 32],
        ordinal: u32,
        body: &[u8],
        receipt: bool,
    ) -> Result<Vec<u8>, EngineError> {
        self.history_channel_fresh(channel)?;
        if receipt != channel.recipient_role
            || manifest == [0; 32]
            || ordinal >= MAX_HISTORY_CHUNKS
            || body.len() > MAX_HISTORY_CHUNK_BYTES
            || channel.sealed.is_some()
            || channel
                .chunk_manifest
                .is_some_and(|actual| actual != manifest)
        {
            return Err(refused());
        }
        if let Some(snapshot) = &channel.scope.snapshot {
            let expected = snapshot
                .encoded_bytes
                .saturating_sub(ordinal * 1536)
                .min(1536) as usize;
            if manifest != snapshot.archive_digest
                || ordinal >= snapshot.fragment_count
                || (!receipt && body.len() != expected)
            {
                return Err(refused());
            }
        }
        let digest: [u8; 32] = Sha256::digest(body).into();
        if let Some(existing) = channel.sealed_chunks.get(ordinal as usize) {
            if existing.digest != digest {
                return Err(refused());
            }
            return Ok(existing.wire.clone());
        }
        if ordinal as usize != channel.sealed_chunks.len()
            || if receipt {
                channel.opened_chunks.len() <= ordinal as usize
            } else {
                channel.opened_chunks.len() != ordinal as usize
            }
        {
            return Err(refused());
        }
        let binding = channel.chunk_binding(&manifest, ordinal, receipt)?;
        let ciphertext = self
            .crypto
            .hpke_seal(
                config(),
                channel.peer_key.as_ref().ok_or_else(refused)?,
                HPKE_INFO,
                &binding,
                body,
            )
            .map_err(|_| refused())?;
        let mut frame =
            self.history_frame(&channel.scope, if receipt { "receipt" } else { "chunk" });
        frame.binding = binding;
        frame.manifest = manifest;
        frame.ordinal = ordinal;
        frame.kem = ciphertext.kem_output.as_slice().to_vec();
        frame.ciphertext = ciphertext.ciphertext.as_slice().to_vec();
        let wire = self.history_sign(frame)?;
        self.history_channel_fresh(channel)?;
        channel.chunk_manifest = Some(manifest);
        channel.sealed_chunks.push(SealedChunk {
            digest,
            wire: wire.clone(),
        });
        Ok(wire)
    }
    pub fn open_history_chunk(
        &self,
        channel: &mut OwnedHistoryChannel,
        wire: &[u8],
    ) -> Result<OpenedHistoryChunk, EngineError> {
        self.history_channel_fresh(channel)?;
        let frame = self.history_verify(decode(wire)?)?;
        Self::history_fixed_context(&frame, &channel.scope)?;
        let receipt = !channel.recipient_role;
        let original = decode(if channel.recipient_role {
            &channel.request
        } else {
            channel.consent.as_ref().ok_or_else(refused)?
        })?;
        let signer = if receipt {
            &channel.scope.recipient
        } else {
            &channel.scope.source
        };
        if frame.phase != if receipt { "receipt" } else { "chunk" }
            || &frame.signer != signer
            || frame.source_generation != original.source_generation
            || frame.manifest == [0; 32]
            || frame.ordinal >= MAX_HISTORY_CHUNKS
            || channel
                .chunk_manifest
                .is_some_and(|actual| actual != frame.manifest)
            || channel.sealed.is_some()
            || !frame.public_key.is_empty()
            || frame.kem.len() != 32
            || frame.ciphertext.len() > MAX_HISTORY_CHUNK_BYTES + 16
            || frame.binding != channel.chunk_binding(&frame.manifest, frame.ordinal, receipt)?
        {
            return Err(refused());
        }
        if let Some(snapshot) = &channel.scope.snapshot
            && (frame.manifest != snapshot.archive_digest
                || frame.ordinal >= snapshot.fragment_count)
        {
            return Err(refused());
        }
        let ordinal = frame.ordinal as usize;
        let digest: [u8; 32] = Sha256::digest(wire).into();
        if let Some(old) = channel.opened_chunks.get(ordinal) {
            if old != &digest {
                return Err(refused());
            }
        } else if ordinal != channel.opened_chunks.len()
            || if receipt {
                channel.sealed_chunks.len() <= ordinal
            } else {
                channel.sealed_chunks.len() != ordinal
            }
        {
            return Err(refused());
        }
        let ciphertext = HpkeCiphertext {
            kem_output: frame.kem.into(),
            ciphertext: frame.ciphertext.into(),
        };
        let body = self
            .crypto
            .hpke_open(
                config(),
                &ciphertext,
                &channel.keys.as_ref().ok_or_else(refused)?.private,
                HPKE_INFO,
                &frame.binding,
            )
            .map_err(|_| refused())?;
        if let Some(snapshot) = &channel.scope.snapshot {
            let expected = snapshot
                .encoded_bytes
                .saturating_sub(frame.ordinal * 1536)
                .min(1536) as usize;
            if !receipt && body.len() != expected {
                return Err(refused());
            }
        }
        if body.len() > MAX_HISTORY_CHUNK_BYTES {
            return Err(refused());
        }
        self.history_channel_fresh(channel)?;
        channel.chunk_manifest = Some(frame.manifest);
        if ordinal == channel.opened_chunks.len() {
            channel.opened_chunks.push(digest);
        }
        Ok(OpenedHistoryChunk {
            ordinal: frame.ordinal,
            body,
        })
    }
}
