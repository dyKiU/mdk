//! Default-off trusted-runtime join-policy injection, separate from MLS wire.
//! The runtime owns the real SDK token and original monotonic deadline. Storage
//! facts cannot construct a lease. A lease must serialize cancellation/generation
//! changes for the synchronous join transaction; no storage relocking or awaits.
use cgka_traits::accepted_welcome::AcceptedWelcomeReceipt;
pub use cgka_traits::device_linking_key_package::LinkingWelcomeDenied;
use cgka_traits::device_linking_key_package::PurposeKeyPackage;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::types::{EpochId, GroupId, MemberId};

/// A fully authenticated occupied leaf in the joined tree. No grant semantics.
pub struct AuthenticatedLinkingLeaf {
    pub leaf_index: u32,
    pub account: MemberId,
    pub signature_public_key: Vec<u8>,
}

/// Facts from the authenticated staged Welcome, before group installation.
/// No Debug or authorization constructor; these values are checked by the owner.
pub struct AuthenticatedLinkingWelcome {
    pub group_id: GroupId,
    pub own_account: MemberId,
    pub own_signature_public_key: Vec<u8>,
    pub own_leaf_index: u32,
    pub welcomer_account: MemberId,
    pub welcomer_signature_public_key: Vec<u8>,
    pub welcomer_leaf_index: u32,
    pub joined_epoch: EpochId,
    pub protocol_profile: ProtocolProfile,
    /// Derived from the authenticated required private component and payload.
    /// Metadata only; it cannot arm a lease or authorize joining.
    pub private_device_profile: bool,
    pub epoch_authenticator_digest: [u8; 32],
    pub leaves: Vec<AuthenticatedLinkingLeaf>,
}

/// Injected only by the trusted account runtime. No host/FFI approval boolean.
pub trait LinkingWelcomePolicy: Send + Sync {
    fn begin_join(
        &self,
        purpose: &PurposeKeyPackage,
    ) -> Result<Box<dyn LinkingWelcomeLease>, LinkingWelcomeDenied>;
}

/// Holds the opaque verification result while one exact join is attempted.
/// Drop after rollback may restore only the same still-live internal token.
/// Implementations must not call storage/network or await from these methods.
pub trait LinkingWelcomeLease: Send {
    /// Check every SDK-known transport binding under the original live lease.
    /// Post-preparation hashes are authenticated metadata, never consent.
    fn check_transport_context(
        &mut self,
        _context: &cgka_traits::peeler::PrivateLinkingWelcomeContext,
    ) -> Result<(), LinkingWelcomeDenied> {
        Err(LinkingWelcomeDenied::NoLiveVerifier)
    }
    /// Only after authenticated full-tree checks: canonical predecessor from
    /// this lease's internally verified SDK context. No stored/native grant.
    fn approved_predecessor(
        &mut self,
    ) -> Result<
        cgka_traits::accepted_device_group_anchor::DeviceGroupAnchorRoster,
        LinkingWelcomeDenied,
    > {
        Err(LinkingWelcomeDenied::NoLiveVerifier)
    }

    fn check_authenticated(
        &mut self,
        welcome: &AuthenticatedLinkingWelcome,
    ) -> Result<(), LinkingWelcomeDenied>;
    /// Last live original-deadline/context-generation check after SQL writes,
    /// immediately before commit. Cancellation never revives a prior token.
    fn check_live_before_commit(&mut self) -> Result<(), LinkingWelcomeDenied>;
    /// Infallible memory-only consumption after the SQL commit, never a grant.
    fn commit_accepted(self: Box<Self>, receipt: &AcceptedWelcomeReceipt);
}
