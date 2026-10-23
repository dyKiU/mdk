use crate::macros::{c_enum, c_mirror};
use marmot_uniffi::conversions::*;

c_enum! { MarmotAccountChatDepartureStatus from AccountChatDepartureStatusFfi { Available, Pending, NeedsAdministrator, Completed, Unavailable } }
c_enum! { MarmotAccountChatDepartureReason from AccountChatDepartureReasonFfi { None, AwaitingSources, AwaitingAdministrator, SharingUnavailable, NoAcceptedChat } }
c_mirror! { MarmotAccountChatDepartureState from AccountChatDepartureStateFfi, free marmot_account_chat_departure_state_free {
    copy status: MarmotAccountChatDepartureStatus,
    copy reason: MarmotAccountChatDepartureReason,
    opt_str operation_id,
} }
