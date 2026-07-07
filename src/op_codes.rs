//! INAP CS-1 operation codes (local operation values used in TCAP Invoke
//! components), ITU-T Q.1218 / ETSI EN 300 374-1.
//!
//! CAP (3GPP TS 29.078) was derived from INAP CS-2, which extends CS-1, so the
//! shared SSF-SCF call-control operations carry the **same** local codes here as
//! in the `gsm_cap` crate (initialDP = 0, connect = 20, …). The codes below are
//! the CS-1 SSF-SCF / SRF set.

/// Call establishment / triggering.
pub const INITIAL_DP: i64 = 0;
pub const ASSIST_REQUEST_INSTRUCTIONS: i64 = 16;
pub const ESTABLISH_TEMPORARY_CONNECTION: i64 = 17;
pub const DISCONNECT_FORWARD_CONNECTION: i64 = 18;
pub const CONNECT_TO_RESOURCE: i64 = 19;
pub const CONNECT: i64 = 20;
pub const RELEASE_CALL: i64 = 22;

/// Event / detection-point handling.
pub const REQUEST_REPORT_BCSM_EVENT: i64 = 23;
pub const EVENT_REPORT_BCSM: i64 = 24;
pub const COLLECT_INFORMATION: i64 = 27;
pub const CONTINUE: i64 = 31;
pub const RESET_TIMER: i64 = 33;

/// Charging.
pub const FURNISH_CHARGING_INFORMATION: i64 = 34;
pub const APPLY_CHARGING: i64 = 35;
pub const APPLY_CHARGING_REPORT: i64 = 36;

/// Call information (metering / duration reporting).
pub const CALL_INFORMATION_REPORT: i64 = 44;
pub const CALL_INFORMATION_REQUEST: i64 = 45;

/// Specialised resources (SRF).
pub const PLAY_ANNOUNCEMENT: i64 = 47;
pub const PROMPT_AND_COLLECT_USER_INFORMATION: i64 = 48;
pub const SPECIALIZED_RESOURCE_REPORT: i64 = 49;

/// Housekeeping.
pub const CANCEL: i64 = 53;
pub const ACTIVITY_TEST: i64 = 55;

/// The name of a well-known INAP CS-1 operation code, if any. Names match the
/// ASN.1 operation identifiers in ETSI EN 300 374-1 (as reported by the Wireshark
/// INAP dissector).
pub fn operation_name(code: i64) -> Option<&'static str> {
    Some(match code {
        INITIAL_DP => "initialDP",
        ASSIST_REQUEST_INSTRUCTIONS => "assistRequestInstructions",
        ESTABLISH_TEMPORARY_CONNECTION => "establishTemporaryConnection",
        DISCONNECT_FORWARD_CONNECTION => "disconnectForwardConnection",
        CONNECT_TO_RESOURCE => "connectToResource",
        CONNECT => "connect",
        RELEASE_CALL => "releaseCall",
        REQUEST_REPORT_BCSM_EVENT => "requestReportBCSMEvent",
        EVENT_REPORT_BCSM => "eventReportBCSM",
        COLLECT_INFORMATION => "collectInformation",
        CONTINUE => "continue",
        RESET_TIMER => "resetTimer",
        FURNISH_CHARGING_INFORMATION => "furnishChargingInformation",
        APPLY_CHARGING => "applyCharging",
        APPLY_CHARGING_REPORT => "applyChargingReport",
        CALL_INFORMATION_REPORT => "callInformationReport",
        CALL_INFORMATION_REQUEST => "callInformationRequest",
        PLAY_ANNOUNCEMENT => "playAnnouncement",
        PROMPT_AND_COLLECT_USER_INFORMATION => "promptAndCollectUserInformation",
        SPECIALIZED_RESOURCE_REPORT => "specializedResourceReport",
        CANCEL => "cancel",
        ACTIVITY_TEST => "activityTest",
        _ => return None,
    })
}
