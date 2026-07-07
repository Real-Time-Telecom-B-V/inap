//! Common INAP CS-1 types (ITU-T Q.1218 / ETSI EN 300 374-1). Addresses and
//! digit strings are carried as `OCTET STRING`s in their respective ITU-T wire
//! formats (Q.763 / Q.931).
//!
//! ## Shared IN leaf IEs (canonical home)
//!
//! CAP (3GPP TS 29.078) was derived from INAP CS-2, which extends CS-1, so a
//! family of leaf IEs is byte-identical between INAP and CAP. Those live **here**
//! as the canonical definitions ([`EventTypeBcsm`], [`MonitorMode`],
//! [`BcsmEvent`], and the address / `Cause` / `MiscCallInfo` aliases), with the
//! same Rust names, fields and wire encoding a CAP codec uses, so a sibling crate
//! can re-export them rather than duplicate them.

use rasn::prelude::*;

/// Identifies the IN service logic at the SCF.
pub type ServiceKey = Integer;
/// Called party number, Q.763 format.
pub type CalledPartyNumber = OctetString;
/// Calling party number, Q.763 format.
pub type CallingPartyNumber = OctetString;
/// Calling party's category, Q.763 format (single octet).
pub type CallingPartysCategory = OctetString;
/// Location number, Q.763 format.
pub type LocationNumber = OctetString;
/// Original called party ID, Q.763 format.
pub type OriginalCalledPartyId = OctetString;
/// Redirecting party ID, Q.763 format.
pub type RedirectingPartyId = OctetString;
/// Redirection information, Q.763 format.
pub type RedirectionInformation = OctetString;
/// Q.850 cause value.
pub type Cause = OctetString;
/// Miscellaneous call info accompanying an event report (opaque octet string).
pub type MiscCallInfo = OctetString;

/// Correlates an assisting/temporary connection with its originating dialogue.
pub type CorrelationId = OctetString;
/// Additional calling party number, Q.763 format.
pub type AdditionalCallingPartyNumber = OctetString;
/// High-layer compatibility, Q.931 format.
pub type HighLayerCompatibility = OctetString;
/// IN-switching-point capabilities, an opaque octet string.
pub type IpsspCapabilities = OctetString;
/// Whether an IP (specialised resource) is available at the SSP.
pub type IpAvailable = OctetString;
/// Service interaction indicators, an opaque octet string.
pub type ServiceInteractionIndicators = OctetString;
/// Forward call indicators, Q.763 format.
pub type ForwardCallIndicators = OctetString;
/// IP routing address (SRF/assist), Q.763 called-party format.
pub type IpRoutingAddress = OctetString;
/// Assisting-SSP IP routing address, Q.763 called-party format.
pub type AssistingSspIpRoutingAddress = OctetString;
/// SCF identifier, an opaque octet string.
pub type ScfId = OctetString;
/// Generic digit string (Q.763 address signals in a BCD/IA5 envelope).
pub type Digits = OctetString;

/// EventTypeBCSM, Basic Call State Model detection-point events.
///
/// Canonical shared IN IE (byte-identical to the CAP definition).
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum EventTypeBcsm {
    CollectedInfo = 2,
    AnalysedInformation = 3,
    RouteSelectFailure = 4,
    OCalledPartyBusy = 5,
    ONoAnswer = 6,
    OAnswer = 7,
    ODisconnect = 9,
    OAbandon = 10,
    TermAttemptAuthorized = 12,
    TBusy = 13,
    TNoAnswer = 14,
    TAnswer = 15,
    TDisconnect = 17,
    TAbandon = 18,
}

/// MonitorMode, how a detection point should be reported.
///
/// Canonical shared IN IE (byte-identical to the CAP definition).
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum MonitorMode {
    Interrupted = 0,
    NotifyAndContinue = 1,
    Transparent = 2,
}

/// BCSMEvent, one event detection-point configuration entry.
///
/// Canonical shared IN IE (byte-identical to the CAP definition): `leg_id` is an
/// opaque `[2]` octet string.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct BcsmEvent {
    #[rasn(tag(context, 0))]
    pub event_type_bcsm: EventTypeBcsm,
    #[rasn(tag(context, 1))]
    pub monitor_mode: MonitorMode,
    #[rasn(tag(context, 2))]
    pub leg_id: Option<OctetString>,
}

/// LegID, identifies a party (call leg). A CHOICE, so it is EXPLICITly tagged
/// where it appears as a field. `LegType` is a single-octet OCTET STRING. Used by
/// the INAP charging / call-information operations.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum LegId {
    #[rasn(tag(context, 0))]
    SendingSideId(OctetString),
    #[rasn(tag(context, 1))]
    ReceivingSideId(OctetString),
}

/// RequestedInformationType, the metering item asked for / reported in the
/// call-information operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum RequestedInformationType {
    CallAttemptElapsedTime = 0,
    CallStopTime = 1,
    CallConnectedElapsedTime = 2,
    ReleaseCause = 30,
}

/// RequestedInformationValue, the value carried in a `CallInformationReport`
/// for one metering item. A CHOICE keyed by the item type.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum RequestedInformationValue {
    #[rasn(tag(context, 0))]
    CallAttemptElapsedTimeValue(Integer),
    #[rasn(tag(context, 1))]
    CallStopTimeValue(OctetString),
    #[rasn(tag(context, 2))]
    CallConnectedElapsedTimeValue(Integer),
    #[rasn(tag(context, 30))]
    ReleaseCauseValue(Cause),
}

/// RequestedInformation, one (type, value) metering pair.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RequestedInformation {
    #[rasn(tag(context, 0))]
    pub requested_information_type: RequestedInformationType,
    /// The value is a CHOICE, hence EXPLICIT tagging.
    #[rasn(tag(explicit(context, 1)))]
    pub requested_information_value: RequestedInformationValue,
}
