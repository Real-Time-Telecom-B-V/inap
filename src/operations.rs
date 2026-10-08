//! INAP CS-1 operation arguments and results (ITU-T Q.1218 / ETSI EN 300 374-1).
//! Each type derives `rasn` BER `Encode`/`Decode`; a consumer wraps them in TCAP
//! components with the matching [operation code](crate::op_codes).
//!
//! A handful of CS-1 operations carry no argument (`continue`,
//! `disconnectForwardConnection`, `activityTest`) or a bare `NULL`
//! (`specializedResourceReport`); those have an [op code](crate::op_codes) but no
//! argument type here. The `collectInformation` argument is optional and its IE
//! layout is not modelled.
//!
//! ## Shared vs INAP-specific
//!
//! The user-interaction operations that are byte-identical between INAP and CAP
//! ([`ConnectToResourceArg`], [`PlayAnnouncementArg`],
//! [`PromptAndCollectUserInformationArg`] / [`PromptAndCollectUserInformationRes`])
//! are the canonical shared definitions (same names, fields and wire encoding a
//! CAP codec uses; `informationToSend` / `collectedInfo` are carried as opaque
//! octet strings). The call-establishment / charging / call-information
//! operations are INAP-flavoured (e.g. [`InitialDpArg`] carries the fixed-network
//! `iPAvailable` / `serviceInteractionIndicators` / `forwardCallIndicators` and no
//! mobile IEs).

use rasn::prelude::*;

use crate::types::*;

// ── Call establishment / triggering ──────────────────────────────────────────

/// InitialDP (op 0), SSF reports a triggered call to the SCF. Tags are from the
/// INAP CS-1 ASN.1 (fixed-network fields, no mobile IEs); fields ascend by tag.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InitialDpArg {
    #[rasn(tag(context, 0))]
    pub service_key: ServiceKey,
    #[rasn(tag(context, 2))]
    pub called_party_number: Option<CalledPartyNumber>,
    #[rasn(tag(context, 3))]
    pub calling_party_number: Option<CallingPartyNumber>,
    #[rasn(tag(context, 5))]
    pub calling_partys_category: Option<CallingPartysCategory>,
    #[rasn(tag(context, 8))]
    pub ip_ssp_capabilities: Option<IpsspCapabilities>,
    #[rasn(tag(context, 9))]
    pub ip_available: Option<IpAvailable>,
    #[rasn(tag(context, 10))]
    pub location_number: Option<LocationNumber>,
    #[rasn(tag(context, 12))]
    pub original_called_party_id: Option<OriginalCalledPartyId>,
    #[rasn(tag(context, 23))]
    pub high_layer_compatibility: Option<HighLayerCompatibility>,
    #[rasn(tag(context, 24))]
    pub service_interaction_indicators: Option<ServiceInteractionIndicators>,
    #[rasn(tag(context, 25))]
    pub additional_calling_party_number: Option<AdditionalCallingPartyNumber>,
    #[rasn(tag(context, 26))]
    pub forward_call_indicators: Option<ForwardCallIndicators>,
    #[rasn(tag(context, 28))]
    pub event_type_bcsm: Option<EventTypeBcsm>,
    #[rasn(tag(context, 29))]
    pub redirecting_party_id: Option<RedirectingPartyId>,
}

/// Connect (op 20), SCF instructs the SSF to route the call. `[0]
/// DestinationRoutingAddress` is a `SEQUENCE OF CalledPartyNumber`.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ConnectArg {
    #[rasn(tag(context, 0))]
    pub destination_routing_address: Vec<CalledPartyNumber>,
    #[rasn(tag(context, 2))]
    pub correlation_id: Option<CorrelationId>,
    #[rasn(tag(context, 6))]
    pub original_called_party_id: Option<OriginalCalledPartyId>,
    #[rasn(tag(context, 8))]
    pub scf_id: Option<ScfId>,
}

/// ReleaseCall (op 22), SCF instructs the SSF to release the call. In INAP CS-1
/// the argument is a bare `Cause` (Q.850), not a SEQUENCE.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct ReleaseCallArg(pub Cause);

/// ConnectToResource (op 19), SCF connects the call to a specialised resource.
/// `resourceAddress` is an inline CHOICE (`ipRoutingAddress [0]` or `none [3]`).
///
/// Canonical shared IN IE (byte-identical to the CAP definition).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ConnectToResourceArg {
    #[rasn(tag(context, 0))]
    pub resource_address_ipv4: Option<IpRoutingAddress>,
    #[rasn(tag(context, 3))]
    pub resource_address_none: Option<()>,
}

/// EstablishTemporaryConnection (op 17), SSF sets up a temporary connection to
/// an assisting SSF / IP.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct EstablishTemporaryConnectionArg {
    #[rasn(tag(context, 0))]
    pub assisting_ssp_ip_routing_address: AssistingSspIpRoutingAddress,
    #[rasn(tag(context, 1))]
    pub correlation_id: Option<CorrelationId>,
    #[rasn(tag(context, 3))]
    pub scf_id: Option<ScfId>,
}

/// AssistRequestInstructions (op 16), assisting SSF asks the SCF for
/// instructions, keyed by the `correlationID`.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AssistRequestInstructionsArg {
    #[rasn(tag(context, 0))]
    pub correlation_id: CorrelationId,
    #[rasn(tag(context, 2))]
    pub ip_ssp_capabilities: Option<IpsspCapabilities>,
}

// ── Event / detection-point handling ─────────────────────────────────────────

/// RequestReportBCSMEvent (op 23): the SCF arms detection points.
///
/// ```text
/// RequestReportBCSMEventArg ::= SEQUENCE {
///     bcsmEvents             [0] SEQUENCE SIZE (1..numOfBCSMEvents) OF BCSMEvent,
///     bcsmEventCorrelationID [1] CorrelationID OPTIONAL,   -- Q.1218 only
///     extensions             [2] SEQUENCE SIZE (1..numOfExtensions) OF
///                                    ExtensionField OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RequestReportBcsmEventArg {
    #[rasn(tag(context, 0))]
    pub bcsm_events: Vec<BcsmEvent>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 1))]
    pub bcsm_event_correlation_id: Option<CorrelationId>,
    #[rasn(tag(context, 2))]
    pub extensions: Option<Extensions>,
}

impl RequestReportBcsmEventArg {
    /// A request arming `bcsm_events`.
    pub fn new(bcsm_events: Vec<BcsmEvent>) -> Self {
        Self {
            bcsm_events,
            bcsm_event_correlation_id: None,
            extensions: None,
        }
    }
}

/// EventReportBCSM (op 24): the SSF reports an armed event.
///
/// ```text
/// EventReportBCSMArg ::= SEQUENCE {
///     eventTypeBCSM                [0] EventTypeBCSM,
///     bcsmEventCorrelationID       [1] CorrelationID OPTIONAL,   -- Q.1218 only
///     eventSpecificInformationBCSM [2] EventSpecificInformationBCSM OPTIONAL,
///                                                                -- CHOICE: explicit
///     legID                        [3] LegID OPTIONAL,           -- CHOICE: explicit
///     miscCallInfo                 [4] MiscCallInfo DEFAULT { messageType request },
///     extensions                   [5] SEQUENCE SIZE(1..numOfExtensions) OF
///                                          ExtensionField OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct EventReportBcsmArg {
    #[rasn(tag(context, 0))]
    pub event_type_bcsm: EventTypeBcsm,
    /// *Q.1218 only.*
    #[rasn(tag(context, 1))]
    pub bcsm_event_correlation_id: Option<CorrelationId>,
    #[rasn(tag(explicit(context, 2)))]
    pub event_specific_information_bcsm: Option<EventSpecificInformationBcsm>,
    #[rasn(tag(explicit(context, 3)))]
    pub leg_id: Option<LegId>,
    /// `DEFAULT { messageType request }`.
    #[rasn(tag(context, 4))]
    pub misc_call_info: Option<MiscCallInfo>,
    #[rasn(tag(context, 5))]
    pub extensions: Option<Extensions>,
}

impl EventReportBcsmArg {
    /// A report of `event_type_bcsm` with every optional member absent.
    pub fn new(event_type_bcsm: EventTypeBcsm) -> Self {
        Self {
            event_type_bcsm,
            bcsm_event_correlation_id: None,
            event_specific_information_bcsm: None,
            leg_id: None,
            misc_call_info: None,
            extensions: None,
        }
    }
}

/// ResetTimer (op 33), SCF restarts an SSF application timer (Tssf).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ResetTimerArg {
    #[rasn(tag(context, 0))]
    pub timer_id: Option<Integer>,
    #[rasn(tag(context, 1))]
    pub timer_value: Integer,
}

/// Cancel (op 53), SCF cancels an outstanding request. In CS-1 the CHOICE is
/// `invokeID [0]` or `allRequests [1]`.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum CancelArg {
    #[rasn(tag(context, 0))]
    InvokeId(Integer),
    #[rasn(tag(context, 1))]
    AllRequests(()),
}

// ── Charging ─────────────────────────────────────────────────────────────────

/// ApplyCharging (op 35), SCF installs charging characteristics at the SSF.
/// `partyToCharge` is a `SendingSideID` (a leg identity), EXPLICITly tagged.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ApplyChargingArg {
    #[rasn(tag(context, 0))]
    pub ach_billing_charging_characteristics: OctetString,
    #[rasn(tag(explicit(context, 2)))]
    pub party_to_charge: Option<LegId>,
}

/// ApplyChargingReport (op 36), SSF returns the metered call result. The
/// argument is a bare `CallResult` (OCTET STRING).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct ApplyChargingReportArg(pub OctetString);

/// FurnishChargingInformation (op 34), SCF supplies charging data to add to the
/// SSF call record. The argument is a bare
/// `FCIBillingChargingCharacteristics` (OCTET STRING).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct FurnishChargingInformationArg(pub OctetString);

// ── Call information (metering / duration reporting) ─────────────────────────

/// CallInformationRequest (op 45), SCF asks the SSF to record and later report
/// a set of call-information items.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CallInformationRequestArg {
    #[rasn(tag(context, 0))]
    pub requested_information_type_list: Vec<RequestedInformationType>,
    /// `legID` is a CHOICE, hence EXPLICIT tagging.
    #[rasn(tag(explicit(context, 3)))]
    pub leg_id: Option<LegId>,
}

/// CallInformationReport (op 44), SSF returns the previously requested
/// call-information items.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CallInformationReportArg {
    #[rasn(tag(context, 0))]
    pub requested_information_list: Vec<RequestedInformation>,
    /// `legID` is a CHOICE, hence EXPLICIT tagging.
    #[rasn(tag(explicit(context, 3)))]
    pub leg_id: Option<LegId>,
}

// ── Specialised resources (SRF) ──────────────────────────────────────────────

/// PlayAnnouncement (op 47), SCF/SRF plays an announcement or tone.
/// `informationToSend` is carried as an opaque octet string.
///
/// Canonical shared IN IE (byte-identical to the CAP definition).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PlayAnnouncementArg {
    #[rasn(tag(context, 0))]
    pub information_to_send: OctetString,
    #[rasn(tag(context, 1))]
    pub disconnect_from_ip_forbidden: Option<bool>,
    #[rasn(tag(context, 2))]
    pub request_announcement_complete: Option<bool>,
}

/// PromptAndCollectUserInformation (op 48) argument, collect digits from the
/// user, optionally after playing a prompt. `collectedInfo` / `informationToSend`
/// are carried as opaque octet strings.
///
/// Canonical shared IN IE (byte-identical to the CAP definition).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PromptAndCollectUserInformationArg {
    #[rasn(tag(context, 0))]
    pub collected_info: OctetString,
    #[rasn(tag(context, 1))]
    pub disconnect_from_ip_forbidden: Option<bool>,
    #[rasn(tag(context, 2))]
    pub information_to_send: Option<OctetString>,
}

/// PromptAndCollectUserInformation (op 48) result, the collected digits.
///
/// Canonical shared IN IE (byte-identical to the CAP definition).
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum PromptAndCollectUserInformationRes {
    #[rasn(tag(context, 0))]
    DigitsResponse(OctetString),
}
