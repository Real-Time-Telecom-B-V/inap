//! INAP CS-1 operation arguments and results.
//!
//! Each type here is the argument (or result) of one operation; a consumer
//! puts its encoding in a TCAP component with the matching
//! [operation code](crate::op_codes).
//!
//! # What these are checked against
//!
//! * **ETS 300 374-1, September 1994** (ETSI Core INAP CS-1), clause 6.3,
//!   module `Core-INAP-CS1-DataTypes`: the baseline. A member with no remark
//!   is in this document.
//! * **ITU-T Q.1218 (10/95)**, clause 2.1.3, module `IN-CS-1-Datatypes`:
//!   members marked *Q.1218 only* exist there and not in ETS 300 374-1. They
//!   are modelled so that a message from a Q.1218 entity decodes; an ETSI Core
//!   INAP entity does not send them.
//! * `legID [3]` in the two call information arguments is in neither. It is a
//!   capability set 2 member (EN 301 140-1 V1.3.4 / Q.1228) that this crate
//!   has carried since 1.0.0; it is marked *CS-2*.
//!
//! The ASN.1 of each argument is quoted in its documentation with the union
//! of the two documents. Members whose type is a CHOICE are EXPLICITly tagged
//! although the modules are `IMPLICIT TAGS` (X.680 31.2.7).
//!
//! Operations with no argument (`continue`, `disconnectForwardConnection`,
//! `activityTest`) and `specializedResourceReport`, whose argument is a bare
//! NULL (`05 00`), have an operation code and no type here. The argument of
//! `collectInformation` is not modelled.

use rasn::prelude::*;

use crate::types::{
    AChBillingChargingCharacteristics, AdditionalCallingPartyNumber, AlertingPattern,
    AssistingSspIpRoutingAddress, BcsmEvent, BearerCapability, CallResult, CalledPartyNumber,
    CallingPartyBusinessGroupId, CallingPartyNumber, CallingPartySubaddress, CallingPartysCategory,
    Carrier, Cause, CgEncountered, CollectedInfo, CorrelationId, Digits,
    EventSpecificInformationBcsm, EventTypeBcsm, Extensions, FciBillingChargingCharacteristics,
    ForwardCallIndicators, ForwardingCondition, HighLayerCompatibility, InformationToSend,
    IpAvailable, IpsspCapabilities, IsdnAccessRelatedInformation, LegId, LocationNumber,
    MiscCallInfo, OriginalCalledPartyId, RedirectingPartyId, RedirectionInformation,
    RequestedInformation, RequestedInformationType, ResourceAddress, RouteList, ScfId,
    ServiceInteractionIndicators, ServiceKey, ServiceProfileIdentifier, TerminalType, TimerId,
    TravellingClassMark, TriggerType,
};

// ── Call establishment / triggering ─────────────────────────────────────────

/// InitialDP (op 0): the SSF reports a triggered call to the SCF.
///
/// ```text
/// InitialDPArg ::= SEQUENCE {
///     serviceKey                   [0]  ServiceKey,
///     dialledDigits                [1]  CalledPartyNumber OPTIONAL,            -- Q.1218 only
///     calledPartyNumber            [2]  CalledPartyNumber OPTIONAL,
///     callingPartyNumber           [3]  CallingPartyNumber OPTIONAL,
///     callingPartyBusinessGroupID  [4]  CallingPartyBusinessGroupID OPTIONAL,  -- Q.1218 only
///     callingPartysCategory        [5]  CallingPartysCategory OPTIONAL,
///     callingPartySubaddress       [6]  CallingPartySubaddress OPTIONAL,       -- Q.1218 only
///     cGEncountered                [7]  CGEncountered OPTIONAL,
///     iPSSPCapabilities            [8]  IPSSPCapabilities OPTIONAL,
///     iPAvailable                  [9]  IPAvailable OPTIONAL,
///     locationNumber               [10] LocationNumber OPTIONAL,
///     miscCallInfo                 [11] MiscCallInfo OPTIONAL,                 -- Q.1218 only
///     originalCalledPartyID        [12] OriginalCalledPartyID OPTIONAL,
///     serviceProfileIdentifier     [13] ServiceProfileIdentifier OPTIONAL,     -- Q.1218 only
///     terminalType                 [14] TerminalType OPTIONAL,                 -- Q.1218 only
///     extensions                   [15] SEQUENCE SIZE(1..numOfExtensions) OF
///                                           ExtensionField OPTIONAL,
///     triggerType                  [16] TriggerType OPTIONAL,                  -- Q.1218 only
///     highLayerCompatibility       [23] HighLayerCompatibility OPTIONAL,
///     serviceInteractionIndicators [24] ServiceInteractionIndicators OPTIONAL,
///     additionalCallingPartyNumber [25] AdditionalCallingPartyNumber OPTIONAL,
///     forwardCallIndicators        [26] ForwardCallIndicators OPTIONAL,
///     bearerCapability             [27] BearerCapability OPTIONAL,             -- CHOICE: explicit
///     eventTypeBCSM                [28] EventTypeBCSM OPTIONAL,
///     redirectingPartyID           [29] RedirectingPartyID OPTIONAL,
///     redirectionInformation       [30] RedirectionInformation OPTIONAL }
/// ```
///
/// ETS 300 374-1 requires an SCF to recognise and ignore six of the Q.1218
/// only members (`dialledDigits`, `callingPartyBusinessGroupID`,
/// `callingPartySubaddress`, `miscCallInfo`, `serviceProfileIdentifier`,
/// `terminalType`) and forbids an SSF to send them.
///
/// `serviceKey` is mandatory as in ETS 300 374-1. Q.1218 makes it OPTIONAL; an
/// InitialDP without it is refused.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InitialDpArg {
    #[rasn(tag(context, 0))]
    pub service_key: ServiceKey,
    /// *Q.1218 only.*
    #[rasn(tag(context, 1))]
    pub dialled_digits: Option<CalledPartyNumber>,
    #[rasn(tag(context, 2))]
    pub called_party_number: Option<CalledPartyNumber>,
    #[rasn(tag(context, 3))]
    pub calling_party_number: Option<CallingPartyNumber>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 4))]
    pub calling_party_business_group_id: Option<CallingPartyBusinessGroupId>,
    #[rasn(tag(context, 5))]
    pub calling_partys_category: Option<CallingPartysCategory>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 6))]
    pub calling_party_subaddress: Option<CallingPartySubaddress>,
    #[rasn(tag(context, 7))]
    pub cg_encountered: Option<CgEncountered>,
    #[rasn(tag(context, 8))]
    pub ip_ssp_capabilities: Option<IpsspCapabilities>,
    #[rasn(tag(context, 9))]
    pub ip_available: Option<IpAvailable>,
    #[rasn(tag(context, 10))]
    pub location_number: Option<LocationNumber>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 11))]
    pub misc_call_info: Option<MiscCallInfo>,
    #[rasn(tag(context, 12))]
    pub original_called_party_id: Option<OriginalCalledPartyId>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 13))]
    pub service_profile_identifier: Option<ServiceProfileIdentifier>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 14))]
    pub terminal_type: Option<TerminalType>,
    #[rasn(tag(context, 15))]
    pub extensions: Option<Extensions>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 16))]
    pub trigger_type: Option<TriggerType>,
    #[rasn(tag(context, 23))]
    pub high_layer_compatibility: Option<HighLayerCompatibility>,
    #[rasn(tag(context, 24))]
    pub service_interaction_indicators: Option<ServiceInteractionIndicators>,
    #[rasn(tag(context, 25))]
    pub additional_calling_party_number: Option<AdditionalCallingPartyNumber>,
    #[rasn(tag(context, 26))]
    pub forward_call_indicators: Option<ForwardCallIndicators>,
    #[rasn(tag(explicit(context, 27)))]
    pub bearer_capability: Option<BearerCapability>,
    #[rasn(tag(context, 28))]
    pub event_type_bcsm: Option<EventTypeBcsm>,
    #[rasn(tag(context, 29))]
    pub redirecting_party_id: Option<RedirectingPartyId>,
    #[rasn(tag(context, 30))]
    pub redirection_information: Option<RedirectionInformation>,
}

impl InitialDpArg {
    /// An InitialDP with only the service key.
    pub fn new(service_key: impl Into<ServiceKey>) -> Self {
        Self {
            service_key: service_key.into(),
            dialled_digits: None,
            called_party_number: None,
            calling_party_number: None,
            calling_party_business_group_id: None,
            calling_partys_category: None,
            calling_party_subaddress: None,
            cg_encountered: None,
            ip_ssp_capabilities: None,
            ip_available: None,
            location_number: None,
            misc_call_info: None,
            original_called_party_id: None,
            service_profile_identifier: None,
            terminal_type: None,
            extensions: None,
            trigger_type: None,
            high_layer_compatibility: None,
            service_interaction_indicators: None,
            additional_calling_party_number: None,
            forward_call_indicators: None,
            bearer_capability: None,
            event_type_bcsm: None,
            redirecting_party_id: None,
            redirection_information: None,
        }
    }
}

/// Connect (op 20): the SCF has the SSF route the call.
///
/// ```text
/// ConnectArg ::= SEQUENCE {
///     destinationRoutingAddress    [0]  DestinationRoutingAddress,
///     alertingPattern              [1]  AlertingPattern OPTIONAL,
///     correlationID                [2]  CorrelationID OPTIONAL,
///     cutAndPaste                  [3]  CutAndPaste OPTIONAL,                   -- INTEGER (0..22)
///     forwardingCondition          [4]  ForwardingCondition OPTIONAL,           -- Q.1218 only
///     iSDNAccessRelatedInformation [5]  ISDNAccessRelatedInformation OPTIONAL,  -- Q.1218 only
///     originalCalledPartyID        [6]  OriginalCalledPartyID OPTIONAL,
///     routeList                    [7]  RouteList OPTIONAL,
///     scfID                        [8]  ScfID OPTIONAL,
///     travellingClassMark          [9]  TravellingClassMark OPTIONAL,           -- Q.1218 only
///     extensions                   [10] SEQUENCE SIZE(1..numOfExtensions) OF
///                                           ExtensionField OPTIONAL,
///     carrier                      [11] Carrier OPTIONAL,                       -- Q.1218 only
///     serviceInteractionIndicators [26] ServiceInteractionIndicators OPTIONAL,
///     callingPartyNumber           [27] CallingPartyNumber OPTIONAL,
///     callingPartysCategory        [28] CallingPartysCategory OPTIONAL,
///     redirectingPartyID           [29] RedirectingPartyID OPTIONAL,
///     redirectionInformation       [30] RedirectionInformation OPTIONAL }
///
/// DestinationRoutingAddress ::= SEQUENCE SIZE (1) OF CalledPartyNumber
/// ```
///
/// Q.1218 allows one to three destination routing addresses, ETS 300 374-1
/// exactly one.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ConnectArg {
    #[rasn(tag(context, 0))]
    pub destination_routing_address: Vec<CalledPartyNumber>,
    #[rasn(tag(context, 1))]
    pub alerting_pattern: Option<AlertingPattern>,
    #[rasn(tag(context, 2))]
    pub correlation_id: Option<CorrelationId>,
    #[rasn(tag(context, 3))]
    pub cut_and_paste: Option<u8>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 4))]
    pub forwarding_condition: Option<ForwardingCondition>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 5))]
    pub isdn_access_related_information: Option<IsdnAccessRelatedInformation>,
    #[rasn(tag(context, 6))]
    pub original_called_party_id: Option<OriginalCalledPartyId>,
    #[rasn(tag(context, 7))]
    pub route_list: Option<RouteList>,
    #[rasn(tag(context, 8))]
    pub scf_id: Option<ScfId>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 9))]
    pub travelling_class_mark: Option<TravellingClassMark>,
    #[rasn(tag(context, 10))]
    pub extensions: Option<Extensions>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 11))]
    pub carrier: Option<Carrier>,
    #[rasn(tag(context, 26))]
    pub service_interaction_indicators: Option<ServiceInteractionIndicators>,
    #[rasn(tag(context, 27))]
    pub calling_party_number: Option<CallingPartyNumber>,
    #[rasn(tag(context, 28))]
    pub calling_partys_category: Option<CallingPartysCategory>,
    #[rasn(tag(context, 29))]
    pub redirecting_party_id: Option<RedirectingPartyId>,
    #[rasn(tag(context, 30))]
    pub redirection_information: Option<RedirectionInformation>,
}

impl ConnectArg {
    /// A Connect to one destination with every optional member absent.
    pub fn new(destination: CalledPartyNumber) -> Self {
        Self {
            destination_routing_address: vec![destination],
            alerting_pattern: None,
            correlation_id: None,
            cut_and_paste: None,
            forwarding_condition: None,
            isdn_access_related_information: None,
            original_called_party_id: None,
            route_list: None,
            scf_id: None,
            travelling_class_mark: None,
            extensions: None,
            carrier: None,
            service_interaction_indicators: None,
            calling_party_number: None,
            calling_partys_category: None,
            redirecting_party_id: None,
            redirection_information: None,
        }
    }
}

/// ReleaseCall (op 22): the SCF has the SSF release the call.
///
/// `ReleaseCallArg ::= Cause`: a bare OCTET STRING, not a SEQUENCE.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct ReleaseCallArg(pub Cause);

/// ConnectToResource (op 19): the SCF connects the call to a specialised
/// resource.
///
/// ```text
/// ConnectToResourceArg ::= SEQUENCE {
///     resourceAddress CHOICE { ... },           -- untagged, see ResourceAddress
///     extensions                   [4]  SEQUENCE SIZE(1..numOfExtensions) OF
///                                           ExtensionField OPTIONAL,
///     serviceInteractionIndicators [30] ServiceInteractionIndicators OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ConnectToResourceArg {
    pub resource_address: ResourceAddress,
    #[rasn(tag(context, 4))]
    pub extensions: Option<Extensions>,
    #[rasn(tag(context, 30))]
    pub service_interaction_indicators: Option<ServiceInteractionIndicators>,
}

impl ConnectToResourceArg {
    /// A ConnectToResource to `resource_address` with every optional member
    /// absent.
    pub fn new(resource_address: ResourceAddress) -> Self {
        Self {
            resource_address,
            extensions: None,
            service_interaction_indicators: None,
        }
    }
}

/// EstablishTemporaryConnection (op 17): the SCF has the SSF set up a
/// connection to an assisting SSF or an intelligent peripheral.
///
/// ```text
/// EstablishTemporaryConnectionArg ::= SEQUENCE {
///     assistingSSPIPRoutingAddress [0]  AssistingSSPIPRoutingAddress,
///     correlationID                [1]  CorrelationID OPTIONAL,
///     legID                        [2]  LegID OPTIONAL,     -- Q.1218 only; CHOICE: explicit
///     scfID                        [3]  ScfID OPTIONAL,
///     extensions                   [4]  SEQUENCE SIZE(1..numOfExtensions) OF
///                                           ExtensionField OPTIONAL,
///     carrier                      [5]  Carrier OPTIONAL,   -- Q.1218 only
///     serviceInteractionIndicators [30] ServiceInteractionIndicators OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct EstablishTemporaryConnectionArg {
    #[rasn(tag(context, 0))]
    pub assisting_ssp_ip_routing_address: AssistingSspIpRoutingAddress,
    #[rasn(tag(context, 1))]
    pub correlation_id: Option<CorrelationId>,
    /// *Q.1218 only.*
    #[rasn(tag(explicit(context, 2)))]
    pub leg_id: Option<LegId>,
    #[rasn(tag(context, 3))]
    pub scf_id: Option<ScfId>,
    #[rasn(tag(context, 4))]
    pub extensions: Option<Extensions>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 5))]
    pub carrier: Option<Carrier>,
    #[rasn(tag(context, 30))]
    pub service_interaction_indicators: Option<ServiceInteractionIndicators>,
}

impl EstablishTemporaryConnectionArg {
    /// A temporary connection to `address` with every optional member absent.
    pub fn new(assisting_ssp_ip_routing_address: AssistingSspIpRoutingAddress) -> Self {
        Self {
            assisting_ssp_ip_routing_address,
            correlation_id: None,
            leg_id: None,
            scf_id: None,
            extensions: None,
            carrier: None,
            service_interaction_indicators: None,
        }
    }
}

/// AssistRequestInstructions (op 16): the assisting SSF or the intelligent
/// peripheral asks the SCF for instructions.
///
/// ```text
/// AssistRequestInstructionsArg ::= SEQUENCE {
///     correlationID     [0] CorrelationID,
///     iPAvailable       [1] IPAvailable OPTIONAL,
///     iPSSPCapabilities [2] IPSSPCapabilities OPTIONAL,
///     extensions        [3] SEQUENCE SIZE(1..numOfExtensions) OF
///                               ExtensionField OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct AssistRequestInstructionsArg {
    #[rasn(tag(context, 0))]
    pub correlation_id: CorrelationId,
    #[rasn(tag(context, 1))]
    pub ip_available: Option<IpAvailable>,
    #[rasn(tag(context, 2))]
    pub ip_ssp_capabilities: Option<IpsspCapabilities>,
    #[rasn(tag(context, 3))]
    pub extensions: Option<Extensions>,
}

impl AssistRequestInstructionsArg {
    /// A request carrying only the correlation identifier.
    pub fn new(correlation_id: CorrelationId) -> Self {
        Self {
            correlation_id,
            ip_available: None,
            ip_ssp_capabilities: None,
            extensions: None,
        }
    }
}

// ── Event / detection point handling ────────────────────────────────────────

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

/// ResetTimer (op 33): the SCF restarts a timer in the SSF.
///
/// ```text
/// ResetTimerArg ::= SEQUENCE {
///     timerID    [0] TimerID DEFAULT tssf,
///     timervalue [1] TimerValue,                -- Integer4, seconds
///     extensions [2] SEQUENCE SIZE(1..numOfExtensions) OF
///                        ExtensionField OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ResetTimerArg {
    /// `DEFAULT tssf`.
    #[rasn(tag(context, 0))]
    pub timer_id: Option<TimerId>,
    #[rasn(tag(context, 1))]
    pub timer_value: Integer,
    #[rasn(tag(context, 2))]
    pub extensions: Option<Extensions>,
}

impl ResetTimerArg {
    /// Reset the default timer (Tssf) to `seconds`.
    pub fn new(seconds: impl Into<Integer>) -> Self {
        Self {
            timer_id: None,
            timer_value: seconds.into(),
            extensions: None,
        }
    }
}

/// Cancel (op 53): the SCF cancels an outstanding request.
///
/// ```text
/// CancelArg ::= CHOICE {
///     invokeID    [0] InvokeID,
///     allRequests [1] NULL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum CancelArg {
    #[rasn(tag(context, 0))]
    InvokeId(Integer),
    #[rasn(tag(context, 1))]
    AllRequests(()),
}

// ── Charging ────────────────────────────────────────────────────────────────

/// ApplyCharging (op 35): the SCF gives the SSF charging instructions.
///
/// ```text
/// ApplyChargingArg ::= SEQUENCE {
///     aChBillingChargingCharacteristics [0] AChBillingChargingCharacteristics,
///     sendCalculationToSCPIndication    [1] BOOLEAN DEFAULT FALSE,   -- ETS 300 374-1 only
///     partyToCharge                     [2] LegID OPTIONAL,          -- CHOICE: explicit
///     extensions                        [3] SEQUENCE SIZE(1..numOfExtensions) OF
///                                               ExtensionField OPTIONAL }
/// ```
///
/// ETS 300 374-1 says `sendCalculationToSCPIndication` shall always be set to
/// TRUE. Q.1218 does not have the member.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ApplyChargingArg {
    #[rasn(tag(context, 0))]
    pub ach_billing_charging_characteristics: AChBillingChargingCharacteristics,
    /// `DEFAULT FALSE`. *ETS 300 374-1 only.*
    #[rasn(tag(context, 1))]
    pub send_calculation_to_scp_indication: Option<bool>,
    #[rasn(tag(explicit(context, 2)))]
    pub party_to_charge: Option<LegId>,
    #[rasn(tag(context, 3))]
    pub extensions: Option<Extensions>,
}

impl ApplyChargingArg {
    /// Charging instructions with every optional member absent.
    pub fn new(ach_billing_charging_characteristics: AChBillingChargingCharacteristics) -> Self {
        Self {
            ach_billing_charging_characteristics,
            send_calculation_to_scp_indication: None,
            party_to_charge: None,
            extensions: None,
        }
    }
}

/// ApplyChargingReport (op 36): the SSF returns the charging result.
///
/// `ApplyChargingReportArg ::= CallResult`: a bare OCTET STRING.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct ApplyChargingReportArg(pub CallResult);

/// FurnishChargingInformation (op 34): the SCF gives the SSF information for
/// the call record.
///
/// `FurnishChargingInformationArg ::= FCIBillingChargingCharacteristics`: a
/// bare OCTET STRING.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(delegate)]
pub struct FurnishChargingInformationArg(pub FciBillingChargingCharacteristics);

// ── Call information ────────────────────────────────────────────────────────

/// CallInformationRequest (op 45): the SCF asks the SSF to record call
/// information.
///
/// ```text
/// CallInformationRequestArg ::= SEQUENCE {
///     requestedInformationTypeList [0] RequestedInformationTypeList,
///     correlationID                [1] CorrelationID OPTIONAL,   -- Q.1218 only
///     extensions                   [2] SEQUENCE SIZE(1..numOfExtensions) OF
///                                          ExtensionField OPTIONAL,
///     legID                        [3] LegID OPTIONAL }          -- CS-2; CHOICE: explicit
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CallInformationRequestArg {
    #[rasn(tag(context, 0))]
    pub requested_information_type_list: Vec<RequestedInformationType>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 1))]
    pub correlation_id: Option<CorrelationId>,
    #[rasn(tag(context, 2))]
    pub extensions: Option<Extensions>,
    /// *CS-2* (EN 301 140-1 / Q.1228). Not a CS-1 member: leave it absent
    /// towards a CS-1 peer.
    #[rasn(tag(explicit(context, 3)))]
    pub leg_id: Option<LegId>,
}

impl CallInformationRequestArg {
    /// A request for `types` with every optional member absent.
    pub fn new(requested_information_type_list: Vec<RequestedInformationType>) -> Self {
        Self {
            requested_information_type_list,
            correlation_id: None,
            extensions: None,
            leg_id: None,
        }
    }
}

/// CallInformationReport (op 44): the SSF returns the requested call
/// information.
///
/// ```text
/// CallInformationReportArg ::= SEQUENCE {
///     requestedInformationList [0] RequestedInformationList,
///     correlationID            [1] CorrelationID OPTIONAL,   -- Q.1218 only
///     extensions               [2] SEQUENCE SIZE(1..numOfExtensions) OF
///                                      ExtensionField OPTIONAL,
///     legID                    [3] LegID OPTIONAL }          -- CS-2; CHOICE: explicit
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CallInformationReportArg {
    #[rasn(tag(context, 0))]
    pub requested_information_list: Vec<RequestedInformation>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 1))]
    pub correlation_id: Option<CorrelationId>,
    #[rasn(tag(context, 2))]
    pub extensions: Option<Extensions>,
    /// *CS-2* (EN 301 140-1 / Q.1228). Not a CS-1 member: leave it absent
    /// towards a CS-1 peer.
    #[rasn(tag(explicit(context, 3)))]
    pub leg_id: Option<LegId>,
}

impl CallInformationReportArg {
    /// A report of `list` with every optional member absent.
    pub fn new(requested_information_list: Vec<RequestedInformation>) -> Self {
        Self {
            requested_information_list,
            correlation_id: None,
            extensions: None,
            leg_id: None,
        }
    }
}

// ── Specialised resources ───────────────────────────────────────────────────

/// PlayAnnouncement (op 47): the SCF has the SRF play an announcement or a
/// tone.
///
/// ```text
/// PlayAnnouncementArg ::= SEQUENCE {
///     informationToSend           [0] InformationToSend,     -- CHOICE: explicit
///     disconnectFromIPForbidden   [1] BOOLEAN DEFAULT TRUE,
///     requestAnnouncementComplete [2] BOOLEAN DEFAULT TRUE,
///     extensions                  [3] SEQUENCE SIZE(1..numOfExtensions) OF
///                                         ExtensionField OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PlayAnnouncementArg {
    #[rasn(tag(explicit(context, 0)))]
    pub information_to_send: InformationToSend,
    /// `DEFAULT TRUE`.
    #[rasn(tag(context, 1))]
    pub disconnect_from_ip_forbidden: Option<bool>,
    /// `DEFAULT TRUE`.
    #[rasn(tag(context, 2))]
    pub request_announcement_complete: Option<bool>,
    #[rasn(tag(context, 3))]
    pub extensions: Option<Extensions>,
}

impl PlayAnnouncementArg {
    /// Play `information_to_send` with every other member at its default.
    pub fn new(information_to_send: InformationToSend) -> Self {
        Self {
            information_to_send,
            disconnect_from_ip_forbidden: None,
            request_announcement_complete: None,
            extensions: None,
        }
    }
}

/// PromptAndCollectUserInformation (op 48) argument: the SCF has the SRF
/// collect information from the user, optionally after a prompt.
///
/// ```text
/// PromptAndCollectUserInformationArg ::= SEQUENCE {
///     collectedInfo             [0] CollectedInfo,                -- CHOICE: explicit
///     disconnectFromIPForbidden [1] BOOLEAN DEFAULT TRUE,
///     informationToSend         [2] InformationToSend OPTIONAL,   -- CHOICE: explicit
///     extensions                [3] SEQUENCE SIZE(1..numOfExtensions) OF
///                                       ExtensionField OPTIONAL }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct PromptAndCollectUserInformationArg {
    #[rasn(tag(explicit(context, 0)))]
    pub collected_info: CollectedInfo,
    /// `DEFAULT TRUE`.
    #[rasn(tag(context, 1))]
    pub disconnect_from_ip_forbidden: Option<bool>,
    #[rasn(tag(explicit(context, 2)))]
    pub information_to_send: Option<InformationToSend>,
    #[rasn(tag(context, 3))]
    pub extensions: Option<Extensions>,
}

impl PromptAndCollectUserInformationArg {
    /// Collect `collected_info` with no prompt and every other member at its
    /// default.
    pub fn new(collected_info: CollectedInfo) -> Self {
        Self {
            collected_info,
            disconnect_from_ip_forbidden: None,
            information_to_send: None,
            extensions: None,
        }
    }
}

/// PromptAndCollectUserInformation (op 48) result, `ReceivedInformationArg`.
///
/// ```text
/// ReceivedInformationArg ::= CHOICE {
///     digitsResponse [0] Digits,
///     iA5Response    [1] IA5String }   -- Q.1218 only
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum PromptAndCollectUserInformationRes {
    #[rasn(tag(context, 0))]
    DigitsResponse(Digits),
    /// *Q.1218 only.*
    #[rasn(tag(context, 1))]
    Ia5Response(Ia5String),
}
