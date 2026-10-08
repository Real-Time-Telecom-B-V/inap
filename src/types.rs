//! Common INAP CS-1 data types.
//!
//! # What these are checked against
//!
//! Every type here was read from the ASN.1 of two documents and is tagged in
//! its documentation with where it comes from:
//!
//! * **ETS 300 374-1, September 1994** (ETSI Core INAP CS-1), clause 6.3,
//!   module `Core-INAP-CS1-DataTypes`. This is the baseline: a type or member
//!   with no remark is in this document.
//! * **ITU-T Q.1218 (10/95)**, clause 2.1.3, module `IN-CS-1-Datatypes`. ETSI
//!   Core INAP is a subset of it. Members and alternatives that only Q.1218
//!   has are modelled so that a message from a Q.1218 entity decodes, and are
//!   marked *Q.1218 only*: an ETSI Core INAP entity does not send them.
//!
//! Both modules are `IMPLICIT TAGS`. A context tag in front of a CHOICE or an
//! open type is nevertheless EXPLICIT (X.680 31.2.7): the member is a
//! constructed element wrapping the encoding of the chosen alternative. Those
//! members carry `tag(explicit(..))` below and are pinned octet by octet in
//! the test suite, since Wireshark does not check the constructed bit.
//!
//! Addresses and digit strings are OCTET STRINGs whose content is defined by
//! the bearer signalling (ISUP, ETS 300 356-1 / Q.763; DSS1, ETS 300 403-1 /
//! Q.931). Build a called party number from a digit string with
//! [`crate::address`].
//!
//! `DEFAULT` members are modelled as `Option`: `None` is "absent, the default
//! applies", and a present value is sent as given.

use rasn::prelude::*;

// ── Octet-string leaf types ─────────────────────────────────────────────────

/// ServiceKey: `Integer4`, identifies the service logic at the SCF.
pub type ServiceKey = Integer;
/// CalledPartyNumber, ISUP called party number.
pub type CalledPartyNumber = OctetString;
/// CallingPartyNumber, ISUP calling party number.
pub type CallingPartyNumber = OctetString;
/// CallingPartysCategory, one octet, ISUP calling party's category.
pub type CallingPartysCategory = OctetString;
/// LocationNumber, ISUP location number.
pub type LocationNumber = OctetString;
/// OriginalCalledPartyID, ISUP original called number.
pub type OriginalCalledPartyId = OctetString;
/// RedirectingPartyID, ISUP redirecting number.
pub type RedirectingPartyId = OctetString;
/// RedirectionInformation, two octets, ISUP redirection information.
pub type RedirectionInformation = OctetString;
/// Cause, ISUP cause indicators (Q.850 values), at least two octets.
pub type Cause = OctetString;
/// Digits, ISUP generic number or generic digits.
pub type Digits = OctetString;
/// CorrelationID: `Digits`.
pub type CorrelationId = Digits;
/// AdditionalCallingPartyNumber: `Digits`.
pub type AdditionalCallingPartyNumber = Digits;
/// AssistingSSPIPRoutingAddress: `Digits`.
pub type AssistingSspIpRoutingAddress = Digits;
/// IPRoutingAddress: `CalledPartyNumber`.
pub type IpRoutingAddress = CalledPartyNumber;
/// HighLayerCompatibility, two octets, DSS1 coding.
pub type HighLayerCompatibility = OctetString;
/// IPSSPCapabilities, network operator specific.
pub type IpsspCapabilities = OctetString;
/// IPAvailable, network operator specific.
pub type IpAvailable = OctetString;
/// ServiceInteractionIndicators, network operator specific.
pub type ServiceInteractionIndicators = OctetString;
/// ForwardCallIndicators, two octets, ISUP forward call indicators.
pub type ForwardCallIndicators = OctetString;
/// ScfID, network operator specific.
pub type ScfId = OctetString;
/// LegType, one octet: `01` is leg 1, `02` is leg 2.
pub type LegType = OctetString;
/// AlertingPattern, three octets, DSS1 signal parameter.
pub type AlertingPattern = OctetString;
/// DateAndTime, six octets, `YYMMDDHHMMSS` in BCD.
pub type DateAndTime = OctetString;
/// RouteList: `SEQUENCE SIZE(1..3) OF OCTET STRING`.
pub type RouteList = Vec<OctetString>;
/// DisplayInformation: `IA5String`.
pub type DisplayInformation = Ia5String;
/// AChBillingChargingCharacteristics, network operator specific.
pub type AChBillingChargingCharacteristics = OctetString;
/// CallResult, network operator specific.
pub type CallResult = OctetString;
/// FCIBillingChargingCharacteristics, network operator specific.
pub type FciBillingChargingCharacteristics = OctetString;

/// CallingPartyBusinessGroupID. *Q.1218 only.*
pub type CallingPartyBusinessGroupId = OctetString;
/// CallingPartySubaddress. *Q.1218 only.*
pub type CallingPartySubaddress = OctetString;
/// ServiceProfileIdentifier. *Q.1218 only.*
pub type ServiceProfileIdentifier = OctetString;
/// Carrier. *Q.1218 only.*
pub type Carrier = OctetString;
/// ISDNAccessRelatedInformation. *Q.1218 only.*
pub type IsdnAccessRelatedInformation = OctetString;
/// TravellingClassMark: `LocationNumber`. *Q.1218 only.*
pub type TravellingClassMark = LocationNumber;

// ── Extensions ──────────────────────────────────────────────────────────────

/// The criticality of an [`ExtensionField`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum CriticalityType {
    Ignore = 0,
    Abort = 1,
}

/// ExtensionField: one network operator specific extension.
///
/// ```text
/// ExtensionField ::= SEQUENCE {
///     type        INTEGER,
///     criticality ENUMERATED { ignore(0), abort(1) } DEFAULT ignore,
///     value       [1] ANY DEFINED BY type }
/// ```
///
/// `value` is an open type, so `[1]` is EXPLICIT and the member holds the
/// complete encoding (tag, length, content) of the extension's own type.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ExtensionField {
    pub extension_type: Integer,
    /// `DEFAULT ignore`.
    pub criticality: Option<CriticalityType>,
    #[rasn(tag(explicit(context, 1)))]
    pub value: Any,
}

/// `SEQUENCE SIZE(1..numOfExtensions) OF ExtensionField`.
pub type Extensions = Vec<ExtensionField>;

// ── Detection points and events ─────────────────────────────────────────────

/// EventTypeBCSM: the detection points of the basic call state models.
///
/// The names follow Q.1218; ETS 300 374-1 spells value 3 `analyzedInformation`
/// and value 13 `tCalledPartyBusy`. `OrigAttemptAuthorized` and
/// `TermAttemptAuthorized` can only be trigger detection points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum EventTypeBcsm {
    OrigAttemptAuthorized = 1,
    CollectedInfo = 2,
    AnalysedInformation = 3,
    RouteSelectFailure = 4,
    OCalledPartyBusy = 5,
    ONoAnswer = 6,
    OAnswer = 7,
    OMidCall = 8,
    ODisconnect = 9,
    OAbandon = 10,
    TermAttemptAuthorized = 12,
    TBusy = 13,
    TNoAnswer = 14,
    TAnswer = 15,
    TMidCall = 16,
    TDisconnect = 17,
    TAbandon = 18,
}

/// MonitorMode: how an armed event is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum MonitorMode {
    Interrupted = 0,
    NotifyAndContinue = 1,
    Transparent = 2,
}

/// LegID: a party in the call.
///
/// ```text
/// LegID ::= CHOICE {
///     sendingSideID   [0] LegType,    -- in operations from SCF to SSF
///     receivingSideID [1] LegType }   -- in operations from SSF to SCF
/// ```
///
/// A CHOICE, so wherever it sits behind a context tag that tag is EXPLICIT.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum LegId {
    #[rasn(tag(context, 0))]
    SendingSideId(LegType),
    #[rasn(tag(context, 1))]
    ReceivingSideId(LegType),
}

impl LegId {
    /// `sendingSideID` with a one-octet leg number.
    pub fn sending(leg: u8) -> Self {
        Self::SendingSideId(vec![leg].into())
    }

    /// `receivingSideID` with a one-octet leg number.
    pub fn receiving(leg: u8) -> Self {
        Self::ReceivingSideId(vec![leg].into())
    }
}

/// DPSpecificCriteria (`DpSpecificCriteria` in Q.1218).
///
/// ```text
/// DPSpecificCriteria ::= CHOICE {
///     numberOfDigits   [0] NumberOfDigits,     -- INTEGER (1..255)
///     applicationTimer [1] ApplicationTimer }  -- INTEGER (0..2047), seconds
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum DpSpecificCriteria {
    #[rasn(tag(context, 0))]
    NumberOfDigits(u8),
    #[rasn(tag(context, 1))]
    ApplicationTimer(u16),
}

/// BCSMEvent: one detection point to arm.
///
/// ```text
/// BCSMEvent ::= SEQUENCE {
///     eventTypeBCSM      [0]  EventTypeBCSM,
///     monitorMode        [1]  MonitorMode,
///     legID              [2]  LegID OPTIONAL,
///     dPSpecificCriteria [30] DPSpecificCriteria OPTIONAL }
/// ```
///
/// `legID` and `dPSpecificCriteria` are CHOICEs, so `[2]` and `[30]` are
/// EXPLICIT.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct BcsmEvent {
    #[rasn(tag(context, 0))]
    pub event_type_bcsm: EventTypeBcsm,
    #[rasn(tag(context, 1))]
    pub monitor_mode: MonitorMode,
    #[rasn(tag(explicit(context, 2)))]
    pub leg_id: Option<LegId>,
    #[rasn(tag(explicit(context, 30)))]
    pub dp_specific_criteria: Option<DpSpecificCriteria>,
}

impl BcsmEvent {
    /// An event with no leg and no criteria.
    pub fn new(event_type_bcsm: EventTypeBcsm, monitor_mode: MonitorMode) -> Self {
        Self {
            event_type_bcsm,
            monitor_mode,
            leg_id: None,
            dp_specific_criteria: None,
        }
    }
}

/// `messageType` of [`MiscCallInfo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum MessageType {
    Request = 0,
    Notification = 1,
}

/// `dpAssignment` of [`MiscCallInfo`]. *Q.1218 only.*
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum DpAssignment {
    IndividualLine = 0,
    GroupBased = 1,
    OfficeBased = 2,
}

/// MiscCallInfo: detection point related information.
///
/// ```text
/// MiscCallInfo ::= SEQUENCE {
///     messageType  [0] ENUMERATED { request(0), notification(1) },
///     dpAssignment [1] ENUMERATED { individualLine(0), groupBased(1),
///                                   officeBased(2) } OPTIONAL }  -- Q.1218 only
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MiscCallInfo {
    #[rasn(tag(context, 0))]
    pub message_type: MessageType,
    /// *Q.1218 only.*
    #[rasn(tag(context, 1))]
    pub dp_assignment: Option<DpAssignment>,
}

impl MiscCallInfo {
    /// `{ messageType request }`, the value an absent member defaults to.
    pub fn request() -> Self {
        Self {
            message_type: MessageType::Request,
            dp_assignment: None,
        }
    }

    /// `{ messageType notification }`.
    pub fn notification() -> Self {
        Self {
            message_type: MessageType::Notification,
            dp_assignment: None,
        }
    }
}

/// collectedInfoSpecificInfo and analyzedInfoSpecificInfo:
/// `SEQUENCE { calledPartyNumber [0] CalledPartyNumber }`.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CalledPartySpecificInfo {
    #[rasn(tag(context, 0))]
    pub called_party_number: CalledPartyNumber,
}

/// routeSelectFailureSpecificInfo: `SEQUENCE { failureCause [0] Cause OPTIONAL }`.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RouteSelectFailureSpecificInfo {
    #[rasn(tag(context, 0))]
    pub failure_cause: Option<Cause>,
}

/// oCalledPartyBusySpecificInfo and tCalledPartyBusySpecificInfo
/// (`tBusySpecificInfo` in Q.1218): `SEQUENCE { busyCause [0] Cause OPTIONAL }`.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct BusySpecificInfo {
    #[rasn(tag(context, 0))]
    pub busy_cause: Option<Cause>,
}

/// The alternatives for which no specific information is defined: an empty
/// SEQUENCE (oNoAnswer, oAnswer, tNoAnswer, tAnswer).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct NoSpecificInfo {}

/// oMidCallSpecificInfo and tMidCallSpecificInfo. Empty in ETS 300 374-1;
/// Q.1218 has `connectTime [0] Integer4 OPTIONAL`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MidCallSpecificInfo {
    /// *Q.1218 only.*
    #[rasn(tag(context, 0))]
    pub connect_time: Option<u32>,
}

/// oDisconnectSpecificInfo and tDisconnectSpecificInfo:
/// `SEQUENCE { releaseCause [0] Cause OPTIONAL }`, to which Q.1218 adds
/// `connectTime [1] Integer4 OPTIONAL`.
#[derive(Debug, Clone, Default, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct DisconnectSpecificInfo {
    #[rasn(tag(context, 0))]
    pub release_cause: Option<Cause>,
    /// *Q.1218 only.*
    #[rasn(tag(context, 1))]
    pub connect_time: Option<u32>,
}

/// EventSpecificInformationBCSM: what the SSF reports with an event.
///
/// A CHOICE of thirteen SEQUENCEs on context tags 0 to 12. As a member of
/// EventReportBCSMArg it sits behind `[2]`, which is therefore EXPLICIT.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum EventSpecificInformationBcsm {
    #[rasn(tag(context, 0))]
    CollectedInfoSpecificInfo(CalledPartySpecificInfo),
    #[rasn(tag(context, 1))]
    AnalyzedInfoSpecificInfo(CalledPartySpecificInfo),
    #[rasn(tag(context, 2))]
    RouteSelectFailureSpecificInfo(RouteSelectFailureSpecificInfo),
    #[rasn(tag(context, 3))]
    OCalledPartyBusySpecificInfo(BusySpecificInfo),
    #[rasn(tag(context, 4))]
    ONoAnswerSpecificInfo(NoSpecificInfo),
    #[rasn(tag(context, 5))]
    OAnswerSpecificInfo(NoSpecificInfo),
    #[rasn(tag(context, 6))]
    OMidCallSpecificInfo(MidCallSpecificInfo),
    #[rasn(tag(context, 7))]
    ODisconnectSpecificInfo(DisconnectSpecificInfo),
    #[rasn(tag(context, 8))]
    TBusySpecificInfo(BusySpecificInfo),
    #[rasn(tag(context, 9))]
    TNoAnswerSpecificInfo(NoSpecificInfo),
    #[rasn(tag(context, 10))]
    TAnswerSpecificInfo(NoSpecificInfo),
    #[rasn(tag(context, 11))]
    TMidCallSpecificInfo(MidCallSpecificInfo),
    #[rasn(tag(context, 12))]
    TDisconnectSpecificInfo(DisconnectSpecificInfo),
}

// ── InitialDP leaf types ────────────────────────────────────────────────────

/// BearerCapability.
///
/// ```text
/// BearerCapability ::= CHOICE {
///     bearerCap [0] OCTET STRING (SIZE (2..maxBearerCapabilityLength)),
///     tmr       [1] OCTET STRING (SIZE (1)) }   -- Q.1218 only
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum BearerCapability {
    /// DSS1 bearer capability / ISUP user service information.
    #[rasn(tag(context, 0))]
    BearerCap(OctetString),
    /// ISUP transmission medium requirement. *Q.1218 only.*
    #[rasn(tag(context, 1))]
    Tmr(OctetString),
}

/// CGEncountered: the call gapping the call ran into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum CgEncountered {
    /// *Q.1218 only.*
    NoCgEncountered = 0,
    ManualCgEncountered = 1,
    ScpOverload = 2,
}

/// TerminalType. *Q.1218 only.*
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum TerminalType {
    Unknown = 0,
    DialPulse = 1,
    Dtmf = 2,
    Isdn = 3,
    IsdnNoDtmf = 4,
    Spare = 16,
}

/// TriggerType. *Q.1218 only.*
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum TriggerType {
    FeatureActivation = 0,
    VerticalServiceCode = 1,
    CustomizedAccess = 2,
    CustomizedIntercom = 3,
    EmergencyService = 12,
    Afr = 13,
    SharedIoTrunk = 14,
    OffHookDelay = 17,
    ChannelSetupPri = 18,
    TNoAnswer = 25,
    TBusy = 26,
    OCalledPartyBusy = 27,
    ONoAnswer = 29,
    OriginationAttemptAuthorized = 30,
    OAnswer = 31,
    ODisconnect = 32,
    TermAttemptAuthorized = 33,
    TAnswer = 34,
    TDisconnect = 35,
}

/// ForwardingCondition. *Q.1218 only.*
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum ForwardingCondition {
    Busy = 0,
    NoAnswer = 1,
    Any = 2,
}

/// TimerID: the timer to reset. Only `tssf` is defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum TimerId {
    Tssf = 0,
}

// ── Call information ────────────────────────────────────────────────────────

/// RequestedInformationType.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum RequestedInformationType {
    CallAttemptElapsedTime = 0,
    CallStopTime = 1,
    CallConnectedElapsedTime = 2,
    CalledAddress = 3,
    ReleaseCause = 30,
}

/// RequestedInformationValue.
///
/// ```text
/// RequestedInformationValue ::= CHOICE {
///     callAttemptElapsedTimeValue   [0]  INTEGER (0..255),   -- seconds
///     callStopTimeValue             [1]  DateAndTime,
///     callConnectedElapsedTimeValue [2]  Integer4,           -- 100 ms units
///     calledAddressValue            [3]  Digits,
///     releaseCauseValue             [30] Cause }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum RequestedInformationValue {
    #[rasn(tag(context, 0))]
    CallAttemptElapsedTimeValue(Integer),
    #[rasn(tag(context, 1))]
    CallStopTimeValue(DateAndTime),
    #[rasn(tag(context, 2))]
    CallConnectedElapsedTimeValue(Integer),
    #[rasn(tag(context, 3))]
    CalledAddressValue(Digits),
    #[rasn(tag(context, 30))]
    ReleaseCauseValue(Cause),
}

/// RequestedInformation: one (type, value) pair. The value is a CHOICE, so
/// `[1]` is EXPLICIT.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct RequestedInformation {
    #[rasn(tag(context, 0))]
    pub requested_information_type: RequestedInformationType,
    #[rasn(tag(explicit(context, 1)))]
    pub requested_information_value: RequestedInformationValue,
}

// ── Specialised resource function ───────────────────────────────────────────

/// VariablePart: one variable element of an announcement.
///
/// ```text
/// VariablePart ::= CHOICE {
///     integer [0] Integer4,
///     number  [1] Digits,                    -- generic digits
///     time    [2] OCTET STRING (SIZE(2)),    -- HH:MM, BCD
///     date    [3] OCTET STRING (SIZE(3)),    -- YYMMDD, BCD
///     price   [4] OCTET STRING (SIZE(4)) }   -- DDDDDD.DD, BCD
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum VariablePart {
    #[rasn(tag(context, 0))]
    Integer(u32),
    #[rasn(tag(context, 1))]
    Number(Digits),
    #[rasn(tag(context, 2))]
    Time(OctetString),
    #[rasn(tag(context, 3))]
    Date(OctetString),
    #[rasn(tag(context, 4))]
    Price(OctetString),
}

/// The `text` alternative of [`MessageId`].
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct MessageIdText {
    #[rasn(tag(context, 0))]
    pub message_content: Ia5String,
    #[rasn(tag(context, 1))]
    pub attributes: Option<OctetString>,
}

/// The `variableMessage` alternative of [`MessageId`]. `variableParts` holds
/// one to five parts; each is a CHOICE and appears with its own tag.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct VariableMessage {
    #[rasn(tag(context, 0))]
    pub elementary_message_id: u32,
    #[rasn(tag(context, 1))]
    pub variable_parts: Vec<VariablePart>,
}

/// MessageID: which announcement to play.
///
/// ```text
/// MessageID ::= CHOICE {
///     elementaryMessageID  [0]  Integer4,
///     text                 [1]  SEQUENCE { messageContent [0] IA5String,
///                                          attributes     [1] OCTET STRING OPTIONAL },
///     elementaryMessageIDs [29] SEQUENCE SIZE (1..numOfMessageIDs) OF Integer4,
///     variableMessage      [30] SEQUENCE { elementaryMessageID [0] Integer4,
///                                          variableParts [1] SEQUENCE SIZE(1..5)
///                                                            OF VariablePart } }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum MessageId {
    #[rasn(tag(context, 0))]
    ElementaryMessageId(u32),
    #[rasn(tag(context, 1))]
    Text(MessageIdText),
    #[rasn(tag(context, 29))]
    ElementaryMessageIds(Vec<u32>),
    #[rasn(tag(context, 30))]
    VariableMessage(VariableMessage),
}

/// InbandInfo: an announcement and how often to play it.
///
/// ```text
/// InbandInfo ::= SEQUENCE {
///     messageID           [0] MessageID,
///     numberOfRepetitions [1] INTEGER (1..127) OPTIONAL,
///     duration            [2] INTEGER (0..32767) OPTIONAL,   -- seconds
///     interval            [3] INTEGER (0..32767) OPTIONAL }  -- seconds
/// ```
///
/// `messageID` is a CHOICE, so `[0]` is EXPLICIT.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct InbandInfo {
    #[rasn(tag(explicit(context, 0)))]
    pub message_id: MessageId,
    #[rasn(tag(context, 1))]
    pub number_of_repetitions: Option<u8>,
    #[rasn(tag(context, 2))]
    pub duration: Option<u16>,
    #[rasn(tag(context, 3))]
    pub interval: Option<u16>,
}

impl InbandInfo {
    /// An announcement played once, with no duration or interval.
    pub fn new(message_id: MessageId) -> Self {
        Self {
            message_id,
            number_of_repetitions: None,
            duration: None,
            interval: None,
        }
    }
}

/// Tone: `SEQUENCE { toneID [0] Integer4, duration [1] Integer4 OPTIONAL }`.
/// The duration is in seconds, 0 is infinite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct Tone {
    #[rasn(tag(context, 0))]
    pub tone_id: u32,
    #[rasn(tag(context, 1))]
    pub duration: Option<u32>,
}

/// InformationToSend: what the SRF sends to the user.
///
/// ```text
/// InformationToSend ::= CHOICE {
///     inbandInfo         [0] InbandInfo,
///     tone               [1] Tone,
///     displayInformation [2] DisplayInformation }   -- IA5String
/// ```
///
/// A CHOICE, so wherever it sits behind a context tag that tag is EXPLICIT.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum InformationToSend {
    #[rasn(tag(context, 0))]
    InbandInfo(InbandInfo),
    #[rasn(tag(context, 1))]
    Tone(Tone),
    #[rasn(tag(context, 2))]
    DisplayInformation(DisplayInformation),
}

/// ErrorTreatment. Value 0 is `stdErrorAndInfo` in ETS 300 374-1 and
/// `reportErrorToScf` in Q.1218.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(enumerated)]
pub enum ErrorTreatment {
    StdErrorAndInfo = 0,
    Help = 1,
    RepeatPrompt = 2,
}

/// CollectedDigits: how to collect digits from the user.
///
/// ```text
/// CollectedDigits ::= SEQUENCE {
///     minimumNbOfDigits   [0]  INTEGER (1..127) DEFAULT 1,
///     maximumNbOfDigits   [1]  INTEGER (1..127),
///     endOfReplyDigit     [2]  OCTET STRING (SIZE (1..2)) OPTIONAL,
///     cancelDigit         [3]  OCTET STRING (SIZE (1..2)) OPTIONAL,
///     startDigit          [4]  OCTET STRING (SIZE (1..2)) OPTIONAL,
///     firstDigitTimeOut   [5]  INTEGER (1..127) OPTIONAL,
///     interDigitTimeOut   [6]  INTEGER (1..127) OPTIONAL,
///     errortreatment      [7]  ErrorTreatment DEFAULT stdErrorAndInfo,
///     interruptableAnnInd [8]  BOOLEAN DEFAULT TRUE,
///     voiceInformation    [9]  BOOLEAN DEFAULT FALSE,
///     voiceBack           [10] BOOLEAN DEFAULT FALSE }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct CollectedDigits {
    /// `DEFAULT 1`.
    #[rasn(tag(context, 0))]
    pub minimum_nb_of_digits: Option<u8>,
    #[rasn(tag(context, 1))]
    pub maximum_nb_of_digits: u8,
    #[rasn(tag(context, 2))]
    pub end_of_reply_digit: Option<OctetString>,
    #[rasn(tag(context, 3))]
    pub cancel_digit: Option<OctetString>,
    #[rasn(tag(context, 4))]
    pub start_digit: Option<OctetString>,
    #[rasn(tag(context, 5))]
    pub first_digit_time_out: Option<u8>,
    #[rasn(tag(context, 6))]
    pub inter_digit_time_out: Option<u8>,
    /// `DEFAULT stdErrorAndInfo`.
    #[rasn(tag(context, 7))]
    pub error_treatment: Option<ErrorTreatment>,
    /// `DEFAULT TRUE`.
    #[rasn(tag(context, 8))]
    pub interruptable_ann_ind: Option<bool>,
    /// `DEFAULT FALSE`.
    #[rasn(tag(context, 9))]
    pub voice_information: Option<bool>,
    /// `DEFAULT FALSE`.
    #[rasn(tag(context, 10))]
    pub voice_back: Option<bool>,
}

impl CollectedDigits {
    /// Collect up to `maximum_nb_of_digits` digits, everything else at its
    /// default.
    pub fn new(maximum_nb_of_digits: u8) -> Self {
        Self {
            minimum_nb_of_digits: None,
            maximum_nb_of_digits,
            end_of_reply_digit: None,
            cancel_digit: None,
            start_digit: None,
            first_digit_time_out: None,
            inter_digit_time_out: None,
            error_treatment: None,
            interruptable_ann_ind: None,
            voice_information: None,
            voice_back: None,
        }
    }
}

/// CollectedInfo: what to collect from the user.
///
/// ```text
/// CollectedInfo ::= CHOICE {
///     collectedDigits [0] CollectedDigits,
///     iA5Information  [1] BOOLEAN }   -- Q.1218 only
/// ```
///
/// A CHOICE, so wherever it sits behind a context tag that tag is EXPLICIT.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum CollectedInfo {
    #[rasn(tag(context, 0))]
    CollectedDigits(CollectedDigits),
    /// *Q.1218 only.*
    #[rasn(tag(context, 1))]
    Ia5Information(bool),
}

/// The `both` alternative of [`ResourceAddress`]. *Q.1218 only.*
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
pub struct ResourceAddressBoth {
    #[rasn(tag(context, 0))]
    pub ip_routing_address: IpRoutingAddress,
    #[rasn(tag(explicit(context, 1)))]
    pub leg_id: LegId,
}

/// The `resourceAddress` of ConnectToResource.
///
/// ```text
/// resourceAddress CHOICE {
///     ipRoutingAddress [0] IPRoutingAddress,
///     legID            [1] LegID,                        -- Q.1218 only
///     both             [2] SEQUENCE {                    -- Q.1218 only
///         ipRoutingAddress [0] IPRoutingAddress,
///         legID            [1] LegID },
///     none             [3] NULL }
/// ```
///
/// The CHOICE itself has no tag inside ConnectToResourceArg, so the tag of the
/// chosen alternative appears directly in the SEQUENCE.
#[derive(Debug, Clone, PartialEq, Eq, AsnType, Decode, Encode)]
#[rasn(choice)]
pub enum ResourceAddress {
    #[rasn(tag(context, 0))]
    IpRoutingAddress(IpRoutingAddress),
    /// *Q.1218 only.*
    #[rasn(tag(explicit(context, 1)))]
    LegId(LegId),
    /// *Q.1218 only.*
    #[rasn(tag(context, 2))]
    Both(ResourceAddressBoth),
    /// The SRF is reached without an address (it is integrated in the SSP).
    #[rasn(tag(context, 3))]
    None(()),
}
