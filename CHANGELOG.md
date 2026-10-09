# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [2.0.0]

Wire-format corrections. Until this release the suite tested encode against
decode, and compared against Wireshark only by checking that the dissection
raised no error. A mistake the encoder and the decoder share passes the first,
and Wireshark's BER dissector does not check the constructed bit of a context
tag, so a primitive element where a constructed one is required passes the
second. Every argument is now checked against a byte vector assembled by hand
from the ASN.1 of ETS 300 374-1 (September 1994) and ITU-T Q.1218 (10/95), and
against the fields Wireshark's INAP dissector reads back, asserted by name and
value.

**Several encodings of 1.x were not interoperable**: a conforming peer rejects
them or reads something else, and this crate could not decode what a conforming
peer sends. They are listed one by one below. Anything that stored or exchanged
1.x encodings of these arguments has to be regenerated.

Most public struct shapes changed. The mechanical part of an upgrade: build
arguments with the new `new(..)` constructors and struct update syntax, replace
raw `OctetString` legs in `BcsmEvent` with `LegId`, and build
`InformationToSend` / `CollectedInfo` / `MiscCallInfo` values instead of
passing pre-encoded octets.

### Fixed
- **Application context**: `cs1_ssp_to_scp()` returned `0.4.0.1.1.0.3.0`. That
  is the identifier of the ASN.1 module `Core-INAP-CS1-Codes`
  (`... in-network(1) modules(0) cs1-codes(3) version1(0)`); the application
  context is `0.4.0.1.1.1.0.0` (`... in-network(1) ac(1) cs1-ssp-to-scp(0)
  version1(0)`, ETS 300 374-1 clause 6.5). The two functions had each other's
  value. Not interoperable before: a dialogue opened with the old value names
  no application context a peer knows, and Wireshark does not recognise it as
  INAP. `core_inap_cs1_codes()` now returns the module identifier and is
  documented as not being a context.
- **RequestReportBCSMEvent**: `BCSMEvent.legID` was a primitive `[2]` holding
  the leg octet (`82 01 02`). It is `[2] LegID`, a CHOICE, so the tag is an
  explicit, constructed wrapper (`A2 03 80 01 02`). Not interoperable before
  whenever a leg was given: Wireshark reported the argument as malformed.
- **EventReportBCSM**: `miscCallInfo` was an OCTET STRING whose content the
  caller supplied, sent behind a primitive `[4]` (`84 03 80 01 01`). It is a
  SEQUENCE and therefore constructed (`A4 03 80 01 01`). Not conformant before
  (X.690 8.9.1); a lenient decoder such as Wireshark's tolerated it.
- **PlayAnnouncement** and **PromptAndCollectUserInformation**:
  `informationToSend` and `collectedInfo` were OCTET STRINGs sent behind a
  primitive tag (`80 05 A1 03 80 01 07`). Both are CHOICEs, so `[0]` and `[2]`
  are explicit, constructed wrappers (`A0 05 A1 03 80 01 07`). Not conformant
  before (X.690 8.14.2); the 1.x vector described as validated against
  Wireshark passed only because Wireshark does not check that bit.
- **ConnectToResource**: `resourceAddress` was two independent OPTIONAL members,
  so an argument with both alternatives, or with neither, could be built and
  sent. It is a CHOICE; exactly one alternative is now representable. Not
  interoperable before when both or neither were set; with exactly one set the
  octets were right.
- **EventTypeBCSM** lacked `origAttemptAuthorized(1)`, `oMidCall(8)` and
  `tMidCall(16)`. An event report or an InitialDP naming one of them could not
  be decoded.
- **InitialDP** could not be decoded as an SSF may send it: `rasn` refuses a
  member it does not know, and `cGEncountered [7]`, `extensions [15]`,
  `bearerCapability [27]` and `redirectionInformation [30]` were not modelled,
  nor were the members ETS 300 374-1 requires an SCF to recognise and ignore.
  The members 1.x had were on the right tags.
- **Connect**, **EstablishTemporaryConnection**, **AssistRequestInstructions**,
  **ApplyCharging**, **ResetTimer**, **CallInformationRequest**,
  **CallInformationReport**, **RequestReportBCSMEvent**: the same for the
  members that were not modelled, `extensions` in each of them among others.
  A message carrying one was refused.
- **Decoding** lost data without an error in three cases, all in `rasn` 0.28:
  an OPTIONAL member behind an explicit tag (every CHOICE-typed member: `legID`,
  `partyToCharge`, `eventSpecificInformationBCSM`, `bearerCapability`,
  `informationToSend`) whose content could not be decoded was returned as
  absent; a SEQUENCE OF whose last element could not be decoded was returned
  without it; octets after the argument were ignored. `decode` now fails in all
  three. The guard is in this crate and costs one extra encode per decode
  (about 0.8 µs on an InitialDP with every member, where `rasn` alone takes
  0.7 µs).
- **ResetTimer**: `timerID` accepted any INTEGER. It is `ENUMERATED { tssf(0) }`.
- **Python**: `decode` returned an object with fewer members than the message
  had whenever the message carried a member the class has no attribute for
  (for instance an InitialDP with `redirectingPartyID`). It now raises
  `InapCodecError`. A service key that does not fit an integer was returned as
  0 and now raises as well.

### Added
- Every member of every argument in ETS 300 374-1 clause 6.3, and the members
  Q.1218 has in addition (marked *Q.1218 only* in the documentation):
  `Extensions`, `EventSpecificInformationBcsm` with its thirteen alternatives,
  `DpSpecificCriteria`, `MiscCallInfo`, `BearerCapability`, `CgEncountered`,
  `InformationToSend` / `InbandInfo` / `MessageId` / `VariablePart` / `Tone`,
  `CollectedInfo` / `CollectedDigits`, `ResourceAddress`, `TimerId`, and the
  `calledAddress` requested information.
- `new(..)` constructors on the arguments with a mandatory member;
  `LegId::sending` / `LegId::receiving`; `MiscCallInfo::request` /
  `::notification`.
- Application contexts `cs1_assist_handoff_ssp_to_scp()` (`0.4.0.1.1.1.1.0`)
  and `cs1_ip_to_scp()` (`0.4.0.1.1.1.2.0`), and the arcs as constants.
- Python: `BcsmEvent(sending_side_id=..., receiving_side_id=...,
  number_of_digits=..., application_timer=...)`,
  `EventReportBcsmArg(event_specific_information_bcsm=..., sending_side_id=...,
  receiving_side_id=..., message_type=...)`, the three added `EventTypeBcsm`
  values, `cs1_assist_handoff_ssp_to_scp()` and `cs1_ip_to_scp()`.

### Changed
- `decode` requires `T: Encode` as well as `Decode`.
- `BcsmEvent.leg_id` is `Option<LegId>`; `MiscCallInfo` is a struct;
  `PlayAnnouncementArg.information_to_send` is `InformationToSend`;
  `PromptAndCollectUserInformationArg.collected_info` is `CollectedInfo` and
  `.information_to_send` is `Option<InformationToSend>`;
  `ConnectToResourceArg.resource_address` replaces `resource_address_ipv4` /
  `resource_address_none`; `ResetTimerArg.timer_id` is `Option<TimerId>`.
- `PromptAndCollectUserInformationRes` has the `Ia5Response` alternative of
  Q.1218, so a `match` on it needs another arm.
- Python: `BcsmEvent.leg_id` and `EventReportBcsmArg.misc_call_info` are
  replaced by the members above; `cs1_ssp_to_scp()` returns the corrected
  value.
- The round-trip and full-stack vector tests of 1.x are replaced by one test
  file per operation family, each with hand-assembled vectors and Wireshark
  field assertions (`tests/common` is the harness).

### Known limits
- `legID [3]` in CallInformationRequest and CallInformationReport is not a
  capability set 1 member. It is in capability set 2 (EN 301 140-1 V1.3.4
  clause 6.1) and was in 1.x; it is kept and marked as such. Leave it absent
  towards a capability set 1 peer.
- `InitialDPArg.serviceKey` is mandatory, as in ETS 300 374-1. Q.1218 makes it
  OPTIONAL; an InitialDP without it is refused.
- A member this crate does not model is refused, not skipped. The extension
  marker of the arguments is a comment in the 1994 ASN.1, and the defined way
  to extend them is the `extensions` member, which is modelled everywhere.
- Wireshark cannot confirm two members: its copy of the ASN.1 (capability set
  4) has nothing on `[1]` of ApplyChargingArg, where ETS 300 374-1 has
  `sendCalculationToSCPIndication`, and Wireshark 4.6 raises a dissector bug
  of its own on `bcsmEventCorrelationID`. Both are pinned by hand-assembled
  vectors only. Of the application contexts it knows `cs1-ssp-to-scp` alone.
- Not in this crate: the argument of CollectInformation, the operations
  InitiateCallAttempt, CallGap, ActivateServiceFiltering,
  ServiceFilteringResponse, EventNotificationCharging,
  RequestNotificationChargingEvent and SendChargingInformation, the error
  codes and error parameters, and the remaining four application contexts.

## [1.1.0]

### Added
- `address` module: build a Q.763 Called Party Number from a digit string
  (`called_party_number`, `international_e164`) instead of hand-packing the ISUP
  address format. The BCD filler is `0x0` per Q.763, so it does not reuse a TBCD
  packer. Exposed to Python as `inap.international_e164` / `.called_party_number`,
  with the `NATURE_*` / `PLAN_ISDN` values.

## [1.0.0]

First release, the INAP CS-1 operation codec (ITU-T Q.1218 / ETSI EN 300 374-1).

### Added
- Call establishment: `InitialDpArg`, `ConnectArg`, `ReleaseCallArg`,
  `ConnectToResourceArg`, `EstablishTemporaryConnectionArg`,
  `AssistRequestInstructionsArg`.
- Event handling: `RequestReportBcsmEventArg`, `EventReportBcsmArg`,
  `ResetTimerArg`, `CancelArg` (+ the shared `EventTypeBcsm` / `MonitorMode` /
  `BcsmEvent` types).
- Charging: `ApplyChargingArg`, `ApplyChargingReportArg`,
  `FurnishChargingInformationArg`.
- Call information: `CallInformationRequestArg`, `CallInformationReportArg` (+
  `RequestedInformationType` / `RequestedInformationValue` /
  `RequestedInformation`).
- Specialised resources: `PlayAnnouncementArg`,
  `PromptAndCollectUserInformationArg` / `PromptAndCollectUserInformationRes`.
- `op_codes` constants + `operation_name()`; `encode`/`decode` BER helpers;
  `InapError`; the `cs1-ssp-to-scp` application-context OID helper.
- Known-answer vectors validated against the Wireshark INAP dissector (INAP arg →
  TCAP → SCCP), plus BER round-trip tests over synthetic values.
- PyO3 bindings (`python` feature) and a Rust-backed Python wheel.

[1.0.0]: https://github.com/Real-Time-Telecom-B-V/inap/releases/tag/v1.0.0
