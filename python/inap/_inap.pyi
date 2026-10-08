"""Type stubs for the Rust-backed ``inap._inap`` extension module.

INAP CS-1 operation codec, ETS 300 374-1 / ITU-T Q.1218. Each operation
argument is built from keyword fields (``bytes`` in their ITU-T wire format),
encoded with ``.encode() -> bytes``, and recovered with the ``decode(bytes)``
classmethod.

The classes expose a subset of the members of each argument. ``decode`` raises
``InapCodecError`` for an argument carrying a member the class has no attribute
for; it never returns the argument with that member dropped.
"""

from __future__ import annotations

from typing import Optional

# ── Operation codes (ETS 300 374-1 clause 6.4) ───────────────────────────────
INITIAL_DP: int
CONNECT: int
RELEASE_CALL: int
REQUEST_REPORT_BCSM_EVENT: int
EVENT_REPORT_BCSM: int
APPLY_CHARGING: int
ESTABLISH_TEMPORARY_CONNECTION: int
CONNECT_TO_RESOURCE: int
CONTINUE: int
ACTIVITY_TEST: int

class InapCodecError(Exception):
    """INAP operation encode/decode error (ETS 300 374-1 / ITU-T Q.1218)."""

class EventTypeBcsm:
    """EventTypeBCSM, Basic Call State Model detection-point events.

    A PyO3 enum: members compare equal to their on-wire ASN.1 ENUMERATED integer
    (``int(...)`` yields the wire value), but it is not a Python ``enum.IntEnum``.
    """

    OrigAttemptAuthorized: EventTypeBcsm
    CollectedInfo: EventTypeBcsm
    AnalysedInformation: EventTypeBcsm
    RouteSelectFailure: EventTypeBcsm
    OCalledPartyBusy: EventTypeBcsm
    ONoAnswer: EventTypeBcsm
    OAnswer: EventTypeBcsm
    OMidCall: EventTypeBcsm
    ODisconnect: EventTypeBcsm
    OAbandon: EventTypeBcsm
    TermAttemptAuthorized: EventTypeBcsm
    TBusy: EventTypeBcsm
    TNoAnswer: EventTypeBcsm
    TAnswer: EventTypeBcsm
    TMidCall: EventTypeBcsm
    TDisconnect: EventTypeBcsm
    TAbandon: EventTypeBcsm
    def __int__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class MonitorMode:
    """MonitorMode, how a detection point should be reported."""

    Interrupted: MonitorMode
    NotifyAndContinue: MonitorMode
    Transparent: MonitorMode
    def __int__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...

class BcsmEvent:
    """One detection point to arm.

    ``sending_side_id`` / ``receiving_side_id`` are the two alternatives of the
    ``legID`` CHOICE (one octet, ``b"\x01"`` is leg 1); give at most one.
    ``number_of_digits`` / ``application_timer`` are the two alternatives of
    ``dPSpecificCriteria``; give at most one. ``ValueError`` otherwise.
    """

    event_type_bcsm: EventTypeBcsm
    monitor_mode: MonitorMode
    sending_side_id: Optional[bytes]
    receiving_side_id: Optional[bytes]
    number_of_digits: Optional[int]
    application_timer: Optional[int]
    def __init__(
        self,
        event_type_bcsm: EventTypeBcsm,
        monitor_mode: MonitorMode,
        *,
        sending_side_id: Optional[bytes] = ...,
        receiving_side_id: Optional[bytes] = ...,
        number_of_digits: Optional[int] = ...,
        application_timer: Optional[int] = ...,
    ) -> None: ...

class InitialDpArg:
    """InitialDP argument (op 0), SSF → SCF."""

    service_key: int
    called_party_number: Optional[bytes]
    calling_party_number: Optional[bytes]
    calling_partys_category: Optional[bytes]
    ip_available: Optional[bytes]
    location_number: Optional[bytes]
    event_type_bcsm: Optional[EventTypeBcsm]
    def __init__(
        self,
        service_key: int,
        *,
        called_party_number: Optional[bytes] = ...,
        calling_party_number: Optional[bytes] = ...,
        calling_partys_category: Optional[bytes] = ...,
        ip_available: Optional[bytes] = ...,
        location_number: Optional[bytes] = ...,
        event_type_bcsm: Optional[EventTypeBcsm] = ...,
    ) -> None: ...
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> InitialDpArg: ...

class ConnectArg:
    """Connect argument (op 20), SCF → SSF."""

    destination_routing_address: list[bytes]
    def __init__(self, destination_routing_address: list[bytes]) -> None: ...
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> ConnectArg: ...

class ReleaseCallArg:
    """ReleaseCall argument (op 22), SCF → SSF, bare Q.850 cause."""

    cause: bytes
    def __init__(self, cause: bytes) -> None: ...
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> ReleaseCallArg: ...

class RequestReportBcsmEventArg:
    """RequestReportBCSMEvent argument (op 23), SCF → SSF."""

    bcsm_events: list[BcsmEvent]
    def __init__(self, bcsm_events: list[BcsmEvent]) -> None: ...
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> RequestReportBcsmEventArg: ...

class EventReportBcsmArg:
    """EventReportBCSM argument (op 24), SSF → SCF.

    ``event_specific_information_bcsm`` is the BER encoding of the chosen
    alternative of EventSpecificInformationBCSM (``bytes.fromhex("a70480028090")``
    is an oDisconnectSpecificInfo with a release cause). ``message_type`` is the
    ``messageType`` of ``miscCallInfo``: 0 request, 1 notification, ``None`` to
    leave the member out.
    """

    event_type_bcsm: EventTypeBcsm
    event_specific_information_bcsm: Optional[bytes]
    sending_side_id: Optional[bytes]
    receiving_side_id: Optional[bytes]
    message_type: Optional[int]
    def __init__(
        self,
        event_type_bcsm: EventTypeBcsm,
        *,
        event_specific_information_bcsm: Optional[bytes] = ...,
        sending_side_id: Optional[bytes] = ...,
        receiving_side_id: Optional[bytes] = ...,
        message_type: Optional[int] = ...,
    ) -> None: ...
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> EventReportBcsmArg: ...

class ApplyChargingArg:
    """ApplyCharging argument (op 35), SCF → SSF."""

    ach_billing_charging_characteristics: bytes
    party_to_charge: Optional[bytes]
    def __init__(
        self,
        ach_billing_charging_characteristics: bytes,
        *,
        party_to_charge: Optional[bytes] = ...,
    ) -> None: ...
    def encode(self) -> bytes: ...
    @classmethod
    def decode(cls, data: bytes) -> ApplyChargingArg: ...

def operation_name(code: int) -> Optional[str]:
    """Name of a well-known INAP CS-1 operation code (e.g. ``0 -> "initialDP"``)."""

def cs1_ssp_to_scp() -> list[int]:
    """The ``cs1-ssp-to-scp`` application context arcs (0.4.0.1.1.1.0.0)."""

def cs1_assist_handoff_ssp_to_scp() -> list[int]:
    """The ``cs1-assist-handoff-ssp-to-scp`` application context arcs
    (0.4.0.1.1.1.1.0)."""

def cs1_ip_to_scp() -> list[int]:
    """The ``cs1-ip-to-scp`` application context arcs (0.4.0.1.1.1.2.0)."""

# ── Called-party-number encoder (Q.763 §3.9) ─────────────────────────────────
NATURE_INTERNATIONAL: int
NATURE_NATIONAL: int
PLAN_ISDN: int

def called_party_number(
    digits: str, nature: int = ..., plan: int = ..., inn: bool = ...
) -> bytes:
    """Encode a Q.763 Called Party Number from a digit string. Defaults to
    international E.164."""

def international_e164(digits: str) -> bytes:
    """Encode an international E.164 Called Party Number (CAMEL
    destinationRoutingAddress)."""
