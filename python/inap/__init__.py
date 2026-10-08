"""inap, Rust-backed Intelligent Network Application Part (INAP CS-1) codec.

INAP CS-1 (ITU-T Q.1218 / ETSI EN 300 374-1) is the ASN.1 operation set that
drives fixed-network Intelligent Network services, service triggering, call
routing, charging and specialised-resource control, between the SSF and the SCF.
This package exposes the same BER codec the Rust crate (``cargo add inap``) ships,
from one source tree / one version.

The wire work (rasn BER encode/decode of the INAP argument types) runs in Rust;
Python just builds and inspects operation arguments. Each operation type has an
``.encode() -> bytes`` method and a ``decode(bytes)`` classmethod. Values are
carried as ``bytes`` in their respective ITU-T wire formats.

Covered: the call-control set (InitialDP, Connect, ReleaseCall,
RequestReportBCSMEvent, EventReportBCSM, ApplyCharging), the shared enums, the
operation codes, and the ``cs1_ssp_to_scp`` application-context OID helper. INAP
rides on TCAP over SCCP; wrapping these arguments in a TCAP Invoke is the caller's
job.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from ._inap import (
    ACTIVITY_TEST,
    APPLY_CHARGING,
    CONNECT,
    CONNECT_TO_RESOURCE,
    CONTINUE,
    ESTABLISH_TEMPORARY_CONNECTION,
    EVENT_REPORT_BCSM,
    INITIAL_DP,
    NATURE_INTERNATIONAL,
    NATURE_NATIONAL,
    PLAN_ISDN,
    RELEASE_CALL,
    REQUEST_REPORT_BCSM_EVENT,
    ApplyChargingArg,
    BcsmEvent,
    ConnectArg,
    EventReportBcsmArg,
    EventTypeBcsm,
    InapCodecError,
    InitialDpArg,
    MonitorMode,
    ReleaseCallArg,
    RequestReportBcsmEventArg,
    called_party_number,
    cs1_assist_handoff_ssp_to_scp,
    cs1_ip_to_scp,
    cs1_ssp_to_scp,
    international_e164,
    operation_name,
)

try:
    __version__ = version("inap")
except PackageNotFoundError:  # running from a source checkout without an installed dist
    __version__ = "0.0.0+unknown"

__all__ = [
    # operation arguments
    "InitialDpArg",
    "ConnectArg",
    "ReleaseCallArg",
    "RequestReportBcsmEventArg",
    "EventReportBcsmArg",
    "ApplyChargingArg",
    # shared types / enums
    "BcsmEvent",
    "EventTypeBcsm",
    "MonitorMode",
    # error
    "InapCodecError",
    # helpers
    "operation_name",
    "cs1_ssp_to_scp",
    "cs1_assist_handoff_ssp_to_scp",
    "cs1_ip_to_scp",
    # called-party-number encoder
    "called_party_number",
    "international_e164",
    "NATURE_INTERNATIONAL",
    "NATURE_NATIONAL",
    "PLAN_ISDN",
    # operation codes
    "INITIAL_DP",
    "CONNECT",
    "RELEASE_CALL",
    "REQUEST_REPORT_BCSM_EVENT",
    "EVENT_REPORT_BCSM",
    "APPLY_CHARGING",
    "ESTABLISH_TEMPORARY_CONNECTION",
    "CONNECT_TO_RESOURCE",
    "CONTINUE",
    "ACTIVITY_TEST",
    "__version__",
]
