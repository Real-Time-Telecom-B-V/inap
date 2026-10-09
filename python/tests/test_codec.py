"""Codec parity / known-answer tests for the inap wheel.

These exercise the same Rust `rasn` BER codec the crate ships, through the Python
surface. Each operation argument must ``encode()`` to the exact BER bytes the Rust
crate produces (the ``KAT_*`` known answers below), and ``decode()`` back to the
same fields. All values are SYNTHETIC, fictional ``+1-555-01xx`` address signals,
made-up keys; nothing here is captured traffic.
"""

from __future__ import annotations

import pytest

import inap


def test_operation_codes_and_names() -> None:
    assert inap.INITIAL_DP == 0
    assert inap.CONNECT == 20
    assert inap.RELEASE_CALL == 22
    assert inap.ESTABLISH_TEMPORARY_CONNECTION == 17
    assert inap.CONNECT_TO_RESOURCE == 19
    assert inap.operation_name(inap.INITIAL_DP) == "initialDP"
    assert inap.operation_name(inap.CONNECT) == "connect"
    assert inap.operation_name(inap.ESTABLISH_TEMPORARY_CONNECTION) == (
        "establishTemporaryConnection"
    )
    assert inap.operation_name(999) is None


def test_event_type_bcsm_wire_values() -> None:
    # The enum's integer value is the on-wire ASN.1 ENUMERATED encoding.
    assert int(inap.EventTypeBcsm.CollectedInfo) == 2
    assert int(inap.EventTypeBcsm.OAnswer) == 7
    # 1, 8 and 16 were missing before 2.0.0 (ETS 300 374-1 clause 6.3).
    assert int(inap.EventTypeBcsm.OrigAttemptAuthorized) == 1
    assert int(inap.EventTypeBcsm.OMidCall) == 8
    assert int(inap.EventTypeBcsm.TMidCall) == 16
    assert int(inap.EventTypeBcsm.TAbandon) == 18


def test_monitor_mode_wire_values() -> None:
    assert int(inap.MonitorMode.Interrupted) == 0
    assert int(inap.MonitorMode.NotifyAndContinue) == 1
    assert int(inap.MonitorMode.Transparent) == 2


def test_application_context_helper() -> None:
    # ETS 300 374-1 clause 6.5: {ccitt(0) identified-organization(4) etsi(0)
    # inDomain(1) in-network(1) ac(1) cs1-ssp-to-scp(0) version1(0)}.
    # Before 2.0.0 this returned 0.4.0.1.1.0.3.0, a module identifier.
    assert inap.cs1_ssp_to_scp() == [0, 4, 0, 1, 1, 1, 0, 0]
    assert inap.cs1_assist_handoff_ssp_to_scp() == [0, 4, 0, 1, 1, 1, 1, 0]
    assert inap.cs1_ip_to_scp() == [0, 4, 0, 1, 1, 1, 2, 0]


# ── Known-answer vectors: Python encode() must be byte-identical to Rust ──────

KAT_INITIAL_DP = bytes.fromhex("301380012a8205031555012385010a8901019c0102")
KAT_CONNECT = bytes.fromhex("3009a00704050315550123")
KAT_RELEASE_CALL = bytes.fromhex("04029003")
KAT_RRBE = bytes.fromhex("300aa0083006800107810101")
KAT_ERB = bytes.fromhex("3003800107")
KAT_APPLY_CHARGING = bytes.fromhex("300a8003000102a203800101")


def test_initial_dp_known_answer_and_round_trip() -> None:
    idp = inap.InitialDpArg(
        42,
        called_party_number=bytes([0x03, 0x15, 0x55, 0x01, 0x23]),
        calling_partys_category=bytes([0x0A]),
        ip_available=bytes([0x01]),
        event_type_bcsm=inap.EventTypeBcsm.CollectedInfo,
    )
    wire = idp.encode()
    assert wire == KAT_INITIAL_DP
    back = inap.InitialDpArg.decode(wire)
    assert back.service_key == 42
    assert back.called_party_number == bytes([0x03, 0x15, 0x55, 0x01, 0x23])
    assert back.calling_partys_category == bytes([0x0A])
    assert back.ip_available == bytes([0x01])
    assert back.event_type_bcsm == inap.EventTypeBcsm.CollectedInfo
    assert back.encode() == wire


def test_initial_dp_minimal() -> None:
    idp = inap.InitialDpArg(1)
    back = inap.InitialDpArg.decode(idp.encode())
    assert back.service_key == 1
    assert back.called_party_number is None
    assert back.event_type_bcsm is None


def test_connect_known_answer_and_round_trip() -> None:
    c = inap.ConnectArg([bytes([0x03, 0x15, 0x55, 0x01, 0x23])])
    assert c.encode() == KAT_CONNECT
    back = inap.ConnectArg.decode(c.encode())
    assert back.destination_routing_address == [bytes([0x03, 0x15, 0x55, 0x01, 0x23])]


def test_connect_multiple_addresses() -> None:
    addrs = [bytes([0x03, 0x15, 0x55, 0x01, 0x01]), bytes([0x03, 0x15, 0x55, 0x01, 0x02])]
    c = inap.ConnectArg(addrs)
    back = inap.ConnectArg.decode(c.encode())
    assert back.destination_routing_address == addrs


def test_release_call_known_answer() -> None:
    # INAP CS-1 releaseCall is a bare Cause OCTET STRING (tag 0x04), not a SEQUENCE.
    rel = inap.ReleaseCallArg(bytes([0x90, 0x03]))
    assert rel.encode() == KAT_RELEASE_CALL
    back = inap.ReleaseCallArg.decode(rel.encode())
    assert back.cause == bytes([0x90, 0x03])


def test_request_report_bcsm_known_answer_and_round_trip() -> None:
    r = inap.RequestReportBcsmEventArg(
        [
            inap.BcsmEvent(
                inap.EventTypeBcsm.OAnswer,
                inap.MonitorMode.NotifyAndContinue,
            ),
        ]
    )
    assert r.encode() == KAT_RRBE
    back = inap.RequestReportBcsmEventArg.decode(r.encode())
    assert len(back.bcsm_events) == 1
    assert back.bcsm_events[0].event_type_bcsm == inap.EventTypeBcsm.OAnswer
    assert back.bcsm_events[0].monitor_mode == inap.MonitorMode.NotifyAndContinue


def test_request_report_bcsm_with_leg_and_criteria() -> None:
    r = inap.RequestReportBcsmEventArg(
        [
            inap.BcsmEvent(
                inap.EventTypeBcsm.ONoAnswer,
                inap.MonitorMode.Interrupted,
                sending_side_id=bytes([0x02]),
                application_timer=30,
            ),
        ]
    )
    # Hand-assembled from the ASN.1: legID [2] and dPSpecificCriteria [30] are
    # CHOICEs, so both are explicit, constructed wrappers (a2 / be).
    assert r.encode() == bytes.fromhex("3014a0123010800106810100a203800102be0381011e")
    back = inap.RequestReportBcsmEventArg.decode(r.encode())
    assert back.bcsm_events[0].sending_side_id == bytes([0x02])
    assert back.bcsm_events[0].receiving_side_id is None
    assert back.bcsm_events[0].application_timer == 30
    assert back.bcsm_events[0].number_of_digits is None


def test_request_report_bcsm_refuses_the_encoding_of_1_x() -> None:
    # legID as a primitive [2]: not a LegID. rasn alone would hand back the
    # event without its leg.
    with pytest.raises(inap.InapCodecError):
        inap.RequestReportBcsmEventArg.decode(
            bytes.fromhex("300da00b300980010981010082" "0102")
        )


def test_bcsm_event_refuses_two_alternatives_of_a_choice() -> None:
    with pytest.raises(ValueError):
        inap.BcsmEvent(
            inap.EventTypeBcsm.ODisconnect,
            inap.MonitorMode.Interrupted,
            sending_side_id=bytes([0x01]),
            receiving_side_id=bytes([0x02]),
        )
    with pytest.raises(ValueError):
        inap.BcsmEvent(
            inap.EventTypeBcsm.ONoAnswer,
            inap.MonitorMode.Interrupted,
            number_of_digits=4,
            application_timer=30,
        )


def test_event_report_bcsm_known_answer_and_round_trip() -> None:
    e = inap.EventReportBcsmArg(inap.EventTypeBcsm.OAnswer)
    assert e.encode() == KAT_ERB
    back = inap.EventReportBcsmArg.decode(e.encode())
    assert back.event_type_bcsm == inap.EventTypeBcsm.OAnswer
    assert back.message_type is None
    assert back.receiving_side_id is None


def test_event_report_bcsm_disconnect() -> None:
    e = inap.EventReportBcsmArg(
        inap.EventTypeBcsm.ODisconnect,
        event_specific_information_bcsm=bytes.fromhex("a70480028090"),
        receiving_side_id=bytes([0x02]),
        message_type=1,
    )
    # 30 15  80 01 09  a2 06 a7 04 80 02 80 90  a3 03 81 01 02  a4 03 80 01 01
    wire = bytes.fromhex("3015800109a206a70480028090a303810102a403800101")
    assert e.encode() == wire
    back = inap.EventReportBcsmArg.decode(wire)
    assert back.event_specific_information_bcsm == bytes.fromhex("a70480028090")
    assert back.receiving_side_id == bytes([0x02])
    assert back.sending_side_id is None
    assert back.message_type == 1


def test_event_report_bcsm_refuses_malformed_members() -> None:
    # Not an EventSpecificInformationBCSM alternative.
    with pytest.raises(inap.InapCodecError):
        inap.EventReportBcsmArg(
            inap.EventTypeBcsm.ODisconnect,
            event_specific_information_bcsm=bytes.fromhex("bf2a00"),
        )
    with pytest.raises(ValueError):
        inap.EventReportBcsmArg(inap.EventTypeBcsm.OAnswer, message_type=2)
    # legID [3] holding an alternative LegID does not have: rasn reports the
    # member as absent, this codec refuses the message.
    with pytest.raises(inap.InapCodecError):
        inap.EventReportBcsmArg.decode(bytes.fromhex("3008800109a303850102"))


def test_decode_refuses_members_the_class_does_not_expose() -> None:
    # An InitialDP with redirectingPartyID [29]: valid, and InitialDpArg has no
    # attribute for it. Dropping it silently would be data loss.
    with pytest.raises(inap.InapCodecError, match="does not expose"):
        inap.InitialDpArg.decode(bytes.fromhex("300b80012a9d06041351551077"))
    # A Connect with callingPartysCategory [28].
    with pytest.raises(inap.InapCodecError, match="does not expose"):
        inap.ConnectArg.decode(bytes.fromhex("300ba006040404102143" "9c010a"))
    # An ApplyCharging whose partyToCharge is a receivingSideID.
    with pytest.raises(inap.InapCodecError, match="does not expose"):
        inap.ApplyChargingArg.decode(bytes.fromhex("300a8003000102a203810101"))


def test_apply_charging_known_answer_and_round_trip() -> None:
    a = inap.ApplyChargingArg(
        bytes([0x00, 0x01, 0x02]), party_to_charge=bytes([0x01])
    )
    assert a.encode() == KAT_APPLY_CHARGING
    back = inap.ApplyChargingArg.decode(a.encode())
    assert back.ach_billing_charging_characteristics == bytes([0x00, 0x01, 0x02])
    assert back.party_to_charge == bytes([0x01])


def test_decode_rejects_garbage() -> None:
    with pytest.raises(inap.InapCodecError):
        inap.InitialDpArg.decode(b"\xff\xff\xff\xff")


def test_decode_rejects_truncated() -> None:
    good = inap.ReleaseCallArg(bytes([0x90, 0x03])).encode()
    with pytest.raises(inap.InapCodecError):
        inap.ReleaseCallArg.decode(good[:1])


def test_called_party_number_encoder() -> None:
    # International E.164, checked against the Q.763 §3.9 format.
    assert inap.international_e164("15550199") == bytes(
        [0x04, 0x10, 0x51, 0x55, 0x10, 0x99]
    )
    # Odd length → O/E bit set (octet1 0x84), trailing 0x0 filler nibble.
    assert inap.international_e164("155501999") == bytes(
        [0x84, 0x10, 0x51, 0x55, 0x10, 0x99, 0x09]
    )
    # National number with the INN indicator set (octet2 0x90).
    assert inap.called_party_number(
        "15550199", inap.NATURE_NATIONAL, inap.PLAN_ISDN, True
    ) == bytes([0x03, 0x90, 0x51, 0x55, 0x10, 0x99])
    # The encoded number drops straight into a Connect destinationRoutingAddress.
    dra = inap.international_e164("15550199")
    c = inap.ConnectArg([dra])
    assert inap.ConnectArg.decode(c.encode()).destination_routing_address == [dra]
    with pytest.raises(inap.InapCodecError):
        inap.international_e164("1555#199")
