//! Known-answer vectors for the INAP CS-1 codec.
//!
//! Each `WIRE_*` constant below is a full **SCCP UnitData → TCAP Begin/Invoke →
//! INAP argument** message (INAP SSN 106). Every one of these exact byte strings
//! was dissected with `tshark` (Wireshark's INAP dissector, which knows the CS-1
//! operation codes, application contexts and argument layouts): each reports the
//! correct INAP operation and decoded fields with **no** "Malformed" / "BER
//! Error" expert info. They are the independent oracle, these tests then peel
//! the same bytes back apart with this crate (SCCP + TCAP dev-deps) and assert
//! the operation code and the decoded INAP argument, so a shared encode/decode
//! bug cannot pass unnoticed (as a bare round-trip could).
//!
//! All values are **synthetic**: fictional `+1-555-01xx` GT digits and address
//! signals, made-up service keys. Nothing here is captured traffic.

use rasn::types::Integer;

use inap::op_codes;
use inap::operations::{
    ApplyChargingArg, CallInformationReportArg, ConnectArg, ConnectToResourceArg,
    EventReportBcsmArg, InitialDpArg, PlayAnnouncementArg, PromptAndCollectUserInformationArg,
    ReleaseCallArg, RequestReportBcsmEventArg,
};
use inap::types::{
    EventTypeBcsm, LegId, MonitorMode, RequestedInformationType, RequestedInformationValue,
};

use tcap::{Component, TcapMessage};

// ── tshark-validated full-stack wire vectors (SCCP UDT / SSN 106) ────────────

const WIRE_INITIAL_DP: &str = "0900030e190b126a0011045155109900f10b126a0011045155100021f34a62484804000010016c40a13e020101020100303680012a820503155501238305031555019985010a8801018901018a05031555011197029181980101990503155501889a0200019c0102";
const WIRE_CONNECT: &str = "0900030e190b126a0011045155109900f10b126a0011045155100021f32462224804000010016c1aa1180201010201143010a0070405031555012386050315550100";
const WIRE_RELEASE_CALL: &str = "0900030e190b126a0011045155109900f10b126a0011045155100021f31662144804000010016c0ca10a02010102011604029003";
const WIRE_CONNECT_TO_RESOURCE: &str = "0900030e190b126a0011045155109900f10b126a0011045155100021f31b62194804000010016c11a10f020101020113300780050315550177";
const WIRE_RRBE: &str = "0900030e190b126a0011045155109900f10b126a0011045155100021f32662244804000010016c1ca11a0201010201173012a01030068001078101013006800109810100";
const WIRE_ERB: &str = "0900030e190b126a0011045155109900f10b126a0011045155100021f31c621a4804000010016c12a1100201010201183008800107a303810102";
const WIRE_APPLY_CHARGING: &str = "0900030e190b126a0011045155109900f10b126a0011045155100021f31e621c4804000010016c14a112020101020123300a8003000102a203800101";
const WIRE_CALL_INFO_REPORT: &str = "0900030e190b126a0011045155109900f10b126a0011045155100021f32c622a4804000010016c22a12002010102012c3018a0163009800102a104820204b0300980011ea1049e029010";
const WIRE_PLAY_ANNOUNCEMENT: &str = "0900030e190b126a0011045155109900f10b126a0011045155100021f321621f4804000010016c17a11502010102012f300d8005a1038001078101ff8201ff";
const WIRE_PROMPT_COLLECT: &str = "0900030e190b126a0011045155109900f10b126a0011045155100021f31e621c4804000010016c14a112020101020130300a8005a00381010a810100";

/// Argument-less / NULL operations, validated to dissect as the named INAP
/// operation with no argument (or a bare NULL). `(name, opcode, wire)`.
const WIRE_ARGLESS: &[(&str, i64, &str)] = &[
    ("continue", op_codes::CONTINUE, "0900030e190b126a0011045155109900f10b126a0011045155100021f31262104804000010016c08a10602010102011f"),
    ("disconnectForwardConnection", op_codes::DISCONNECT_FORWARD_CONNECTION, "0900030e190b126a0011045155109900f10b126a0011045155100021f31262104804000010016c08a106020101020112"),
    ("activityTest", op_codes::ACTIVITY_TEST, "0900030e190b126a0011045155109900f10b126a0011045155100021f31262104804000010016c08a106020101020137"),
    ("collectInformation", op_codes::COLLECT_INFORMATION, "0900030e190b126a0011045155109900f10b126a0011045155100021f31262104804000010016c08a10602010102011b"),
    ("specializedResourceReport", op_codes::SPECIALIZED_RESOURCE_REPORT, "0900030e190b126a0011045155109900f10b126a0011045155100021f31462124804000010016c0aa1080201010201310500"),
];

// ── Peeling helpers: SCCP UDT → TCAP Begin → first Invoke ────────────────────

/// Peel the SCCP UnitData + TCAP Begin framing and return `(operation_code,
/// argument_bytes)` from the first Invoke component.
fn peel(wire_hex: &str) -> (i64, Vec<u8>) {
    let wire = hex::decode(wire_hex).expect("hex");
    let udt = sccp::UnitData::decode(&wire).expect("sccp udt");
    let msg = tcap::decode(&udt.data).expect("tcap");
    let components = match msg {
        TcapMessage::Begin(b) => b.components.expect("components"),
        other => panic!("expected Begin, got {other}"),
    };
    match &components[0] {
        Component::Invoke(inv) => {
            let op = match inv.operation_code {
                tcap::OperationCode::Local(v) => v,
                ref other => panic!("expected Local opcode, got {other:?}"),
            };
            let arg = inv
                .parameter
                .as_ref()
                .map(|p| p.as_bytes().to_vec())
                .unwrap_or_default();
            (op, arg)
        }
        other => panic!("expected Invoke, got {other}"),
    }
}

fn decode_arg<T: rasn::Decode>(wire_hex: &str, expected_op: i64) -> T {
    let (op, arg) = peel(wire_hex);
    assert_eq!(op, expected_op, "operation code");
    inap::decode(&arg).expect("inap decode")
}

// ── Per-operation known-answer assertions ────────────────────────────────────

#[test]
fn initial_dp_decodes_fixed_network_fields() {
    let (op, _) = peel(WIRE_INITIAL_DP);
    assert_eq!(op, op_codes::INITIAL_DP);
    assert_eq!(op_codes::operation_name(op), Some("initialDP"));

    let idp: InitialDpArg = decode_arg(WIRE_INITIAL_DP, op_codes::INITIAL_DP);
    assert_eq!(idp.service_key, Integer::from(42));
    assert_eq!(
        idp.called_party_number.as_deref(),
        Some(&[0x03, 0x15, 0x55, 0x01, 0x23][..])
    );
    assert_eq!(idp.calling_partys_category.as_deref(), Some(&[0x0a][..]));
    // INAP fixed-network IEs (absent from the CAMEL profile).
    assert_eq!(idp.ip_available.as_deref(), Some(&[0x01][..]));
    assert_eq!(
        idp.service_interaction_indicators.as_deref(),
        Some(&[0x01][..])
    );
    assert_eq!(
        idp.forward_call_indicators.as_deref(),
        Some(&[0x00, 0x01][..])
    );
    assert_eq!(idp.event_type_bcsm, Some(EventTypeBcsm::CollectedInfo));
}

#[test]
fn connect_decodes_routing_address() {
    let c: ConnectArg = decode_arg(WIRE_CONNECT, op_codes::CONNECT);
    assert_eq!(c.destination_routing_address.len(), 1);
    assert_eq!(
        &c.destination_routing_address[0][..],
        &[0x03, 0x15, 0x55, 0x01, 0x23]
    );
    assert_eq!(
        c.original_called_party_id.as_deref(),
        Some(&[0x03, 0x15, 0x55, 0x01, 0x00][..])
    );
}

#[test]
fn release_call_decodes_bare_cause() {
    // INAP CS-1 releaseCall carries a bare Cause (Q.850), not a SEQUENCE.
    let (op, arg) = peel(WIRE_RELEASE_CALL);
    assert_eq!(op, op_codes::RELEASE_CALL);
    // The argument is a primitive OCTET STRING: tag 0x04, length 2.
    assert_eq!(arg[0], 0x04);
    let rel: ReleaseCallArg = inap::decode(&arg).expect("decode");
    assert_eq!(&rel.0[..], &[0x90, 0x03]);
}

#[test]
fn connect_to_resource_decodes_ip_routing_address() {
    let c: ConnectToResourceArg =
        decode_arg(WIRE_CONNECT_TO_RESOURCE, op_codes::CONNECT_TO_RESOURCE);
    assert_eq!(
        c.resource_address_ipv4.as_deref(),
        Some(&[0x03, 0x15, 0x55, 0x01, 0x77][..])
    );
    assert!(c.resource_address_none.is_none());
}

#[test]
fn request_report_bcsm_decodes_event_list() {
    let r: RequestReportBcsmEventArg = decode_arg(WIRE_RRBE, op_codes::REQUEST_REPORT_BCSM_EVENT);
    assert_eq!(r.bcsm_events.len(), 2);
    assert_eq!(r.bcsm_events[0].event_type_bcsm, EventTypeBcsm::OAnswer);
    assert_eq!(
        r.bcsm_events[0].monitor_mode,
        MonitorMode::NotifyAndContinue
    );
    assert_eq!(r.bcsm_events[1].event_type_bcsm, EventTypeBcsm::ODisconnect);
    assert_eq!(r.bcsm_events[1].monitor_mode, MonitorMode::Interrupted);
}

#[test]
fn event_report_bcsm_decodes_leg_id() {
    let e: EventReportBcsmArg = decode_arg(WIRE_ERB, op_codes::EVENT_REPORT_BCSM);
    assert_eq!(e.event_type_bcsm, EventTypeBcsm::OAnswer);
    match e.leg_id {
        Some(LegId::ReceivingSideId(v)) => assert_eq!(&v[..], &[0x02]),
        other => panic!("expected receivingSideID, got {other:?}"),
    }
}

#[test]
fn apply_charging_decodes_party_to_charge() {
    let a: ApplyChargingArg = decode_arg(WIRE_APPLY_CHARGING, op_codes::APPLY_CHARGING);
    assert_eq!(
        &a.ach_billing_charging_characteristics[..],
        &[0x00, 0x01, 0x02]
    );
    match a.party_to_charge {
        Some(LegId::SendingSideId(v)) => assert_eq!(&v[..], &[0x01]),
        other => panic!("expected sendingSideID, got {other:?}"),
    }
}

#[test]
fn call_information_report_decodes_nested_choice_values() {
    let r: CallInformationReportArg =
        decode_arg(WIRE_CALL_INFO_REPORT, op_codes::CALL_INFORMATION_REPORT);
    assert_eq!(r.requested_information_list.len(), 2);
    let first = &r.requested_information_list[0];
    assert_eq!(
        first.requested_information_type,
        RequestedInformationType::CallConnectedElapsedTime
    );
    match &first.requested_information_value {
        RequestedInformationValue::CallConnectedElapsedTimeValue(v) => {
            assert_eq!(v, &Integer::from(1200))
        }
        other => panic!("unexpected value {other:?}"),
    }
    let second = &r.requested_information_list[1];
    match &second.requested_information_value {
        RequestedInformationValue::ReleaseCauseValue(c) => assert_eq!(&c[..], &[0x90, 0x10]),
        other => panic!("unexpected value {other:?}"),
    }
}

#[test]
fn play_announcement_decodes_information_to_send() {
    let p: PlayAnnouncementArg = decode_arg(WIRE_PLAY_ANNOUNCEMENT, op_codes::PLAY_ANNOUNCEMENT);
    // informationToSend is an opaque octet string carrying an encoded
    // InformationToSend CHOICE (tshark dissects it as tone/toneID=7).
    assert_eq!(&p.information_to_send[..], &[0xa1, 0x03, 0x80, 0x01, 0x07]);
    assert_eq!(p.disconnect_from_ip_forbidden, Some(true));
    assert_eq!(p.request_announcement_complete, Some(true));
}

#[test]
fn prompt_and_collect_decodes_collected_info() {
    let p: PromptAndCollectUserInformationArg = decode_arg(
        WIRE_PROMPT_COLLECT,
        op_codes::PROMPT_AND_COLLECT_USER_INFORMATION,
    );
    // collectedInfo is an opaque octet string carrying an encoded CollectedInfo
    // CHOICE (tshark dissects it as collectedDigits/maximumNbOfDigits=10).
    assert_eq!(&p.collected_info[..], &[0xa0, 0x03, 0x81, 0x01, 0x0a]);
    assert_eq!(p.disconnect_from_ip_forbidden, Some(false));
}

#[test]
fn argless_operations_carry_the_right_opcode() {
    for (name, opcode, wire) in WIRE_ARGLESS {
        let (op, arg) = peel(wire);
        assert_eq!(op, *opcode, "{name} opcode");
        assert_eq!(op_codes::operation_name(op), Some(*name), "{name} name");
        // continue / disconnectForwardConnection / activityTest / collectInformation
        // carry no argument; specializedResourceReport carries a bare NULL (05 00).
        if *name == "specializedResourceReport" {
            assert_eq!(arg, vec![0x05, 0x00]);
        } else {
            assert!(arg.is_empty(), "{name} should have no argument");
        }
    }
}
