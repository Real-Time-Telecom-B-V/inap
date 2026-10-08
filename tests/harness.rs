//! The Wireshark harness itself: it must accept what is right, reject what is
//! wrong, report fields rather than a bare "no crash", and reach the INAP
//! dissector the way a real dialogue does.
//!
//! All values are synthetic.

mod common;

use common::{dissect, dissect_unchecked, Carrier};
use inap::op_codes;
use inap::operations::ReleaseCallArg;

#[test]
fn release_call_is_dissected_as_a_bare_cause() {
    // Cause, ITU-T Q.850 as carried in ISUP (Q.763 3.12): 0x80 = no extension,
    // coding standard ITU-T, location "user"; 0x90 = no extension, cause 16
    // (normal call clearing).
    let ber = inap::encode(&ReleaseCallArg(vec![0x80, 0x90].into())).unwrap();
    // ReleaseCallArg ::= Cause, an OCTET STRING: universal tag 4, length 2.
    assert_eq!(ber, [0x04, 0x02, 0x80, 0x90]);

    let Some(d) = dissect(op_codes::RELEASE_CALL, Some(&ber), Carrier::Continue) else {
        return;
    };
    // Wireshark's copy is capability set 4, where the argument became a CHOICE
    // whose first alternative is the bare Cause of capability set 1.
    d.hex("inap.initialCallSegment", "8090")
        .show("inap.cause_indicator", "16");
}

#[test]
fn harness_rejects_a_release_call_wrapped_in_a_sequence() {
    // If the harness let a SEQUENCE { OCTET STRING } through where a bare
    // OCTET STRING belongs, it would be worthless as an oracle.
    let wrapped = [0x30, 0x04, 0x04, 0x02, 0x80, 0x90];
    let Some(d) = dissect_unchecked(op_codes::RELEASE_CALL, Some(&wrapped), Carrier::Continue)
    else {
        return;
    };
    assert!(
        !d.problems().is_empty(),
        "Wireshark should reject a SEQUENCE-wrapped releaseCall\n{}",
        d.summary()
    );
    assert!(d.values("inap.initialCallSegment").is_empty());
}

#[test]
fn harness_rejects_an_unknown_operation_code() {
    // Wireshark only looks the operation up when there is an argument to
    // dissect, so give it one.
    let Some(d) = dissect_unchecked(250, Some(&[0x05, 0x00]), Carrier::Continue) else {
        return;
    };
    assert!(!d.problems().is_empty(), "{}", d.summary());
}

#[test]
fn inap_is_selected_by_subsystem_number_without_a_dialogue_portion() {
    // A Continue has no dialogue portion. Wireshark then goes by the SCCP
    // subsystem number: 106 is in the INAP dissector's default range.
    let Some(d) = dissect(op_codes::CONTINUE, None, Carrier::Continue) else {
        return;
    };
    d.present("inap").show("inap.code.local", "31");
}

#[test]
fn operations_without_an_argument_are_recognised() {
    // continue, disconnectForwardConnection and activityTest have no ARGUMENT
    // (ETS 300 374-1 clause 6.1): the Invoke ends after the operation code.
    for operation in [
        op_codes::CONTINUE,
        op_codes::DISCONNECT_FORWARD_CONNECTION,
        op_codes::ACTIVITY_TEST,
    ] {
        let Some(d) = dissect(operation, None, Carrier::Continue) else {
            return;
        };
        d.show("inap.code.local", &operation.to_string());
    }
}

#[test]
fn specialized_resource_report_carries_a_null() {
    // SpecializedResourceReportArg ::= NULL: universal tag 5, length 0.
    let Some(d) = dissect(
        op_codes::SPECIALIZED_RESOURCE_REPORT,
        Some(&[0x05, 0x00]),
        Carrier::Continue,
    ) else {
        return;
    };
    d.show("inap.code.local", "49");
}
