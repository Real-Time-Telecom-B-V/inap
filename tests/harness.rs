//! The Wireshark harness itself: it must accept what is right, reject what is
//! wrong, report fields rather than a bare "no crash", and reach the INAP
//! dissector the way a real dialogue does.
//!
//! All values are synthetic.

mod common;

use common::{
    dissect, dissect_frame, dissect_unchecked, m3ua_frame_with_ssn, tcap_message, Carrier,
};
use inap::operations::ReleaseCallArg;
use inap::{application_context, op_codes};
use rasn::types::ObjectIdentifier;

/// A subsystem number no Wireshark dissector claims for TCAP, so that only the
/// application context can select the upper layer.
const NEUTRAL_SSN: u8 = 12;

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

fn upper_layer(context: &ObjectIdentifier) -> Option<(bool, Vec<String>)> {
    let tcap = tcap_message(op_codes::CONTINUE, None, &Carrier::Begin(context));
    let d = dissect_frame(&m3ua_frame_with_ssn(tcap, NEUTRAL_SSN))?;
    let names = d
        .shows("tcap.aarq_application_context_name")
        .into_iter()
        .map(str::to_string)
        .collect();
    Some((d.fields.iter().any(|f| f.name == "inap"), names))
}

#[test]
fn inap_is_selected_by_the_application_context_alone() {
    // With a subsystem number nobody claims, the application context in the
    // AARQ is all Wireshark has to go by. It registers 0.4.0.1.1.1.0.0 for
    // INAP under the name "cs1-ssp-to-scp". (It registers none of the other
    // Core INAP contexts, so those are checked against ETS 300 374-1 only, in
    // tests/application_context.rs.)
    let Some((is_inap, names)) = upper_layer(&application_context::cs1_ssp_to_scp()) else {
        return;
    };
    assert!(is_inap, "the context did not select INAP");
    assert_eq!(names, ["0.4.0.1.1.1.0.0"]);
}

#[test]
fn the_identifier_used_before_2_0_0_does_not_select_inap() {
    // 0.4.0.1.1.0.3.0 is what `cs1_ssp_to_scp()` returned until 2.0.0. It is
    // the identifier of the ASN.1 module Core-INAP-CS1-Codes, and Wireshark
    // knows it under that name and does not treat it as an INAP context.
    let Some((is_inap, names)) = upper_layer(&application_context::core_inap_cs1_codes()) else {
        return;
    };
    assert!(!is_inap, "a module identifier selected INAP");
    assert_eq!(names, ["0.4.0.1.1.0.3.0"]);
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
