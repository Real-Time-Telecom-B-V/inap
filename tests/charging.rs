//! ApplyCharging (op 35), ApplyChargingReport (op 36),
//! FurnishChargingInformation (op 34), CallInformationRequest (op 45) and
//! CallInformationReport (op 44): ETS 300 374-1 (September 1994) clause 6.3
//! and ITU-T Q.1218 (10/95) clause 2.1.3.
//!
//! Vectors are assembled by hand from the ASN.1; `tests/bcsm_events.rs`
//! explains the tag octet rules and `tests/call_control.rs` the synthetic
//! numbers.

mod common;

use common::{dissect, dissect_unchecked, extensions, known_answer, octets, vector, EXTENSION};
use inap::op_codes;
use inap::operations::{
    ApplyChargingArg, ApplyChargingReportArg, CallInformationReportArg, CallInformationRequestArg,
    FurnishChargingInformationArg,
};
use inap::types::{
    LegId, RequestedInformation, RequestedInformationType, RequestedInformationValue,
};
use rasn::types::Integer;

use common::Carrier::Continue;

// ── ApplyCharging ───────────────────────────────────────────────────────────

#[test]
fn apply_charging_with_party_and_extensions() {
    let arg = ApplyChargingArg {
        party_to_charge: Some(LegId::sending(1)),
        extensions: Some(extensions()),
        ..ApplyChargingArg::new(octets("01 02 03"))
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 19                                  -- 5 + 5 + 15 = 25
           80 03 01 02 03                      -- aChBillingChargingCharacteristics [0]
           a2 03                               -- partyToCharge [2]: LegID is a CHOICE, EXPLICIT
              80 01 01                         --   sendingSideID [0] leg 1
           a3 0d                               -- extensions [3]
              {EXTENSION}
        "
        ),
    );
    let Some(d) = dissect(op_codes::APPLY_CHARGING, Some(&ber), Continue) else {
        return;
    };
    d.hex("inap.aChBillingChargingCharacteristics", "010203")
        .show("inap.partyToCharge", "0")
        .hex("inap.sendingSideID", "01")
        .show("inap.extensions", "1");
}

#[test]
fn apply_charging_send_calculation_to_scp_indication() {
    // sendCalculationToSCPIndication [1] BOOLEAN DEFAULT FALSE is in ETS
    // 300 374-1 ("shall always be set to TRUE") and not in Q.1218.
    let arg = ApplyChargingArg {
        send_calculation_to_scp_indication: Some(true),
        party_to_charge: Some(LegId::sending(1)),
        ..ApplyChargingArg::new(octets("01 02 03"))
    };
    let ber = known_answer(
        &arg,
        "
        30 0d                                  -- 5 + 3 + 5 = 13
           80 03 01 02 03                      -- aChBillingChargingCharacteristics
           81 01 ff                            -- sendCalculationToSCPIndication [1] TRUE
           a2 03 80 01 01                      -- partyToCharge: sendingSideID leg 1
        ",
    );
    // Wireshark's copy of the ASN.1 is the ITU-T capability set 4 module,
    // which has no member on [1] (its comment: "The TAG value 1 should not be
    // used for future extensions (used in CS-1 by regions)"). It therefore
    // reports the member as lying beyond the known sequence. That is the only
    // complaint it may have; this member is pinned by the vector alone.
    let Some(d) = dissect_unchecked(op_codes::APPLY_CHARGING, Some(&ber), Continue) else {
        return;
    };
    d.hex("inap.aChBillingChargingCharacteristics", "010203");
    let unrelated: Vec<String> = d
        .problems()
        .into_iter()
        .filter(|p| !p.contains("beyond the end of the known sequence definition"))
        .filter(|p| {
            !p.starts_with("_ws.expert.severity")
                && !p.starts_with("_ws.expert.group")
                && !p.starts_with("_ws.malformed")
        })
        .collect();
    assert!(unrelated.is_empty(), "{unrelated:?}");
}

#[test]
fn apply_charging_as_encoded_by_1_x_still_decodes() {
    let old = vector("30 0a 80 03 00 01 02 a2 03 80 01 01");
    let arg: ApplyChargingArg = inap::decode(&old).unwrap();
    assert_eq!(arg.party_to_charge, Some(LegId::sending(1)));
    assert_eq!(inap::encode(&arg).unwrap(), old);
}

// ── ApplyChargingReport, FurnishChargingInformation ─────────────────────────

#[test]
fn apply_charging_report_is_a_bare_call_result() {
    // ApplyChargingReportArg ::= CallResult, a network operator specific
    // OCTET STRING.
    let ber = known_answer(
        &ApplyChargingReportArg(octets("01 02 03")),
        "04 03 01 02 03",
    );
    let Some(d) = dissect(op_codes::APPLY_CHARGING_REPORT, Some(&ber), Continue) else {
        return;
    };
    d.hex("inap.ApplyChargingReportArg", "010203");
}

#[test]
fn furnish_charging_information_is_a_bare_octet_string() {
    // FurnishChargingInformationArg ::= FCIBillingChargingCharacteristics.
    let ber = known_answer(
        &FurnishChargingInformationArg(octets("01 02 03")),
        "04 03 01 02 03",
    );
    let Some(d) = dissect(op_codes::FURNISH_CHARGING_INFORMATION, Some(&ber), Continue) else {
        return;
    };
    d.hex("inap.FurnishChargingInformationArg", "010203");
}

// ── CallInformationRequest ──────────────────────────────────────────────────

#[test]
fn call_information_request_with_every_type() {
    let arg = CallInformationRequestArg {
        extensions: Some(extensions()),
        ..CallInformationRequestArg::new(vec![
            RequestedInformationType::CallAttemptElapsedTime,
            RequestedInformationType::CallStopTime,
            RequestedInformationType::CallConnectedElapsedTime,
            RequestedInformationType::CalledAddress,
            RequestedInformationType::ReleaseCause,
        ])
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 20                                  -- 17 + 15 = 32
           a0 0f                               -- requestedInformationTypeList [0] SEQUENCE OF
              0a 01 00                         --   callAttemptElapsedTime(0), plain ENUMERATED
              0a 01 01                         --   callStopTime(1)
              0a 01 02                         --   callConnectedElapsedTime(2)
              0a 01 03                         --   calledAddress(3)
              0a 01 1e                         --   releaseCause(30)
           a2 0d                               -- extensions [2]
              {EXTENSION}
        "
        ),
    );
    let Some(d) = dissect(op_codes::CALL_INFORMATION_REQUEST, Some(&ber), Continue) else {
        return;
    };
    d.show("inap.requestedInformationTypeList", "5")
        .show_all("inap.RequestedInformationType", &["0", "1", "2", "3", "30"])
        .show("inap.extensions", "1")
        .absent("inap.legID");
}

#[test]
fn call_information_request_members_outside_core_inap() {
    // correlationID [1] is Q.1218 only; legID [3] is a capability set 2 member
    // (EN 301 140-1 V1.3.4 clause 6.1) that 1.x already had.
    let arg = CallInformationRequestArg {
        correlation_id: Some(octets("00 21 43")),
        leg_id: Some(LegId::sending(2)),
        ..CallInformationRequestArg::new(vec![RequestedInformationType::ReleaseCause])
    };
    let ber = known_answer(
        &arg,
        "
        30 0f                                  -- 5 + 5 + 5
           a0 03 0a 01 1e                      -- releaseCause(30)
           81 03 00 21 43                      -- correlationID [1]
           a3 03                               -- legID [3]: CHOICE, EXPLICIT
              80 01 02                         --   sendingSideID leg 2
        ",
    );
    let Some(d) = dissect(op_codes::CALL_INFORMATION_REQUEST, Some(&ber), Continue) else {
        return;
    };
    d.hex("inap.correlationID", "002143")
        .show("inap.legID", "0")
        .hex("inap.sendingSideID", "02");
}

// ── CallInformationReport ───────────────────────────────────────────────────

fn item(
    requested_information_type: RequestedInformationType,
    requested_information_value: RequestedInformationValue,
) -> RequestedInformation {
    RequestedInformation {
        requested_information_type,
        requested_information_value,
    }
}

#[test]
fn call_information_report_with_every_value() {
    let arg = CallInformationReportArg {
        extensions: Some(extensions()),
        ..CallInformationReportArg::new(vec![
            item(
                RequestedInformationType::CallAttemptElapsedTime,
                RequestedInformationValue::CallAttemptElapsedTimeValue(7.into()),
            ),
            item(
                RequestedInformationType::CallStopTime,
                RequestedInformationValue::CallStopTimeValue(octets("39 90 03 21 51 10")),
            ),
            item(
                RequestedInformationType::CallConnectedElapsedTime,
                RequestedInformationValue::CallConnectedElapsedTimeValue(1200.into()),
            ),
            item(
                RequestedInformationType::CalledAddress,
                RequestedInformationValue::CalledAddressValue(octets("00 04 13 51 55 10")),
            ),
            item(
                RequestedInformationType::ReleaseCause,
                RequestedInformationValue::ReleaseCauseValue(octets("80 90")),
            ),
        ])
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 4f                                  -- 64 + 15 = 79
           a0 3e                               -- requestedInformationList [0], 10+15+11+15+11 = 62
              30 08                            --   RequestedInformation
                 80 01 00                      --     type callAttemptElapsedTime(0)
                 a1 03                         --     value [1]: CHOICE, EXPLICIT
                    80 01 07                   --       callAttemptElapsedTimeValue [0] 7 s
              30 0d
                 80 01 01                      --     type callStopTime(1)
                 a1 08
                    81 06 39 90 03 21 51 10    --       callStopTimeValue [1]: 1993-09-30 12:15:01,
                                               --       the example of ETS 300 374-1
              30 09
                 80 01 02                      --     type callConnectedElapsedTime(2)
                 a1 04
                    82 02 04 b0                --       callConnectedElapsedTimeValue [2] 1200
              30 0d
                 80 01 03                      --     type calledAddress(3)
                 a1 08
                    83 06 00 04 13 51 55 10    --       calledAddressValue [3], a generic number
              30 09
                 80 01 1e                      --     type releaseCause(30)
                 a1 04
                    9e 02 80 90                --       releaseCauseValue [30]
           a2 0d                               -- extensions [2]
              {EXTENSION}
        "
        ),
    );
    let Some(d) = dissect(op_codes::CALL_INFORMATION_REPORT, Some(&ber), Continue) else {
        return;
    };
    d.show("inap.requestedInformationList", "5")
        .show_all("inap.requestedInformationType", &["0", "1", "2", "3", "30"])
        .show_all(
            "inap.requestedInformationValue",
            &["0", "1", "2", "3", "30"],
        )
        .show("inap.callAttemptElapsedTimeValue", "7")
        .hex("inap.callStopTimeValue", "399003215110")
        .show("inap.callConnectedElapsedTimeValue", "1200")
        .hex("inap.calledAddressValue", "000413515510")
        .hex("inap.releaseCauseValue", "8090")
        .show("inap.cause_indicator", "16")
        .show("inap.extensions", "1");
}

#[test]
fn call_information_report_members_outside_core_inap() {
    let arg = CallInformationReportArg {
        correlation_id: Some(octets("00 21 43")),
        leg_id: Some(LegId::receiving(2)),
        ..CallInformationReportArg::new(vec![item(
            RequestedInformationType::CallConnectedElapsedTime,
            RequestedInformationValue::CallConnectedElapsedTimeValue(1200.into()),
        )])
    };
    let ber = known_answer(
        &arg,
        "
        30 17                                  -- 13 + 5 + 5 = 23
           a0 0b 30 09 80 01 02 a1 04 82 02 04 b0
           81 03 00 21 43                      -- correlationID [1], Q.1218 only
           a3 03 81 01 02                      -- legID [3], CS-2: receivingSideID leg 2
        ",
    );
    let Some(d) = dissect(op_codes::CALL_INFORMATION_REPORT, Some(&ber), Continue) else {
        return;
    };
    d.hex("inap.correlationID", "002143")
        .show("inap.legID", "1")
        .hex("inap.receivingSideID", "02");
}

#[test]
fn call_information_report_as_encoded_by_1_x_still_decodes() {
    let old =
        vector("30 18 a0 16 30 09 80 01 02 a1 04 82 02 04 b0 30 09 80 01 1e a1 04 9e 02 90 10");
    let arg: CallInformationReportArg = inap::decode(&old).unwrap();
    assert_eq!(arg.requested_information_list.len(), 2);
    assert_eq!(
        arg.requested_information_list[0].requested_information_value,
        RequestedInformationValue::CallConnectedElapsedTimeValue(Integer::from(1200))
    );
    assert_eq!(inap::encode(&arg).unwrap(), old);
}
