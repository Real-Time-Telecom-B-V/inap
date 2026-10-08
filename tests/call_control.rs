//! InitialDP (op 0), Connect (op 20), ReleaseCall (op 22),
//! EstablishTemporaryConnection (op 17), AssistRequestInstructions (op 16),
//! ResetTimer (op 33) and Cancel (op 53): ETS 300 374-1 (September 1994)
//! clause 6.3 and ITU-T Q.1218 (10/95) clause 2.1.3.
//!
//! Vectors are assembled by hand from the ASN.1; `tests/bcsm_events.rs`
//! explains the tag octet rules. A context tag above 15 on a primitive type is
//! `0x80 | n` up to 30 (`[23]` = 97, `[30]` = 9e); on a constructed one it is
//! `0xa0 | n` (`[15]` = af, `[27]` = bb).
//!
//! All values are synthetic. Numbers are in the fictional +1 555 01xx range:
//!
//! * called party number (Q.763 3.9) `04 10 51 55 10 32`: even number of
//!   digits, international; ISDN numbering plan; digits 1 555 0123.
//! * calling party style numbers (Q.763 3.10) `04 13 51 55 10 xx`:
//!   international; ISDN plan, presentation allowed, network provided.
//! * generic number (Q.763 3.26) `00 04 13 51 55 10 xx`: the same behind a
//!   number qualifier octet.
//! * generic digits (Q.763 3.24) `00 21 43`: BCD even, type 0, digits 1234.

mod common;

use common::{dissect, extensions, known_answer, octets, refused, vector, EXTENSION};
use inap::op_codes;
use inap::operations::{
    AssistRequestInstructionsArg, CancelArg, ConnectArg, EstablishTemporaryConnectionArg,
    InitialDpArg, ReleaseCallArg, ResetTimerArg,
};
use inap::types::{
    BearerCapability, CgEncountered, DpAssignment, EventTypeBcsm, ForwardingCondition, LegId,
    MessageType, MiscCallInfo, TerminalType, TimerId, TriggerType,
};
use rasn::types::Integer;

use common::Carrier::Continue;

// ── InitialDP ───────────────────────────────────────────────────────────────

#[test]
fn initial_dp_with_every_core_inap_member() {
    let arg = InitialDpArg {
        called_party_number: Some(octets("04 10 51 55 10 32")),
        calling_party_number: Some(octets("04 13 51 55 10 99")),
        calling_partys_category: Some(octets("0a")),
        cg_encountered: Some(CgEncountered::ManualCgEncountered),
        ip_ssp_capabilities: Some(octets("01")),
        ip_available: Some(octets("01")),
        location_number: Some(octets("04 13 51 55 10 11")),
        original_called_party_id: Some(octets("04 13 51 55 10 44")),
        extensions: Some(extensions()),
        high_layer_compatibility: Some(octets("91 81")),
        service_interaction_indicators: Some(octets("01")),
        additional_calling_party_number: Some(octets("00 04 13 51 55 10 88")),
        forward_call_indicators: Some(octets("20 01")),
        bearer_capability: Some(BearerCapability::BearerCap(octets("80 90 a3"))),
        event_type_bcsm: Some(EventTypeBcsm::CollectedInfo),
        redirecting_party_id: Some(octets("04 13 51 55 10 77")),
        redirection_information: Some(octets("03 01")),
        ..InitialDpArg::new(42)
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 68                                  -- 104, see the sum below
           80 01 2a                            -- serviceKey [0] 42                        3
           82 06 04 10 51 55 10 32             -- calledPartyNumber [2]                    8
           83 06 04 13 51 55 10 99             -- callingPartyNumber [3]                   8
           85 01 0a                            -- callingPartysCategory [5] ordinary       3
           87 01 01                            -- cGEncountered [7] manualCGencountered    3
           88 01 01                            -- iPSSPCapabilities [8]                    3
           89 01 01                            -- iPAvailable [9]                          3
           8a 06 04 13 51 55 10 11             -- locationNumber [10]                      8
           8c 06 04 13 51 55 10 44             -- originalCalledPartyID [12]               8
           af 0d                               -- extensions [15] SEQUENCE OF             15
              {EXTENSION}
           97 02 91 81                         -- highLayerCompatibility [23] telephony    4
           98 01 01                            -- serviceInteractionIndicators [24]        3
           99 07 00 04 13 51 55 10 88          -- additionalCallingPartyNumber [25]        9
           9a 02 20 01                         -- forwardCallIndicators [26]               4
           bb 05                               -- bearerCapability [27]: CHOICE, EXPLICIT  7
              80 03 80 90 a3                   --   bearerCap [0]: speech, 64 kbit/s, A-law
           9c 01 02                            -- eventTypeBCSM [28] collectedInfo(2)      3
           9d 06 04 13 51 55 10 77             -- redirectingPartyID [29]                  8
           9e 02 03 01                         -- redirectionInformation [30]              4
        "
        ),
    );
    let Some(d) = dissect(op_codes::INITIAL_DP, Some(&ber), Continue) else {
        return;
    };
    d.show("inap.serviceKey", "42")
        .hex("inap.calledPartyNumber", "041051551032")
        .hex("inap.callingPartyNumber", "041351551099")
        .hex("inap.callingPartysCategory", "0a")
        .show("inap.cGEncountered", "1")
        .hex("inap.iPSSPCapabilities", "01")
        .hex("inap.iPAvailable", "01")
        .hex("inap.locationNumber", "041351551011")
        .hex("inap.originalCalledPartyID", "041351551044")
        .show("inap.extensions", "1")
        .show("inap.criticality", "1")
        .hex("inap.highLayerCompatibility", "9181")
        .hex("inap.serviceInteractionIndicators", "01")
        .hex("inap.additionalCallingPartyNumber", "00041351551088")
        .hex("inap.forwardCallIndicators", "2001")
        .show("inap.bearerCapability", "0")
        .hex("inap.bearerCap", "8090a3")
        .show("inap.eventTypeBCSM", "2")
        .hex("inap.redirectingPartyID", "041351551077")
        .hex("inap.redirectionInformation", "0301");
}

#[test]
fn initial_dp_with_the_q1218_members() {
    // dialledDigits, callingPartyBusinessGroupID, callingPartySubaddress,
    // miscCallInfo, serviceProfileIdentifier and terminalType are the six
    // members ETS 300 374-1 clause 6.3 requires an SCF to recognise and
    // ignore; triggerType and the tmr alternative are in Q.1218 alone.
    let arg = InitialDpArg {
        dialled_digits: Some(octets("04 10 21 43")),
        calling_party_business_group_id: Some(octets("01 02")),
        calling_party_subaddress: Some(octets("80 50")),
        misc_call_info: Some(MiscCallInfo {
            message_type: MessageType::Request,
            dp_assignment: Some(DpAssignment::GroupBased),
        }),
        service_profile_identifier: Some(octets("31 32")),
        terminal_type: Some(TerminalType::Isdn),
        trigger_type: Some(TriggerType::OffHookDelay),
        bearer_capability: Some(BearerCapability::Tmr(octets("00"))),
        ..InitialDpArg::new(42)
    };
    let ber = known_answer(
        &arg,
        "
        30 28                                  -- 3 + 6 + 4 + 4 + 8 + 4 + 3 + 3 + 5 = 40
           80 01 2a                            -- serviceKey 42
           81 04 04 10 21 43                   -- dialledDigits [1]
           84 02 01 02                         -- callingPartyBusinessGroupID [4]
           86 02 80 50                         -- callingPartySubaddress [6]
           ab 06                               -- miscCallInfo [11] SEQUENCE
              80 01 00                         --   messageType request(0)
              81 01 01                         --   dpAssignment groupBased(1)
           8d 02 31 32                         -- serviceProfileIdentifier [13]
           8e 01 03                            -- terminalType [14] isdn(3)
           90 01 11                            -- triggerType [16] offHookDelay(17)
           bb 03                               -- bearerCapability [27] EXPLICIT
              81 01 00                         --   tmr [1]: speech
        ",
    );
    let Some(d) = dissect(op_codes::INITIAL_DP, Some(&ber), Continue) else {
        return;
    };
    d.hex("inap.dialledDigits", "04102143")
        .hex("inap.callingPartyBusinessGroupID", "0102")
        .hex("inap.callingPartySubaddress", "8050")
        .present("inap.miscCallInfo_element")
        .show("inap.messageType", "0")
        .show("inap.dpAssignment", "1")
        .hex("inap.serviceProfileIdentifier", "3132")
        .show("inap.terminalType", "3")
        .show("inap.triggerType", "17")
        .show("inap.bearerCapability", "1")
        .hex("inap.tmr", "00");
}

#[test]
fn initial_dp_minimal() {
    let ber = known_answer(
        &InitialDpArg::new(42),
        "30 03 80 01 2a                        -- serviceKey [0] 42",
    );
    let Some(d) = dissect(op_codes::INITIAL_DP, Some(&ber), Continue) else {
        return;
    };
    d.show("inap.serviceKey", "42")
        .absent("inap.bearerCapability");
}

#[test]
fn initial_dp_as_encoded_by_1_x_still_decodes() {
    // The InitialDP argument of the 1.x known-answer suite. Its members were
    // on the right tags; what 1.x lacked were the members it did not model
    // (cGEncountered, extensions, bearerCapability, redirectionInformation),
    // which made it refuse an InitialDP carrying any of them.
    let old = vector(
        "30 36 80 01 2a 82 05 03 15 55 01 23 83 05 03 15 55 01 99 85 01 0a 88 01 01 89 01 01
         8a 05 03 15 55 01 11 97 02 91 81 98 01 01 99 05 03 15 55 01 88 9a 02 00 01 9c 01 02",
    );
    let arg: InitialDpArg = inap::decode(&old).unwrap();
    assert_eq!(arg.service_key, Integer::from(42));
    assert_eq!(arg.event_type_bcsm, Some(EventTypeBcsm::CollectedInfo));
    assert_eq!(inap::encode(&arg).unwrap(), old);
}

#[test]
fn initial_dp_without_a_service_key_is_refused() {
    // Q.1218 makes serviceKey OPTIONAL, ETS 300 374-1 does not. This crate
    // follows ETS 300 374-1: 30 03 9c 01 02 (eventTypeBCSM alone) is refused.
    let error = refused::<InitialDpArg>(&vector("30 03 9c 01 02"));
    assert!(error.contains("service_key"), "{error}");
}

// ── Connect ─────────────────────────────────────────────────────────────────

#[test]
fn connect_with_every_core_inap_member() {
    let arg = ConnectArg {
        alerting_pattern: Some(octets("00 00 04")),
        correlation_id: Some(octets("00 21 43")),
        cut_and_paste: Some(3),
        original_called_party_id: Some(octets("04 13 51 55 10 44")),
        route_list: Some(vec![octets("01"), octets("02 03")]),
        scf_id: Some(octets("01 02")),
        extensions: Some(extensions()),
        service_interaction_indicators: Some(octets("01")),
        calling_party_number: Some(octets("04 13 51 55 10 99")),
        calling_partys_category: Some(octets("0a")),
        redirecting_party_id: Some(octets("04 13 51 55 10 77")),
        redirection_information: Some(octets("03 01")),
        ..ConnectArg::new(octets("04 10 51 55 10 32"))
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 55                                  -- 85, see the sum below
           a0 08                               -- destinationRoutingAddress [0] SEQUENCE OF   10
              04 06 04 10 51 55 10 32          --   CalledPartyNumber, a plain OCTET STRING
           81 03 00 00 04                      -- alertingPattern [1]                         5
           82 03 00 21 43                      -- correlationID [2]                           5
           83 01 03                            -- cutAndPaste [3] 3                           3
           86 06 04 13 51 55 10 44             -- originalCalledPartyID [6]                   8
           a7 07                               -- routeList [7] SEQUENCE OF OCTET STRING      9
              04 01 01
              04 02 02 03
           88 02 01 02                         -- scfID [8]                                   4
           aa 0d                               -- extensions [10]                            15
              {EXTENSION}
           9a 01 01                            -- serviceInteractionIndicators [26]           3
           9b 06 04 13 51 55 10 99             -- callingPartyNumber [27]                     8
           9c 01 0a                            -- callingPartysCategory [28]                  3
           9d 06 04 13 51 55 10 77             -- redirectingPartyID [29]                     8
           9e 02 03 01                         -- redirectionInformation [30]                 4
        "
        ),
    );
    let Some(d) = dissect(op_codes::CONNECT, Some(&ber), Continue) else {
        return;
    };
    d.show("inap.destinationRoutingAddress", "1")
        .hex("inap.CalledPartyNumber", "041051551032")
        .hex("inap.alertingPattern", "000004")
        .hex("inap.correlationID", "002143")
        .show("inap.cutAndPaste", "3")
        .hex("inap.originalCalledPartyID", "041351551044")
        .show("inap.routeList", "2")
        .hex_all("inap.Route", &["01", "0203"])
        .hex("inap.scfID", "0102")
        .show("inap.extensions", "1")
        .hex("inap.serviceInteractionIndicators", "01")
        .hex("inap.callingPartyNumber", "041351551099")
        .hex("inap.callingPartysCategory", "0a")
        .hex("inap.redirectingPartyID", "041351551077")
        .hex("inap.redirectionInformation", "0301");
}

#[test]
fn connect_with_the_q1218_members() {
    let arg = ConnectArg {
        forwarding_condition: Some(ForwardingCondition::NoAnswer),
        isdn_access_related_information: Some(octets("1e 02 81 83")),
        travelling_class_mark: Some(octets("04 13 51 55 10 11")),
        carrier: Some(octets("10 32 54")),
        ..ConnectArg::new(octets("04 10 51 55 10 32"))
    };
    let ber = known_answer(
        &arg,
        "
        30 20                                  -- 10 + 3 + 6 + 8 + 5 = 32
           a0 08 04 06 04 10 51 55 10 32       -- destinationRoutingAddress
           84 01 01                            -- forwardingCondition [4] noanswer(1)
           85 04 1e 02 81 83                   -- iSDNAccessRelatedInformation [5]
           89 06 04 13 51 55 10 11             -- travellingClassMark [9]
           8b 03 10 32 54                      -- carrier [11]
        ",
    );
    let Some(d) = dissect(op_codes::CONNECT, Some(&ber), Continue) else {
        return;
    };
    d.show("inap.forwardingCondition", "1")
        .hex("inap.iSDNAccessRelatedInformation", "1e028183")
        .hex("inap.travellingClassMark", "041351551011")
        .hex("inap.carrier", "103254");
}

#[test]
fn connect_with_two_destinations() {
    // DestinationRoutingAddress is SIZE (1) in ETS 300 374-1 and SIZE (1..3)
    // in Q.1218.
    let arg = ConnectArg {
        destination_routing_address: vec![octets("04 10 21 43"), octets("04 10 65 87")],
        ..ConnectArg::new(octets("00"))
    };
    let ber = known_answer(
        &arg,
        "
        30 0e
           a0 0c                               -- two CalledPartyNumbers, 6 + 6
              04 04 04 10 21 43
              04 04 04 10 65 87
        ",
    );
    let Some(d) = dissect(op_codes::CONNECT, Some(&ber), Continue) else {
        return;
    };
    d.show("inap.destinationRoutingAddress", "2")
        .hex_all("inap.CalledPartyNumber", &["04102143", "04106587"]);
}

#[test]
fn connect_as_encoded_by_1_x_still_decodes() {
    // The Connect argument of the 1.x known-answer suite:
    // destinationRoutingAddress and originalCalledPartyID [6].
    let old = vector("30 10 a0 07 04 05 03 15 55 01 23 86 05 03 15 55 01 00");
    let arg: ConnectArg = inap::decode(&old).unwrap();
    assert_eq!(arg.destination_routing_address, [octets("03 15 55 01 23")]);
    assert_eq!(arg.original_called_party_id, Some(octets("03 15 55 01 00")));
    assert_eq!(inap::encode(&arg).unwrap(), old);
}

// ── ReleaseCall ─────────────────────────────────────────────────────────────

#[test]
fn release_call_is_a_bare_cause() {
    // ReleaseCallArg ::= Cause. Cause (Q.850 in Q.763 3.12): 80 = location
    // user, 90 = cause 16, normal call clearing.
    let ber = known_answer(
        &ReleaseCallArg(octets("80 90")),
        "04 02 80 90                           -- OCTET STRING, no SEQUENCE around it",
    );
    // A SEQUENCE around the Cause is not a ReleaseCallArg.
    refused::<ReleaseCallArg>(&vector("30 04 04 02 80 90"));
    let Some(d) = dissect(op_codes::RELEASE_CALL, Some(&ber), Continue) else {
        return;
    };
    // Wireshark's capability set 4 copy calls the bare Cause initialCallSegment.
    d.hex("inap.initialCallSegment", "8090")
        .show("inap.cause_indicator", "16");
}

// ── EstablishTemporaryConnection ────────────────────────────────────────────

#[test]
fn establish_temporary_connection_with_every_core_inap_member() {
    let arg = EstablishTemporaryConnectionArg {
        correlation_id: Some(octets("00 21 43")),
        scf_id: Some(octets("01 02")),
        extensions: Some(extensions()),
        service_interaction_indicators: Some(octets("01")),
        ..EstablishTemporaryConnectionArg::new(octets("00 04 13 51 55 10 66"))
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 24                                  -- 9 + 5 + 4 + 15 + 3 = 36
           80 07 00 04 13 51 55 10 66          -- assistingSSPIPRoutingAddress [0]
           81 03 00 21 43                      -- correlationID [1]
           83 02 01 02                         -- scfID [3]
           a4 0d                               -- extensions [4]
              {EXTENSION}
           9e 01 01                            -- serviceInteractionIndicators [30]
        "
        ),
    );
    let Some(d) = dissect(
        op_codes::ESTABLISH_TEMPORARY_CONNECTION,
        Some(&ber),
        Continue,
    ) else {
        return;
    };
    d.hex("inap.assistingSSPIPRoutingAddress", "00041351551066")
        .hex("inap.correlationID", "002143")
        .hex("inap.scfID", "0102")
        .show("inap.extensions", "1")
        .hex("inap.serviceInteractionIndicators", "01");
}

#[test]
fn establish_temporary_connection_with_the_q1218_members() {
    let arg = EstablishTemporaryConnectionArg {
        leg_id: Some(LegId::sending(1)),
        carrier: Some(octets("10 32 54")),
        ..EstablishTemporaryConnectionArg::new(octets("00 04 13 51 55 10 66"))
    };
    let ber = known_answer(
        &arg,
        "
        30 13                                  -- 9 + 5 + 5 = 19
           80 07 00 04 13 51 55 10 66          -- assistingSSPIPRoutingAddress
           a2 03                               -- legID [2]: CHOICE, EXPLICIT
              80 01 01                         --   sendingSideID leg 1
           85 03 10 32 54                      -- carrier [5]
        ",
    );
    let Some(d) = dissect(
        op_codes::ESTABLISH_TEMPORARY_CONNECTION,
        Some(&ber),
        Continue,
    ) else {
        return;
    };
    // Capability set 4 turned [2] into a partyToConnect CHOICE whose
    // alternative [2] is the LegID; the octets are the same.
    d.show("inap.legID", "0")
        .hex("inap.sendingSideID", "01")
        .hex("inap.carrier", "103254");
}

// ── AssistRequestInstructions ───────────────────────────────────────────────

#[test]
fn assist_request_instructions_with_every_member() {
    let arg = AssistRequestInstructionsArg {
        ip_available: Some(octets("01")),
        ip_ssp_capabilities: Some(octets("02")),
        extensions: Some(extensions()),
        ..AssistRequestInstructionsArg::new(octets("00 04 13 51 55 10 66"))
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 1e                                  -- 9 + 3 + 3 + 15 = 30
           80 07 00 04 13 51 55 10 66          -- correlationID [0], a generic number here
           81 01 01                            -- iPAvailable [1]
           82 01 02                            -- iPSSPCapabilities [2]
           a3 0d                               -- extensions [3]
              {EXTENSION}
        "
        ),
    );
    let Some(d) = dissect(op_codes::ASSIST_REQUEST_INSTRUCTIONS, Some(&ber), Continue) else {
        return;
    };
    d.hex("inap.correlationID", "00041351551066")
        .hex("inap.iPAvailable", "01")
        .hex("inap.iPSSPCapabilities", "02")
        .show("inap.extensions", "1");
}

#[test]
fn assist_request_instructions_minimal() {
    known_answer(
        &AssistRequestInstructionsArg::new(octets("00 04 13 51 55 10 66")),
        "30 09 80 07 00 04 13 51 55 10 66",
    );
    // correlationID is mandatory.
    refused::<AssistRequestInstructionsArg>(&vector("30 03 82 01 02"));
}

// ── ResetTimer ──────────────────────────────────────────────────────────────

#[test]
fn reset_timer_with_every_member() {
    let arg = ResetTimerArg {
        timer_id: Some(TimerId::Tssf),
        extensions: Some(extensions()),
        ..ResetTimerArg::new(30)
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 15                                  -- 3 + 3 + 15 = 21
           80 01 00                            -- timerID [0] tssf(0)
           81 01 1e                            -- timervalue [1] 30 s
           a2 0d                               -- extensions [2]
              {EXTENSION}
        "
        ),
    );
    let Some(d) = dissect(op_codes::RESET_TIMER, Some(&ber), Continue) else {
        return;
    };
    d.show("inap.timerID", "0")
        .show("inap.timervalue", "30")
        .show("inap.extensions", "1");
}

#[test]
fn reset_timer_minimal_and_unknown_timer() {
    let ber = known_answer(
        &ResetTimerArg::new(30),
        "30 03 81 01 1e                        -- timerID absent: DEFAULT tssf",
    );
    if let Some(d) = dissect(op_codes::RESET_TIMER, Some(&ber), Continue) {
        d.absent("inap.timerID").show("inap.timervalue", "30");
    }
    // TimerID ::= ENUMERATED { tssf(0) }: nothing else is defined. 1.x took
    // any INTEGER here.
    let error = refused::<ResetTimerArg>(&vector("30 06 80 01 01 81 01 1e"));
    assert!(error.contains("timer_id"), "{error}");
}

// ── Cancel ──────────────────────────────────────────────────────────────────

#[test]
fn cancel_one_invocation() {
    let ber = known_answer(
        &CancelArg::InvokeId(5.into()),
        "80 01 05                              -- invokeID [0] 5; the argument is the CHOICE itself",
    );
    let Some(d) = dissect(op_codes::CANCEL, Some(&ber), Continue) else {
        return;
    };
    d.show("inap.CancelArg", "0").show("inap.invokeID", "5");
}

#[test]
fn cancel_all_requests() {
    let ber = known_answer(
        &CancelArg::AllRequests(()),
        "81 00                                 -- allRequests [1] NULL",
    );
    // CancelArg has no alternative [2].
    refused::<CancelArg>(&vector("82 00"));
    let Some(d) = dissect(op_codes::CANCEL, Some(&ber), Continue) else {
        return;
    };
    d.show("inap.CancelArg", "1")
        .present("inap.allRequests_element");
}
