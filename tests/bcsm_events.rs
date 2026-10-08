//! RequestReportBCSMEvent (op 23) and EventReportBCSM (op 24) with the types
//! they carry: ETS 300 374-1 (September 1994) clause 6.3 and ITU-T Q.1218
//! (10/95) clause 2.1.3.
//!
//! # How the vectors are derived
//!
//! Both modules are `IMPLICIT TAGS`. An identifier octet is
//! `class (2 bits) | constructed (1 bit) | number (5 bits)`:
//!
//! * `[n]` on a primitive type (INTEGER, ENUMERATED, OCTET STRING, BOOLEAN,
//!   NULL) replaces the universal tag: `0x80 | n`.
//! * `[n]` on a SEQUENCE or SEQUENCE OF replaces the universal tag and stays
//!   constructed: `0xa0 | n`.
//! * `[n]` on a CHOICE or an open type cannot replace anything, so it is
//!   EXPLICIT (X.680 31.2.7): a constructed `0xa0 | n` whose content is the
//!   complete encoding of the chosen alternative.
//!
//! Wireshark does not look at the constructed bit of a context tag: it reads
//! `82 01 ..` and `a2 03 8x 01 ..` alike. The byte vectors are what pins that
//! bit; the dissections pin the tag numbers and the nesting.
//!
//! All values are synthetic.

mod common;

use common::{
    dissect, dissect_unchecked, extensions, known_answer, octets, refused, vector, Carrier,
    EXTENSION,
};
use inap::op_codes;
use inap::operations::{EventReportBcsmArg, RequestReportBcsmEventArg};
use inap::types::{
    BcsmEvent, BusySpecificInfo, CalledPartySpecificInfo, DisconnectSpecificInfo, DpAssignment,
    DpSpecificCriteria, EventSpecificInformationBcsm, EventTypeBcsm, LegId, MessageType,
    MidCallSpecificInfo, MiscCallInfo, MonitorMode, NoSpecificInfo, RouteSelectFailureSpecificInfo,
};

// ── RequestReportBCSMEvent ──────────────────────────────────────────────────

#[test]
fn request_report_bcsm_event_with_legs_and_criteria() {
    let arg = RequestReportBcsmEventArg {
        extensions: Some(extensions()),
        ..RequestReportBcsmEventArg::new(vec![
            BcsmEvent::new(EventTypeBcsm::OAnswer, MonitorMode::NotifyAndContinue),
            BcsmEvent {
                leg_id: Some(LegId::sending(2)),
                ..BcsmEvent::new(EventTypeBcsm::ODisconnect, MonitorMode::Interrupted)
            },
            BcsmEvent {
                leg_id: Some(LegId::sending(2)),
                dp_specific_criteria: Some(DpSpecificCriteria::ApplicationTimer(30)),
                ..BcsmEvent::new(EventTypeBcsm::ONoAnswer, MonitorMode::Interrupted)
            },
            BcsmEvent {
                dp_specific_criteria: Some(DpSpecificCriteria::NumberOfDigits(8)),
                ..BcsmEvent::new(EventTypeBcsm::CollectedInfo, MonitorMode::Interrupted)
            },
        ])
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 45                                  -- 54 + 15 = 69
           a0 34                               -- bcsmEvents [0] SEQUENCE OF, 8 + 13 + 18 + 13
              30 06                            --   BCSMEvent
                 80 01 07                      --     eventTypeBCSM oAnswer(7)
                 81 01 01                      --     monitorMode notifyAndContinue(1)
              30 0b                            --   BCSMEvent, 3 + 3 + 5
                 80 01 09                      --     oDisconnect(9)
                 81 01 00                      --     interrupted(0)
                 a2 03                         --     legID [2]: LegID is a CHOICE, EXPLICIT
                    80 01 02                   --       sendingSideID [0] leg 2
              30 10                            --   BCSMEvent, 3 + 3 + 5 + 5
                 80 01 06                      --     oNoAnswer(6)
                 81 01 00
                 a2 03 80 01 02                --     legID: sendingSideID leg 2
                 be 03                         --     dPSpecificCriteria [30]: a CHOICE, EXPLICIT
                                               --       (10 1 11110: context, constructed, 30)
                    81 01 1e                   --       applicationTimer [1] 30 s
              30 0b                            --   BCSMEvent, 3 + 3 + 5
                 80 01 02                      --     collectedInfo(2)
                 81 01 00
                 be 03 80 01 08                --     dPSpecificCriteria: numberOfDigits [0] 8
           a2 0d                               -- extensions [2] SEQUENCE OF
              {EXTENSION}
        "
        ),
    );
    let Some(d) = dissect(
        op_codes::REQUEST_REPORT_BCSM_EVENT,
        Some(&ber),
        Carrier::Continue,
    ) else {
        return;
    };
    d.show("inap.bcsmEvents", "4")
        .show_all("inap.eventTypeBCSM", &["7", "9", "6", "2"])
        .show_all("inap.monitorMode", &["1", "0", "0", "0"])
        // Two events carry a leg, both sendingSideID (alternative 0) leg 2.
        .show_all("inap.legID", &["0", "0"])
        .hex_all("inap.sendingSideID", &["02", "02"])
        .show_all("inap.dpSpecificCriteria", &["1", "0"])
        .show("inap.applicationTimer", "30")
        .show("inap.numberOfDigits", "8")
        .show("inap.extensions", "1")
        .show("inap.criticality", "1");
}

#[test]
fn request_report_bcsm_event_before_2_0_0_is_refused() {
    // 1.x wrote legID as a primitive [2] holding the bare leg octet:
    //   30 0d a0 0b 30 09 80 01 09 81 01 00 82 01 02
    // A LegID has to be a constructed [2] wrapping the chosen alternative.
    let old = vector("30 0d a0 0b 30 09 80 01 09 81 01 00 82 01 02");
    let error = refused::<RequestReportBcsmEventArg>(&old);
    assert!(error.contains("could not be decoded"), "{error}");

    // Wireshark throws on it: the event list is cut short and the packet is
    // marked malformed.
    let Some(d) = dissect_unchecked(
        op_codes::REQUEST_REPORT_BCSM_EVENT,
        Some(&old),
        Carrier::Continue,
    ) else {
        return;
    };
    assert!(
        d.problems().iter().any(|p| p.contains("Malformed")),
        "{}",
        d.summary()
    );
    assert!(d.values("inap.sendingSideID").is_empty());
}

#[test]
fn request_report_bcsm_event_correlation_id() {
    // Q.1218 only. Generic digits (Q.763 3.24): 00 = BCD even, type of digits
    // 0; 21 43 = digits 1234.
    let arg = RequestReportBcsmEventArg {
        bcsm_event_correlation_id: Some(octets("00 21 43")),
        ..RequestReportBcsmEventArg::new(vec![BcsmEvent::new(
            EventTypeBcsm::OAnswer,
            MonitorMode::NotifyAndContinue,
        )])
    };
    let ber = known_answer(
        &arg,
        "
        30 0f                                  -- 10 + 5
           a0 08 30 06 80 01 07 81 01 01       -- bcsmEvents: oAnswer, notifyAndContinue
           81 03 00 21 43                      -- bcsmEventCorrelationID [1] Digits
        ",
    );
    // Wireshark 4.6 reads the member and then trips over a subtree it never
    // registered for it (`failed assertion "idx >= 0 && idx < num_tree_types"`,
    // a "Dissector bug" expert item). The field it read first is still right;
    // the structure of this member is pinned by the vector alone.
    let Some(d) = dissect_unchecked(
        op_codes::REQUEST_REPORT_BCSM_EVENT,
        Some(&ber),
        Carrier::Continue,
    ) else {
        return;
    };
    d.show("inap.eventTypeBCSM", "7")
        .hex("inap.bcsmEventCorrelationID", "002143");
    assert!(
        d.problems().is_empty() || d.only_dissector_bugs(),
        "{:?}",
        d.problems()
    );
}

// ── EventTypeBCSM ───────────────────────────────────────────────────────────

#[test]
fn event_type_bcsm_has_the_seventeen_values_of_the_specification() {
    // EventTypeBCSM ::= ENUMERATED { origAttemptAuthorized(1), collectedInfo(2),
    //   analyzedInformation(3), routeSelectFailure(4), oCalledPartyBusy(5),
    //   oNoAnswer(6), oAnswer(7), oMidCall(8), oDisconnect(9), oAbandon(10),
    //   termAttemptAuthorized(12), tCalledPartyBusy(13), tNoAnswer(14),
    //   tAnswer(15), tMidCall(16), tDisconnect(17), tAbandon(18) }
    // 1.x lacked 1, 8 and 16 and refused a report of a mid-call event.
    use EventTypeBcsm::*;
    let specified = [
        (OrigAttemptAuthorized, 1u8),
        (CollectedInfo, 2),
        (AnalysedInformation, 3),
        (RouteSelectFailure, 4),
        (OCalledPartyBusy, 5),
        (ONoAnswer, 6),
        (OAnswer, 7),
        (OMidCall, 8),
        (ODisconnect, 9),
        (OAbandon, 10),
        (TermAttemptAuthorized, 12),
        (TBusy, 13),
        (TNoAnswer, 14),
        (TAnswer, 15),
        (TMidCall, 16),
        (TDisconnect, 17),
        (TAbandon, 18),
    ];
    for (event, value) in specified {
        // EventReportBCSMArg with only eventTypeBCSM [0]: 30 03 80 01 vv.
        let bytes = [0x30, 0x03, 0x80, 0x01, value];
        assert_eq!(
            inap::encode(&EventReportBcsmArg::new(event)).unwrap(),
            bytes
        );
        let decoded: EventReportBcsmArg = inap::decode(&bytes).unwrap();
        assert_eq!(decoded.event_type_bcsm, event);
    }
    // 0, 11 and 19 are not assigned.
    for value in [0u8, 11, 19] {
        refused::<EventReportBcsmArg>(&[0x30, 0x03, 0x80, 0x01, value]);
    }
}

#[test]
fn event_type_bcsm_values_added_in_2_0_0_are_known_to_wireshark() {
    for (event, value) in [
        (EventTypeBcsm::OrigAttemptAuthorized, "1"),
        (EventTypeBcsm::OMidCall, "8"),
        (EventTypeBcsm::TMidCall, "16"),
    ] {
        let ber = inap::encode(&EventReportBcsmArg::new(event)).unwrap();
        let Some(d) = dissect(op_codes::EVENT_REPORT_BCSM, Some(&ber), Carrier::Continue) else {
            return;
        };
        d.show("inap.eventTypeBCSM", value);
    }
}

// ── EventReportBCSM ─────────────────────────────────────────────────────────

#[test]
fn event_report_bcsm_disconnect_with_every_core_inap_member() {
    let arg = EventReportBcsmArg {
        event_specific_information_bcsm: Some(
            EventSpecificInformationBcsm::ODisconnectSpecificInfo(DisconnectSpecificInfo {
                release_cause: Some(octets("80 90")),
                connect_time: None,
            }),
        ),
        leg_id: Some(LegId::receiving(2)),
        misc_call_info: Some(MiscCallInfo::notification()),
        extensions: Some(extensions()),
        ..EventReportBcsmArg::new(EventTypeBcsm::ODisconnect)
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 24                                  -- 3 + 8 + 5 + 5 + 15 = 36
           80 01 09                            -- eventTypeBCSM oDisconnect(9)
           a2 06                               -- eventSpecificInformationBCSM [2]: CHOICE, EXPLICIT
              a7 04                            --   oDisconnectSpecificInfo [7] SEQUENCE
                 80 02 80 90                   --     releaseCause [0]: location user, cause 16
           a3 03                               -- legID [3]: CHOICE, EXPLICIT
              81 01 02                         --   receivingSideID [1] leg 2
           a4 03                               -- miscCallInfo [4] SEQUENCE, constructed
              80 01 01                         --   messageType notification(1)
           a5 0d                               -- extensions [5]
              {EXTENSION}
        "
        ),
    );
    let Some(d) = dissect(op_codes::EVENT_REPORT_BCSM, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("inap.eventTypeBCSM", "9")
        .show("inap.eventSpecificInformationBCSM", "7")
        .present("inap.oDisconnectSpecificInfo_element")
        .hex("inap.releaseCause", "8090")
        .show("inap.cause_indicator", "16")
        .show("inap.legID", "1")
        .hex("inap.receivingSideID", "02")
        .present("inap.miscCallInfo_element")
        .show("inap.messageType", "1")
        .show("inap.extensions", "1");
}

#[test]
fn event_report_bcsm_misc_call_info_before_2_0_0_is_refused() {
    // 1.x modelled miscCallInfo as an OCTET STRING, so the caller supplied the
    // content of the SEQUENCE and it went out behind a primitive tag:
    //   30 08 80 01 09 84 03 80 01 01
    // A SEQUENCE is always constructed (X.690 8.9.1): a4, not 84.
    let old = vector("30 08 80 01 09 84 03 80 01 01");
    let error = refused::<EventReportBcsmArg>(&old);
    assert!(error.contains("misc_call_info"), "{error}");

    // Wireshark does not look at that bit and reads the old bytes without
    // complaint, which is how the mistake went unnoticed.
    let Some(d) = dissect_unchecked(op_codes::EVENT_REPORT_BCSM, Some(&old), Carrier::Continue)
    else {
        return;
    };
    assert!(d.problems().is_empty(), "{:?}", d.problems());
    d.show("inap.messageType", "1");
}

#[test]
fn event_report_bcsm_minimal() {
    let ber = known_answer(
        &EventReportBcsmArg::new(EventTypeBcsm::OAbandon),
        "30 03 80 01 0a                        -- eventTypeBCSM oAbandon(10), nothing else",
    );
    let Some(d) = dissect(op_codes::EVENT_REPORT_BCSM, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("inap.eventTypeBCSM", "10")
        .absent("inap.eventSpecificInformationBCSM")
        .absent("inap.legID")
        // Absent: DEFAULT { messageType request } applies.
        .absent("inap.miscCallInfo_element");
}

#[test]
fn event_report_bcsm_q1218_members() {
    // bcsmEventCorrelationID [1] and dpAssignment [1] are Q.1218 only.
    let arg = EventReportBcsmArg {
        bcsm_event_correlation_id: Some(octets("00 21 43")),
        misc_call_info: Some(MiscCallInfo {
            message_type: MessageType::Request,
            dp_assignment: Some(DpAssignment::OfficeBased),
        }),
        ..EventReportBcsmArg::new(EventTypeBcsm::OAnswer)
    };
    let ber = known_answer(
        &arg,
        "
        30 10                                  -- 3 + 5 + 8
           80 01 07                            -- eventTypeBCSM oAnswer(7)
           81 03 00 21 43                      -- bcsmEventCorrelationID [1] Digits
           a4 06                               -- miscCallInfo [4]
              80 01 00                         --   messageType request(0)
              81 01 02                         --   dpAssignment officeBased(2)
        ",
    );
    // As in request_report_bcsm_event_correlation_id: Wireshark 4.6 stops at
    // bcsmEventCorrelationID with a dissector bug of its own.
    if let Some(d) = dissect_unchecked(op_codes::EVENT_REPORT_BCSM, Some(&ber), Carrier::Continue) {
        d.hex("inap.bcsmEventCorrelationID", "002143");
        assert!(
            d.problems().is_empty() || d.only_dissector_bugs(),
            "{:?}",
            d.problems()
        );
    }

    // The same miscCallInfo without the member Wireshark trips over.
    let arg = EventReportBcsmArg {
        bcsm_event_correlation_id: None,
        ..arg
    };
    let ber = known_answer(&arg, "30 0b 80 01 07 a4 06 80 01 00 81 01 02");
    let Some(d) = dissect(op_codes::EVENT_REPORT_BCSM, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("inap.messageType", "0")
        .show("inap.dpAssignment", "2");
}

/// One EventReportBCSM per alternative of EventSpecificInformationBCSM.
///
/// Every vector has the shape
/// `30 LL  80 01 <event>  a2 LL  <alternative tag> LL <content>`: `[2]` is the
/// EXPLICIT wrapper, and the alternative's own tag `[0]`..`[12]` replaces the
/// tag of its SEQUENCE, so it is `a0`..`ac`.
#[test]
fn event_specific_information_alternatives() {
    use EventSpecificInformationBcsm as Info;
    // Called party number (Q.763 3.9): 04 = even, international; 10 = ISDN
    // numbering plan; 51 55 10 32 = digits 1 555 0123.
    let called = || CalledPartySpecificInfo {
        called_party_number: octets("04 10 51 55 10 32"),
    };
    let cases: Vec<(EventTypeBcsm, Info, &str, &str, &str)> = vec![
        (
            EventTypeBcsm::CollectedInfo,
            Info::CollectedInfoSpecificInfo(called()),
            "30 0f 80 01 02 a2 0a a0 08 80 06 04 10 51 55 10 32",
            "0",
            "inap.collectedInfoSpecificInfo_element",
        ),
        (
            EventTypeBcsm::AnalysedInformation,
            Info::AnalyzedInfoSpecificInfo(called()),
            "30 0f 80 01 03 a2 0a a1 08 80 06 04 10 51 55 10 32",
            "1",
            "inap.analysedInfoSpecificInfo_element",
        ),
        (
            EventTypeBcsm::RouteSelectFailure,
            Info::RouteSelectFailureSpecificInfo(RouteSelectFailureSpecificInfo {
                failure_cause: Some(octets("80 83")),
            }),
            "30 0b 80 01 04 a2 06 a2 04 80 02 80 83",
            "2",
            "inap.routeSelectFailureSpecificInfo_element",
        ),
        (
            EventTypeBcsm::OCalledPartyBusy,
            Info::OCalledPartyBusySpecificInfo(BusySpecificInfo {
                busy_cause: Some(octets("80 91")),
            }),
            "30 0b 80 01 05 a2 06 a3 04 80 02 80 91",
            "3",
            "inap.oCalledPartyBusySpecificInfo_element",
        ),
        (
            EventTypeBcsm::ONoAnswer,
            Info::ONoAnswerSpecificInfo(NoSpecificInfo {}),
            "30 07 80 01 06 a2 02 a4 00",
            "4",
            "inap.oNoAnswerSpecificInfo_element",
        ),
        (
            EventTypeBcsm::OAnswer,
            Info::OAnswerSpecificInfo(NoSpecificInfo {}),
            "30 07 80 01 07 a2 02 a5 00",
            "5",
            "inap.oAnswerSpecificInfo_element",
        ),
        (
            // Empty in ETS 300 374-1.
            EventTypeBcsm::OMidCall,
            Info::OMidCallSpecificInfo(MidCallSpecificInfo { connect_time: None }),
            "30 07 80 01 08 a2 02 a6 00",
            "6",
            "inap.oMidCallSpecificInfo_element",
        ),
        (
            // Q.1218: connectTime [0] Integer4, here 100.
            EventTypeBcsm::OMidCall,
            Info::OMidCallSpecificInfo(MidCallSpecificInfo {
                connect_time: Some(100),
            }),
            "30 0a 80 01 08 a2 05 a6 03 80 01 64",
            "6",
            "inap.oMidCallSpecificInfo_element",
        ),
        (
            // Q.1218 adds connectTime [1], here 300 = 01 2c.
            EventTypeBcsm::ODisconnect,
            Info::ODisconnectSpecificInfo(DisconnectSpecificInfo {
                release_cause: Some(octets("80 90")),
                connect_time: Some(300),
            }),
            "30 0f 80 01 09 a2 0a a7 08 80 02 80 90 81 02 01 2c",
            "7",
            "inap.oDisconnectSpecificInfo_element",
        ),
        (
            EventTypeBcsm::TBusy,
            Info::TBusySpecificInfo(BusySpecificInfo {
                busy_cause: Some(octets("80 91")),
            }),
            "30 0b 80 01 0d a2 06 a8 04 80 02 80 91",
            "8",
            "inap.tBusySpecificInfo_element",
        ),
        (
            EventTypeBcsm::TNoAnswer,
            Info::TNoAnswerSpecificInfo(NoSpecificInfo {}),
            "30 07 80 01 0e a2 02 a9 00",
            "9",
            "inap.tNoAnswerSpecificInfo_element",
        ),
        (
            EventTypeBcsm::TAnswer,
            Info::TAnswerSpecificInfo(NoSpecificInfo {}),
            "30 07 80 01 0f a2 02 aa 00",
            "10",
            "inap.tAnswerSpecificInfo_element",
        ),
        (
            EventTypeBcsm::TMidCall,
            Info::TMidCallSpecificInfo(MidCallSpecificInfo { connect_time: None }),
            "30 07 80 01 10 a2 02 ab 00",
            "11",
            "inap.tMidCallSpecificInfo_element",
        ),
        (
            EventTypeBcsm::TDisconnect,
            Info::TDisconnectSpecificInfo(DisconnectSpecificInfo {
                release_cause: Some(octets("80 90")),
                connect_time: None,
            }),
            "30 0b 80 01 11 a2 06 ac 04 80 02 80 90",
            "12",
            "inap.tDisconnectSpecificInfo_element",
        ),
    ];
    for (event, info, bytes, alternative, element) in cases {
        let arg = EventReportBcsmArg {
            event_specific_information_bcsm: Some(info),
            ..EventReportBcsmArg::new(event)
        };
        let ber = known_answer(&arg, bytes);
        if let Some(d) = dissect(op_codes::EVENT_REPORT_BCSM, Some(&ber), Carrier::Continue) {
            d.show("inap.eventSpecificInformationBCSM", alternative)
                .present(element);
        }
    }
}

#[test]
fn event_specific_information_fields_are_dissected() {
    let arg = EventReportBcsmArg {
        event_specific_information_bcsm: Some(
            EventSpecificInformationBcsm::CollectedInfoSpecificInfo(CalledPartySpecificInfo {
                called_party_number: octets("04 10 51 55 10 32"),
            }),
        ),
        ..EventReportBcsmArg::new(EventTypeBcsm::CollectedInfo)
    };
    let ber = inap::encode(&arg).unwrap();
    let Some(d) = dissect(op_codes::EVENT_REPORT_BCSM, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.hex("inap.calledPartynumber", "041051551032");

    let arg = EventReportBcsmArg {
        event_specific_information_bcsm: Some(
            EventSpecificInformationBcsm::ODisconnectSpecificInfo(DisconnectSpecificInfo {
                release_cause: Some(octets("80 90")),
                connect_time: Some(300),
            }),
        ),
        ..EventReportBcsmArg::new(EventTypeBcsm::ODisconnect)
    };
    let ber = inap::encode(&arg).unwrap();
    let Some(d) = dissect(op_codes::EVENT_REPORT_BCSM, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.hex("inap.releaseCause", "8090")
        .show("inap.connectTime", "300");
}
