//! What `rasn` loses while decoding, and that [`inap::decode`] refuses it.
//!
//! Each test first shows the leniency with `rasn::ber::decode` on the crate's
//! own type: the decode succeeds and data that was on the wire is gone. It
//! then shows `inap::decode` returning an error for the same octets. If a
//! future `rasn` stops being lenient, the first half of a test fails and says
//! so; the second half is the behaviour this crate guarantees either way.
//!
//! The three cases (seen on rasn 0.28.13 to 0.28.15):
//!
//! 1. an OPTIONAL member behind an EXPLICIT tag whose content does not decode
//!    is reported as absent, after its octets have been consumed;
//! 2. a SEQUENCE OF whose last element does not decode is returned without
//!    that element (an earlier malformed element leaves octets behind and is
//!    caught by rasn);
//! 3. octets after the outermost value are ignored.
//!
//! All values are synthetic.

mod common;

use common::{refused, vector};
use inap::operations::{
    ApplyChargingArg, CallInformationReportArg, ConnectArg, EventReportBcsmArg, InitialDpArg,
    PlayAnnouncementArg, PromptAndCollectUserInformationArg, RequestReportBcsmEventArg,
};
use inap::types::{EventTypeBcsm, LegId, MiscCallInfo};

/// `rasn` alone, without this crate's guard.
fn lenient<T: rasn::Decode>(bytes: &[u8]) -> T {
    rasn::ber::decode(bytes).expect(
        "rasn refused these octets: it no longer has the leniency this test documents, \
         which is good news; adjust the first half of the test",
    )
}

// ── 1. OPTIONAL behind an EXPLICIT tag ──────────────────────────────────────

#[test]
fn event_report_leg_id_with_an_unknown_alternative() {
    // legID [3] holds [5], and LegID has only [0] and [1].
    //   30 08  80 01 09  a3 03 85 01 02
    let wire = vector("30 08 80 01 09 a3 03 85 01 02");

    let lost: EventReportBcsmArg = lenient(&wire);
    assert_eq!(lost.event_type_bcsm, EventTypeBcsm::ODisconnect);
    assert_eq!(
        lost.leg_id, None,
        "the leg is on the wire and rasn dropped it"
    );
    // An SCF handed this value cannot tell which party disconnected.

    let error = refused::<EventReportBcsmArg>(&wire);
    assert!(error.contains("[3]"), "{error}");
}

#[test]
fn event_report_leg_id_lost_while_a_later_member_survives() {
    // The same malformed legID followed by a well-formed miscCallInfo [4].
    let wire = vector("30 0d 80 01 09 a3 03 85 01 02 a4 03 80 01 01");

    let lost: EventReportBcsmArg = lenient(&wire);
    assert_eq!(lost.leg_id, None);
    assert_eq!(lost.misc_call_info, Some(MiscCallInfo::notification()));

    let error = refused::<EventReportBcsmArg>(&wire);
    assert!(error.contains("[3]"), "{error}");
}

#[test]
fn event_report_event_specific_information_with_a_broken_cause() {
    // eventSpecificInformationBCSM [2] { oDisconnectSpecificInfo [7] {
    // releaseCause [0] of declared length 5 with two octets present } }.
    //   30 0b  80 01 09  a2 06 a7 04 80 05 80 90
    let wire = vector("30 0b 80 01 09 a2 06 a7 04 80 05 80 90");

    let lost: EventReportBcsmArg = lenient(&wire);
    assert_eq!(lost.event_specific_information_bcsm, None);
    // The release cause the SSF reported is gone, with no error.

    refused::<EventReportBcsmArg>(&wire);
}

#[test]
fn initial_dp_bearer_capability_with_an_unknown_alternative() {
    // bearerCapability [27] holds [5]; BearerCapability has [0] and [1].
    //   30 0a  80 01 2a  bb 05 85 03 80 90 a3
    let wire = vector("30 0a 80 01 2a bb 05 85 03 80 90 a3");

    let lost: InitialDpArg = lenient(&wire);
    assert_eq!(lost.bearer_capability, None);

    let error = refused::<InitialDpArg>(&wire);
    assert!(error.contains("[27]"), "{error}");
}

#[test]
fn apply_charging_party_to_charge_with_an_unknown_alternative() {
    //   30 0a  80 03 01 02 03  a2 03 85 01 01
    let wire = vector("30 0a 80 03 01 02 03 a2 03 85 01 01");

    let lost: ApplyChargingArg = lenient(&wire);
    assert_eq!(lost.party_to_charge, None);
    // Absent means "charge the calling party": the wrong party is charged.

    let error = refused::<ApplyChargingArg>(&wire);
    assert!(error.contains("[2]"), "{error}");
}

#[test]
fn prompt_and_collect_information_to_send_with_an_unknown_alternative() {
    // informationToSend [2] holds [7]; InformationToSend has [0] to [2].
    //   30 0c  a0 05 a0 03 81 01 0a  a2 03 87 01 07
    let wire = vector("30 0c a0 05 a0 03 81 01 0a a2 03 87 01 07");

    let lost: PromptAndCollectUserInformationArg = lenient(&wire);
    assert_eq!(lost.information_to_send, None);
    // The SRF would collect digits without playing the prompt.

    let error = refused::<PromptAndCollectUserInformationArg>(&wire);
    assert!(error.contains("[2]"), "{error}");
}

#[test]
fn a_mandatory_explicit_member_was_never_lenient() {
    // The same malformed content in a member that is not OPTIONAL fails in
    // rasn itself: the leniency is specific to OPTIONAL.
    let wire = vector("30 05 a0 03 87 01 07");
    assert!(rasn::ber::decode::<PlayAnnouncementArg>(&wire).is_err());
    refused::<PlayAnnouncementArg>(&wire);
}

// ── 2. SEQUENCE OF ──────────────────────────────────────────────────────────

#[test]
fn request_report_bcsm_event_list_loses_a_malformed_last_event() {
    // Two events; the second has monitorMode 7, which is not defined.
    //   a0 10  30 06 80 01 07 81 01 01      oAnswer, notifyAndContinue
    //          30 06 80 01 09 81 01 07      oDisconnect, monitorMode 7
    let wire = vector("30 12 a0 10 30 06 80 01 07 81 01 01 30 06 80 01 09 81 01 07");

    let lost: RequestReportBcsmEventArg = lenient(&wire);
    assert_eq!(lost.bcsm_events.len(), 1, "one of two events is gone");
    assert_eq!(lost.bcsm_events[0].event_type_bcsm, EventTypeBcsm::OAnswer);
    // An SSF handed this value arms answer and never reports the disconnect.

    let error = refused::<RequestReportBcsmEventArg>(&wire);
    assert!(error.contains("could not be decoded"), "{error}");
}

#[test]
fn request_report_bcsm_event_list_can_come_back_empty() {
    // A single event, malformed in the same way: an argument with no events.
    let wire = vector("30 0a a0 08 30 06 80 01 09 81 01 07");
    let lost: RequestReportBcsmEventArg = lenient(&wire);
    assert!(lost.bcsm_events.is_empty());
    refused::<RequestReportBcsmEventArg>(&wire);
}

#[test]
fn request_report_bcsm_event_as_encoded_by_1_x_loses_its_leg() {
    // The 1.x encoding of an event with a leg (primitive [2], see
    // tests/bcsm_events.rs) runs into case 1 inside the list: the event
    // survives and its leg does not.
    let wire = vector("30 0d a0 0b 30 09 80 01 09 81 01 00 82 01 02");
    let lost: RequestReportBcsmEventArg = lenient(&wire);
    assert_eq!(lost.bcsm_events.len(), 1);
    assert_eq!(lost.bcsm_events[0].leg_id, None);
    refused::<RequestReportBcsmEventArg>(&wire);
}

#[test]
fn a_malformed_element_before_the_last_was_never_lenient() {
    // With a well-formed event after the malformed one, rasn finds octets
    // left over in the list and fails by itself.
    let wire = vector(
        "30 1a a0 18 30 06 80 01 07 81 01 01 30 06 80 01 09 81 01 07 30 06 80 01 06 81 01 00",
    );
    assert!(rasn::ber::decode::<RequestReportBcsmEventArg>(&wire).is_err());
    refused::<RequestReportBcsmEventArg>(&wire);

    // So does an element of the wrong type, here an INTEGER among the
    // destination addresses of a Connect.
    let wire = vector("30 0b a0 09 04 04 04 10 21 43 02 01 05");
    assert!(rasn::ber::decode::<ConnectArg>(&wire).is_err());
    refused::<ConnectArg>(&wire);
}

#[test]
fn call_information_report_list_loses_a_malformed_last_item() {
    // Two items; the value of the second holds [7], not a
    // RequestedInformationValue alternative.
    //   a0 16  30 09 80 01 02 a1 04 82 02 04 b0
    //          30 09 80 01 1e a1 04 87 02 80 90
    let wire =
        vector("30 18 a0 16 30 09 80 01 02 a1 04 82 02 04 b0 30 09 80 01 1e a1 04 87 02 80 90");

    let lost: CallInformationReportArg = lenient(&wire);
    assert_eq!(lost.requested_information_list.len(), 1);

    refused::<CallInformationReportArg>(&wire);
}

// ── 3. Trailing octets ──────────────────────────────────────────────────────

#[test]
fn octets_after_the_argument_are_refused() {
    //   30 03 80 01 09 | 83 01 02
    let wire = vector("30 03 80 01 09 83 01 02");
    let lost: EventReportBcsmArg = lenient(&wire);
    assert_eq!(lost.event_type_bcsm, EventTypeBcsm::ODisconnect);

    let error = refused::<EventReportBcsmArg>(&wire);
    assert!(error.contains("[3]"), "{error}");
}

// ── What the guard must not refuse ──────────────────────────────────────────

#[test]
fn other_ber_forms_of_the_same_value_are_accepted() {
    let expected = EventReportBcsmArg {
        leg_id: Some(LegId::receiving(2)),
        misc_call_info: Some(MiscCallInfo::notification()),
        ..EventReportBcsmArg::new(EventTypeBcsm::ODisconnect)
    };
    // Canonical: 30 0d 80 01 09 a3 03 81 01 02 a4 03 80 01 01
    for wire in [
        // Long-form lengths (X.690 8.1.3.5).
        "30 81 0f 80 01 09 a3 81 03 81 01 02 a4 81 03 80 01 01",
        // Indefinite lengths on every constructed element (X.690 8.1.3.6).
        "30 80 80 01 09 a3 80 81 01 02 00 00 a4 80 80 01 01 00 00 00 00",
        // The leg octet as a constructed OCTET STRING (X.690 8.7.3).
        "30 0f 80 01 09 a3 05 a1 03 04 01 02 a4 03 80 01 01",
    ] {
        let decoded: EventReportBcsmArg = inap::decode(&vector(wire)).unwrap();
        assert_eq!(decoded, expected, "{wire}");
    }

    // BOOLEAN TRUE as any non-zero octet (X.690 8.2.2).
    let arg: PlayAnnouncementArg =
        inap::decode(&vector("30 0a a0 05 a1 03 80 01 07 81 01 01")).unwrap();
    assert_eq!(arg.disconnect_from_ip_forbidden, Some(true));
}

#[test]
fn a_member_this_crate_does_not_know_is_refused_not_skipped() {
    // [9] is not a member of EventReportBCSMArg in capability set 1. rasn
    // refuses it by itself ("unexpected extra data"); the guard keeps that.
    let wire = vector("30 06 80 01 09 89 01 02");
    assert!(rasn::ber::decode::<EventReportBcsmArg>(&wire).is_err());
    refused::<EventReportBcsmArg>(&wire);
}
