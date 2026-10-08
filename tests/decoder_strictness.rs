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
use inap::operations::{ApplyChargingArg, CallInformationReportArg, EventReportBcsmArg};
use inap::types::{EventTypeBcsm, LegId};

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
fn apply_charging_party_to_charge_with_an_unknown_alternative() {
    //   30 0a  80 03 01 02 03  a2 03 85 01 01
    let wire = vector("30 0a 80 03 01 02 03 a2 03 85 01 01");

    let lost: ApplyChargingArg = lenient(&wire);
    assert_eq!(lost.party_to_charge, None);
    // Absent means "charge the calling party": the wrong party is charged.

    let error = refused::<ApplyChargingArg>(&wire);
    assert!(error.contains("[2]"), "{error}");
}

// ── 2. SEQUENCE OF ──────────────────────────────────────────────────────────

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
    // Canonical: 30 08 80 01 09 a3 03 81 01 02
    for wire in [
        "30 08 80 01 09 a3 03 81 01 02",
        // Long-form lengths (X.690 8.1.3.5).
        "30 81 09 80 01 09 a3 81 03 81 01 02",
        // Indefinite lengths on every constructed element (X.690 8.1.3.6).
        "30 80 80 01 09 a3 80 81 01 02 00 00 00 00",
        // The leg octet as a constructed OCTET STRING (X.690 8.7.3).
        "30 0a 80 01 09 a3 05 a1 03 04 01 02",
    ] {
        let decoded: EventReportBcsmArg = inap::decode(&vector(wire)).unwrap();
        assert_eq!(
            decoded.event_type_bcsm,
            EventTypeBcsm::ODisconnect,
            "{wire}"
        );
        assert_eq!(
            decoded.leg_id,
            Some(LegId::ReceivingSideId(vec![0x02].into())),
            "{wire}"
        );
    }
}

#[test]
fn a_member_this_crate_does_not_know_is_refused_not_skipped() {
    // [9] is not a member of EventReportBCSMArg in capability set 1. rasn
    // refuses it by itself ("unexpected extra data"); the guard keeps that.
    let wire = vector("30 06 80 01 09 89 01 02");
    assert!(rasn::ber::decode::<EventReportBcsmArg>(&wire).is_err());
    refused::<EventReportBcsmArg>(&wire);
}
