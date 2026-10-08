//! The called party number builder of `inap::address` against Q.763 3.9 and
//! against Wireshark's ISUP dissector, which decodes the number where it sits
//! in a Connect.
//!
//! Q.763 3.9, called party number:
//!
//! ```text
//! octet 1   bit 8 odd/even indicator, bits 7-1 nature of address indicator
//! octet 2   bit 8 INN indicator, bits 7-5 numbering plan, bits 4-1 spare
//! octet 3.. address signals, two per octet, the first in bits 4-1; an odd
//!           number of signals ends with filler 0000 in bits 8-5
//! ```
//!
//! All numbers are in the fictional +1 555 01xx range.

mod common;

use common::{dissect, vector, Carrier};
use inap::address::{self, NATURE_INTERNATIONAL, NATURE_NATIONAL, PLAN_ISDN};
use inap::op_codes;
use inap::operations::ConnectArg;

fn dissected(number: Vec<u8>) -> Option<common::Dissection> {
    let ber = inap::encode(&ConnectArg::new(number.into())).unwrap();
    dissect(op_codes::CONNECT, Some(&ber), Carrier::Continue)
}

#[test]
fn international_number_with_an_even_number_of_digits() {
    let number = address::international_e164("15550123").unwrap();
    assert_eq!(
        number,
        vector(
            "
        04                 -- even, nature of address 4 (international)
        10                 -- INN allowed, numbering plan 1 (ISDN, E.164)
        51 55 10 32        -- 1 5 | 5 5 | 0 1 | 2 3, first digit in the low nibble
        "
        )
    );
    let Some(d) = dissected(number) else {
        return;
    };
    d.show("isup.isdn_odd_even_indicator", "False")
        .show("isup.called_party_nature_of_address_indicator", "4")
        .show("isup.inn_indicator", "False")
        .show("isup.numbering_plan_indicator", "1")
        .show("isup.called", "15550123");
}

#[test]
fn international_number_with_an_odd_number_of_digits() {
    let number = address::international_e164("155501234").unwrap();
    assert_eq!(
        number,
        vector(
            "
        84                 -- odd, nature of address 4
        10
        51 55 10 32 04     -- last octet: digit 4 and the 0000 filler
        "
        )
    );
    let Some(d) = dissected(number) else {
        return;
    };
    d.show("isup.isdn_odd_even_indicator", "True")
        .show("isup.called", "155501234");
}

#[test]
fn national_number_with_the_inn_indicator_set() {
    let number =
        address::called_party_number("15550199", NATURE_NATIONAL, PLAN_ISDN, true).unwrap();
    assert_eq!(
        number,
        vector(
            "
        03                 -- even, nature of address 3 (national)
        90                 -- INN not allowed (bit 8), numbering plan 1
        51 55 10 99
        "
        )
    );
    let Some(d) = dissected(number) else {
        return;
    };
    d.show("isup.called_party_nature_of_address_indicator", "3")
        .show("isup.inn_indicator", "True")
        .show("isup.numbering_plan_indicator", "1")
        .show("isup.called", "15550199");
}

#[test]
fn what_does_not_fit_is_refused() {
    assert!(address::international_e164("1555#123").is_err());
    assert!(address::called_party_number("1", 0x80, PLAN_ISDN, false).is_err());
    assert!(address::called_party_number("1", NATURE_INTERNATIONAL, 8, false).is_err());
}
