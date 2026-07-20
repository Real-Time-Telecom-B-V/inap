//! Encoder for the Q.763 Called Party Number that CAMEL / INAP carries as raw
//! bytes.
//!
//! INAP keeps [`CalledPartyNumber`](crate::types::CalledPartyNumber) (and the
//! sibling party-number IEs) as an opaque OCTET STRING. This builds one from a
//! digit string so a caller does not hand-pack the ISUP address format
//! (ITU-T Q.763 §3.9):
//!
//! * octet 1: the odd/even indicator (bit 8) and the 7-bit nature of address;
//! * octet 2: the INN indicator (bit 8), the 3-bit numbering plan (bits 7-5),
//!   spare (bits 4-1);
//! * then the address signals, two BCD digits per octet, low nibble first, with
//!   a `0x0` filler nibble for an odd count.
//!
//! The filler here is `0x0` per Q.763, not the `0xF` TBCD filler used for MAP
//! AddressStrings, so this does not reuse a TBCD packer.
//!
//! ```
//! use inap::address;
//! // A CAMEL destinationRoutingAddress, international E.164.
//! assert_eq!(
//!     address::international_e164("15550199").unwrap(),
//!     vec![0x04, 0x10, 0x51, 0x55, 0x10, 0x99],
//! );
//! ```

use crate::error::InapError;

/// Nature of address — subscriber number.
pub const NATURE_SUBSCRIBER: u8 = 1;
/// Nature of address — unknown.
pub const NATURE_UNKNOWN: u8 = 2;
/// Nature of address — national (significant) number.
pub const NATURE_NATIONAL: u8 = 3;
/// Nature of address — international number.
pub const NATURE_INTERNATIONAL: u8 = 4;

/// Numbering plan — ISDN / telephony (E.164).
pub const PLAN_ISDN: u8 = 1;

/// Encode a Q.763 Called Party Number from a digit string.
///
/// `nature` is the 7-bit nature-of-address indicator, `plan` the 3-bit numbering
/// plan, `inn` the internal-network-number indicator (`true` = routing to an
/// internal network number not allowed). Non-decimal input is rejected.
pub fn called_party_number(
    digits: &str,
    nature: u8,
    plan: u8,
    inn: bool,
) -> Result<Vec<u8>, InapError> {
    if nature > 0x7F {
        return Err(InapError::InvalidAddress(format!(
            "nature of address {nature} does not fit 7 bits"
        )));
    }
    if plan > 0x07 {
        return Err(InapError::InvalidAddress(format!(
            "numbering plan {plan} does not fit 3 bits"
        )));
    }
    let odd = (digits.len() & 1) as u8;
    let mut out = Vec::with_capacity(2 + digits.len().div_ceil(2));
    out.push((odd << 7) | nature);
    out.push((u8::from(inn) << 7) | (plan << 4));
    out.extend(bcd(digits)?);
    Ok(out)
}

/// Encode an international E.164 Called Party Number (`0x04 0x10 …`): the common
/// CAMEL `destinationRoutingAddress` form.
pub fn international_e164(digits: &str) -> Result<Vec<u8>, InapError> {
    called_party_number(digits, NATURE_INTERNATIONAL, PLAN_ISDN, false)
}

/// BCD address signals: two digits per octet, low nibble first, `0x0` filler for
/// an odd count (Q.763 §3.9).
fn bcd(digits: &str) -> Result<Vec<u8>, InapError> {
    let nibbles: Vec<u8> = digits
        .chars()
        .map(|c| {
            c.to_digit(10).map(|d| d as u8).ok_or_else(|| {
                InapError::InvalidAddress(format!("non-decimal address digit {c:?}"))
            })
        })
        .collect::<Result<_, _>>()?;
    let mut out = Vec::with_capacity(nibbles.len().div_ceil(2));
    let mut i = 0;
    while i < nibbles.len() {
        let low = nibbles[i];
        let high = if i + 1 < nibbles.len() {
            nibbles[i + 1]
        } else {
            0x00
        };
        out.push((high << 4) | low);
        i += 2;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vectors. Fictional `+1 555 01xx` destinations; the bytes are
    // checked against the Q.763 §3.9 format, not a round-trip.

    #[test]
    fn international_even_length() {
        // +1 555 0199 (8 digits, even): O/E=0, NoA=international, NPI=ISDN.
        assert_eq!(
            international_e164("15550199").unwrap(),
            vec![0x04, 0x10, 0x51, 0x55, 0x10, 0x99]
        );
    }

    #[test]
    fn international_odd_length_gets_zero_filler() {
        // 9 digits, odd: O/E=1 (octet1 0x84), trailing 0x0 filler nibble.
        assert_eq!(
            international_e164("155501999").unwrap(),
            vec![0x84, 0x10, 0x51, 0x55, 0x10, 0x99, 0x09]
        );
    }

    #[test]
    fn national_number_sets_fields() {
        // NoA=national(3), even → octet1 0x03; NPI=ISDN → octet2 0x10.
        assert_eq!(
            called_party_number("15550199", NATURE_NATIONAL, PLAN_ISDN, false).unwrap(),
            vec![0x03, 0x10, 0x51, 0x55, 0x10, 0x99]
        );
    }

    #[test]
    fn inn_indicator_sets_octet2_top_bit() {
        // inn=true → octet2 bit 8 set: 0x80 | (ISDN<<4) = 0x90.
        assert_eq!(
            called_party_number("15550199", NATURE_INTERNATIONAL, PLAN_ISDN, true).unwrap()[1],
            0x90
        );
    }

    #[test]
    fn rejects_non_digit() {
        assert!(matches!(
            international_e164("1555#199"),
            Err(InapError::InvalidAddress(_))
        ));
    }
}
