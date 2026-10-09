//! Application context names against ETS 300 374-1 (September 1994) clause
//! 6.5, one test per constant. The expected arcs are copied from the value
//! notation in the specification, quoted above each test.
//!
//! The DER content octets are checked as well, since that is what goes into
//! the AARQ: the first two arcs share an octet (40 * 0 + 4 = 0x04) and every
//! other arc here is below 128, one octet each.

use inap::application_context as ac;
use rasn::types::ObjectIdentifier;

fn arcs(oid: &ObjectIdentifier) -> Vec<u32> {
    oid.iter().copied().collect()
}

fn content_octets(oid: &ObjectIdentifier) -> Vec<u8> {
    let ber = rasn::ber::encode(oid).unwrap();
    // 06 <length> <content>
    assert_eq!(ber[0], 0x06);
    assert_eq!(usize::from(ber[1]), ber.len() - 2);
    ber[2..].to_vec()
}

#[test]
fn cs1_ssp_to_scp_is_ac_0() {
    // Core-INAP-CS1-SSP-to-SCP-AC ::= {ccitt(0) identified-organization(4)
    //   etsi(0) inDomain(1) in-network(1) ac(1) cs1-ssp-to-scp(0) version1(0)}
    let oid = ac::cs1_ssp_to_scp();
    assert_eq!(arcs(&oid), [0, 4, 0, 1, 1, 1, 0, 0]);
    assert_eq!(
        content_octets(&oid),
        [0x04, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00]
    );
    assert_eq!(ac::CS1_SSP_TO_SCP, [0, 4, 0, 1, 1, 1, 0, 0]);
}

#[test]
fn cs1_assist_handoff_ssp_to_scp_is_ac_1() {
    // Core-INAP-CS1-assist-handoff-SSP-to-SCP-AC ::= {ccitt(0)
    //   identified-organization(4) etsi(0) inDomain(1) in-network(1) ac(1)
    //   cs1-assist-handoff-ssp-to-scp(1) version1(0)}
    let oid = ac::cs1_assist_handoff_ssp_to_scp();
    assert_eq!(arcs(&oid), [0, 4, 0, 1, 1, 1, 1, 0]);
    assert_eq!(
        content_octets(&oid),
        [0x04, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00]
    );
}

#[test]
fn cs1_ip_to_scp_is_ac_2() {
    // Core-INAP-CS1-IP-to-SCP-AC ::= {ccitt(0) identified-organization(4)
    //   etsi(0) inDomain(1) in-network(1) ac(1) cs1-ip-to-scp(2) version1(0)}
    let oid = ac::cs1_ip_to_scp();
    assert_eq!(arcs(&oid), [0, 4, 0, 1, 1, 1, 2, 0]);
    assert_eq!(
        content_octets(&oid),
        [0x04, 0x00, 0x01, 0x01, 0x01, 0x02, 0x00]
    );
}

#[test]
fn core_inap_cs1_codes_is_module_3_and_not_a_context() {
    // Core-INAP-CS1-Codes {ccitt(0) identified-organization(4) etsi(0)
    //   inDomain(1) in-network(1) modules(0) cs1-codes(3) version1(0)}
    let oid = ac::core_inap_cs1_codes();
    assert_eq!(arcs(&oid), [0, 4, 0, 1, 1, 0, 3, 0]);
    // Under modules(0), where every context is under ac(1).
    assert_eq!(arcs(&oid)[5], 0);
    for context in [
        ac::cs1_ssp_to_scp(),
        ac::cs1_assist_handoff_ssp_to_scp(),
        ac::cs1_ip_to_scp(),
    ] {
        assert_eq!(arcs(&context)[5], 1);
        assert_ne!(context, oid);
    }
}

#[test]
fn the_value_returned_before_2_0_0_is_no_longer_the_ssp_to_scp_context() {
    // Until 2.0.0 `cs1_ssp_to_scp()` returned 0.4.0.1.1.0.3.0, the module
    // identifier above, and `core_inap_cs1_codes()` returned the context. A
    // dialogue opened with the old value names no application context a peer
    // knows. tests/harness.rs shows Wireshark agreeing on both.
    assert_ne!(arcs(&ac::cs1_ssp_to_scp()), [0, 4, 0, 1, 1, 0, 3, 0]);
    assert_ne!(arcs(&ac::core_inap_cs1_codes()), [0, 4, 0, 1, 1, 1, 0, 0]);
}
