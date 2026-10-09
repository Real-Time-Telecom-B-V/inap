//! Core INAP CS-1 application context names, ETS 300 374-1 (September 1994)
//! clause 6.5.
//!
//! An application context names the set of operations a TCAP dialogue may
//! carry; it travels in the dialogue portion of the first message. The Core
//! INAP CS-1 contexts are registered under the ETSI IN arc:
//!
//! ```text
//!   { ccitt(0) identified-organization(4) etsi(0) inDomain(1) in-network(1) }  = 0.4.0.1.1
//!   modules(0)  = 0.4.0.1.1.0     -- ASN.1 module identifiers, never on the wire
//!   ac(1)       = 0.4.0.1.1.1     -- application contexts
//! ```
//!
//! Only the contexts opened by an operation this crate has are given. The
//! remaining four of clause 6.5 (`cs1-scp-to-ssp(3)`, opened with
//! InitiateCallAttempt, and the traffic and service management contexts 4 to
//! 6) are not.
//!
//! ITU-T Q.1218 registers its own, different context names under
//! `{ ccitt recommendation q 1218 }`; they are not given here.

use rasn::types::ObjectIdentifier;

fn oid(arcs: &[u32]) -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(arcs.to_vec().into())
}

/// Arcs of [`cs1_ssp_to_scp`].
pub const CS1_SSP_TO_SCP: [u32; 8] = [0, 4, 0, 1, 1, 1, 0, 0];
/// Arcs of [`cs1_assist_handoff_ssp_to_scp`].
pub const CS1_ASSIST_HANDOFF_SSP_TO_SCP: [u32; 8] = [0, 4, 0, 1, 1, 1, 1, 0];
/// Arcs of [`cs1_ip_to_scp`].
pub const CS1_IP_TO_SCP: [u32; 8] = [0, 4, 0, 1, 1, 1, 2, 0];
/// Arcs of [`core_inap_cs1_codes`].
pub const CORE_INAP_CS1_CODES: [u32; 8] = [0, 4, 0, 1, 1, 0, 3, 0];

/// `Core-INAP-CS1-SSP-to-SCP-AC`, the dialogue an SSP opens with InitialDP.
///
/// `{ ... in-network(1) ac(1) cs1-ssp-to-scp(0) version1(0) }` =
/// `0.4.0.1.1.1.0.0`.
pub fn cs1_ssp_to_scp() -> ObjectIdentifier {
    oid(&CS1_SSP_TO_SCP)
}

/// `Core-INAP-CS1-assist-handoff-SSP-to-SCP-AC`, the dialogue an assisting or
/// hand-off SSP opens with AssistRequestInstructions.
///
/// `{ ... in-network(1) ac(1) cs1-assist-handoff-ssp-to-scp(1) version1(0) }`
/// = `0.4.0.1.1.1.1.0`.
pub fn cs1_assist_handoff_ssp_to_scp() -> ObjectIdentifier {
    oid(&CS1_ASSIST_HANDOFF_SSP_TO_SCP)
}

/// `Core-INAP-CS1-IP-to-SCP-AC`, the dialogue an intelligent peripheral opens
/// with AssistRequestInstructions.
///
/// `{ ... in-network(1) ac(1) cs1-ip-to-scp(2) version1(0) }` =
/// `0.4.0.1.1.1.2.0`.
pub fn cs1_ip_to_scp() -> ObjectIdentifier {
    oid(&CS1_IP_TO_SCP)
}

/// The identifier of the ASN.1 module `Core-INAP-CS1-Codes` (ETS 300 374-1
/// clause 6.4).
///
/// `{ ... in-network(1) modules(0) cs1-codes(3) version1(0) }` =
/// `0.4.0.1.1.0.3.0`. This names a module of the specification. It is not an
/// application context and has no place in a dialogue portion.
pub fn core_inap_cs1_codes() -> ObjectIdentifier {
    oid(&CORE_INAP_CS1_CODES)
}
