//! INAP CS-1 Application Context (and abstract-syntax) OIDs, ETSI EN 300 374-1.
//!
//! An application context identifies the INAP operation set used in a TCAP
//! dialogue. The Core INAP CS-1 identifiers live under the ETSI IN network arc:
//!
//! ```text
//!   in-network   = { itu-t(0) identified-organization(4) etsi(0)
//!                     inDomain(1) in-network(1) }        = 0.4.0.1.1
//!   ac(0)        = 0.4.0.1.1.0
//!   as(1)        = 0.4.0.1.1.1
//! ```
//!
//! The SSP-to-SCP application context (`cs1-ssp-to-scp`) is the one used on the
//! SSF ↔ SCF dialogue; `core-INAP-CS1-Codes` names the operations-and-errors
//! abstract syntax.

use rasn::types::ObjectIdentifier;

/// `cs1-ssp-to-scp`, the Core INAP CS-1 SSP ↔ SCP application context.
///
/// `0.4.0.1.1.0.3.0`.
pub fn cs1_ssp_to_scp() -> ObjectIdentifier {
    let arcs: Vec<u32> = vec![0, 4, 0, 1, 1, 0, 3, 0];
    ObjectIdentifier::new_unchecked(arcs.into())
}

/// `core-INAP-CS1-Codes`, the Core INAP CS-1 operations-and-errors abstract
/// syntax name.
///
/// `0.4.0.1.1.1.0.0`.
pub fn core_inap_cs1_codes() -> ObjectIdentifier {
    let arcs: Vec<u32> = vec![0, 4, 0, 1, 1, 1, 0, 0];
    ObjectIdentifier::new_unchecked(arcs.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssp_to_scp_oid_shape() {
        // cs1-ssp-to-scp = 0.4.0.1.1.0.3.0
        assert_eq!(
            cs1_ssp_to_scp().iter().copied().collect::<Vec<u32>>(),
            vec![0, 4, 0, 1, 1, 0, 3, 0]
        );
    }

    #[test]
    fn codes_oid_shape() {
        // core-INAP-CS1-Codes = 0.4.0.1.1.1.0.0
        assert_eq!(
            core_inap_cs1_codes().iter().copied().collect::<Vec<u32>>(),
            vec![0, 4, 0, 1, 1, 1, 0, 0]
        );
    }

    #[test]
    fn ac_and_as_are_distinct() {
        assert_ne!(cs1_ssp_to_scp(), core_inap_cs1_codes());
    }
}
