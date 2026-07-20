//! # inap
//!
//! **Intelligent Network Application Part (INAP), Capability Set 1** operation
//! codec, ITU-T Q.1218 / ETSI EN 300 374-1. BER encode/decode of the SSF ↔ SCF
//! (and SRF) operations that drive fixed-network Intelligent Network services:
//! service triggering, call routing, charging, and specialised-resource
//! (announcement / digit collection) control.
//!
//! INAP rides on TCAP over SCCP; this crate is the **operation layer**, the
//! argument/result types (via [`rasn`] ASN.1 BER) and the
//! [operation codes](op_codes). A consumer wraps an INAP argument in a TCAP
//! Invoke with the matching operation code; the surrounding dialogue (application
//! context, transaction IDs) is the TCAP layer's job.
//!
//! CAMEL's CAP (3GPP TS 29.078, the [`gsm_cap`](https://crates.io/crates/gsm_cap)
//! crate) was derived from INAP CS-2, so the two operation sets are near-siblings:
//! the shared call-control operations carry the same codes and closely matching
//! argument shapes, with INAP CS-1 adding the fixed-network assist / temporary
//! connection / call-information operations.
//!
//! ```
//! use inap::operations::ReleaseCallArg;
//!
//! // SCF → SSF: release the call with a Q.850 cause (synthetic bytes).
//! let rel = ReleaseCallArg(vec![0x90, 0x03].into());
//! let ber = inap::encode(&rel).unwrap();
//! let back: ReleaseCallArg = inap::decode(&ber).unwrap();
//! assert_eq!(rel, back);
//! ```
//!
//! (See [`operations`] for the full set and [`op_codes`] for the codes.)

pub mod address;
pub mod application_context;
pub mod error;
pub mod op_codes;
pub mod operations;
pub mod types;

#[cfg(feature = "python")]
pub mod python;

pub use error::InapError;
pub use op_codes::operation_name;

#[cfg(feature = "python")]
pub use python::register;

/// Encode an INAP operation argument/result to BER.
pub fn encode<T: rasn::Encode>(value: &T) -> Result<Vec<u8>, InapError> {
    rasn::ber::encode(value).map_err(|e| InapError::Encode(e.to_string()))
}

/// Decode an INAP operation argument/result from BER.
pub fn decode<T: rasn::Decode>(bytes: &[u8]) -> Result<T, InapError> {
    rasn::ber::decode(bytes).map_err(|e| InapError::Decode(e.to_string()))
}
