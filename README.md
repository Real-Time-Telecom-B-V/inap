# inap

[![crates.io](https://img.shields.io/crates/v/inap.svg)](https://crates.io/crates/inap)
[![docs.rs](https://docs.rs/inap/badge.svg)](https://docs.rs/inap)
[![CI](https://github.com/Real-Time-Telecom-B-V/inap/actions/workflows/ci.yaml/badge.svg)](https://github.com/Real-Time-Telecom-B-V/inap/actions/workflows/ci.yaml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An **Intelligent Network Application Part (INAP), Capability Set 1** operation
codec, ITU-T Q.1218 / ETSI EN 300 374-1. BER encode/decode of the SSF ↔ SCF (and
SRF) operations that drive fixed-network Intelligent Network services: service
triggering, call routing, charging, and specialised-resource (announcement /
digit collection) control. It ships as **both** a Rust crate (`cargo add inap`)
and a Rust-backed Python wheel (`pip install inap`), built from one source tree
and one version.

INAP rides on TCAP over SCCP; this crate is the **operation layer**, the
argument/result types (via [`rasn`](https://crates.io/crates/rasn) ASN.1 BER) and
the operation codes. A consumer wraps an INAP argument in a TCAP Invoke with the
matching operation code; the dialogue (application context, transaction IDs) is
the TCAP layer's job.

CAMEL's CAP (3GPP TS 29.078) was derived from INAP CS-2, so the two operation
sets are near-siblings: the shared call-control operations carry the same codes
and closely matching argument shapes, with INAP CS-1 adding the fixed-network
assist / temporary-connection / call-information operations.

```rust
use inap::operations::ReleaseCallArg;

// SCF → SSF: release the call with a bare Q.850 cause (synthetic bytes).
let rel = ReleaseCallArg(vec![0x90, 0x03].into());
let ber = inap::encode(&rel).unwrap();
let back: ReleaseCallArg = inap::decode(&ber).unwrap();
assert_eq!(rel, back);
```

```python
import inap

# SSF → SCF: an InitialDP for a triggered call (synthetic bytes).
idp = inap.InitialDpArg(
    42,  # service key
    called_party_number=bytes([0x03, 0x15, 0x55, 0x01, 0x23]),
    event_type_bcsm=inap.EventTypeBcsm.CollectedInfo,
)
ber = idp.encode()                          # bytes (BER)
back = inap.InitialDpArg.decode(ber)        # -> InitialDpArg
```

The `initialDP` operation (SSF → SCF, sent when a call hits a detection point) and
the rest are in [`operations`](src/operations.rs); see
[`tests/roundtrip.rs`](tests/roundtrip.rs) for worked examples and
[`tests/vectors.rs`](tests/vectors.rs) for the tshark-validated known-answer
vectors.

## Coverage

Call establishment (InitialDP, Connect, ReleaseCall, ConnectToResource,
EstablishTemporaryConnection, AssistRequestInstructions,
DisconnectForwardConnection), event handling (RequestReportBCSMEvent,
EventReportBCSM, CollectInformation, Continue, ResetTimer, Cancel), charging
(ApplyCharging, ApplyChargingReport, FurnishChargingInformation), call
information (CallInformationRequest, CallInformationReport), and specialised
resources (PlayAnnouncement, PromptAndCollectUserInformation,
SpecializedResourceReport, ActivityTest), plus the
[`op_codes`](src/op_codes.rs) with `operation_name()` and the
[`application_context`](src/application_context.rs) OID helper
(`cs1-ssp-to-scp`).

The user-interaction operations (ConnectToResource, PlayAnnouncement,
PromptAndCollectUserInformation) are byte-identical between INAP and CAP; they are
the canonical definitions here, with `informationToSend` / `collectedInfo` carried
as opaque octet strings. The call-establishment / charging / call-information
operations are INAP-flavoured, for example `InitialDP` carries the fixed-network
`iPAvailable` / `serviceInteractionIndicators` / `forwardCallIndicators` and no
mobile IEs.

The **Python surface** covers the call-control set (InitialDP, Connect,
ReleaseCall, RequestReportBCSMEvent, EventReportBCSM, ApplyCharging), the shared
enums (`EventTypeBcsm` / `MonitorMode`), the operation codes, and the
`cs1_ssp_to_scp` application-context helper. Each operation type has
`.encode() -> bytes` and a `decode(bytes)` classmethod. The remaining operations
are Rust-only for now.

## Validation

The codec is validated against an independent oracle rather than by round-trip
alone (a shared encode/decode bug passes a round-trip). Each INAP argument is
wrapped in a TCAP Begin/Invoke inside an SCCP UnitData (INAP SSN 106) and
dissected with `tshark` (Wireshark's INAP dissector, which knows the CS-1
operation codes, application contexts and argument layouts): every operation
reports the correct name and decoded fields with no "Malformed" / "BER Error"
expert info. Those exact bytes are committed as known-answer vectors in
[`tests/vectors.rs`](tests/vectors.rs), which peel them back apart and assert the
decoded arguments.

## Performance

Single-core, `cargo bench` ([`benches/codec.rs`](benches/codec.rs)); the codec is
`rasn` BER pack/unpack of the INAP argument types, no I/O. All fixtures synthetic.

### Full-stack integration benchmark (INAP → TCAP → SCCP)

[`benches/integration.rs`](benches/integration.rs) assembles the classic IN
service exchange **the way it goes on the wire** and measures the whole path end
to end, encode an INAP argument, wrap it in a TCAP `Invoke` inside a
`Begin`/`Continue` transaction, carry that in an SCCP `UnitData` (UDT) with GT +
SSN addresses, then decode it all back:

* **InitialDP** (SSF → SCF, TCAP `Begin`)
* **Connect** (SCF → SSF, TCAP `Continue`)

using the sibling [`tcap`](https://github.com/Real-Time-Telecom-B-V/tcap) and
[`sccp`](https://github.com/Real-Time-Telecom-B-V/sccp) codecs (git dev-deps).

A counting-allocator [leak check](examples/leak_check.rs)
(`./scripts/mem_leak_test.sh`) hammers encode/decode across the call-control and
specialised-resource operations and asserts **live bytes stay flat** (Δ 0 over
millions of cycles). Both benches and the leak check run in CI.

The Python wheel is the same Rust code behind PyO3; per-call overhead is the
Python↔Rust boundary, not the codec. The module is `gil_used = false`, so it
loads on free-threaded ("no-GIL") CPython 3.13t / 3.14t.

## Install

```bash
cargo add inap          # Rust crate (zero pyo3 in the default build)
pip install inap        # Rust-backed Python wheel
```

## Development

```bash
cargo test                              # unit + integration + doctests
cargo test --features python            # + the PyO3 binding face
cargo clippy --all-targets -- -D warnings
cargo clippy --features python --lib -- -D warnings
cargo bench --no-run                    # incl. the INAP→TCAP→SCCP integration bench
./scripts/mem_leak_test.sh              # live-bytes leak check (PASS/FAIL)
cargo deny check                        # advisories, licenses, sources

# Python wheel
maturin develop && pytest python/tests -q
```

## License

MIT, see [LICENSE](LICENSE). Part of the SS7 stack (rides on TCAP; peer of the
MAP and CAP layers).
