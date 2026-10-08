# inap

[![crates.io](https://img.shields.io/crates/v/inap.svg)](https://crates.io/crates/inap)
[![docs.rs](https://docs.rs/inap/badge.svg)](https://docs.rs/inap)
[![CI](https://github.com/Real-Time-Telecom-B-V/inap/actions/workflows/ci.yaml/badge.svg)](https://github.com/Real-Time-Telecom-B-V/inap/actions/workflows/ci.yaml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An **Intelligent Network Application Part (INAP), Capability Set 1** operation
codec, ETSI ETS 300 374-1 (Core INAP) with the additional members of ITU-T
Q.1218. BER encode/decode of the SSF ↔ SCF (and SRF) operations that drive fixed-network Intelligent Network services: service
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
the files under [`tests/`](tests) for worked examples of every argument, each
with the octets it encodes to.

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

`continue`, `disconnectForwardConnection` and `activityTest` have no argument
and `specializedResourceReport` carries a bare NULL; those have an operation
code and no type. The argument of `collectInformation` is not modelled.

The **Python surface** covers the call-control set (InitialDP, Connect,
ReleaseCall, RequestReportBCSMEvent, EventReportBCSM, ApplyCharging), the shared
enums (`EventTypeBcsm` / `MonitorMode`), the operation codes, and the
application-context helpers. Each operation type has `.encode() -> bytes` and a
`decode(bytes)` classmethod. The classes expose a subset of each argument's
members; `decode` raises `InapCodecError` for a message carrying a member the
class has no attribute for, it does not drop the member. The remaining
operations are Rust-only for now.

## Conformance

**Which specification.** The types are modelled from two documents and each
member's documentation says where it comes from:

* ETS 300 374-1, September 1994 (ETSI Core INAP CS-1), clauses 6.3 to 6.5: the
  baseline.
* ITU-T Q.1218 (10/95), clause 2.1.3: members and alternatives that Q.1218 has
  and Core INAP left out are modelled so that a message from a Q.1218 entity
  decodes. They are marked "Q.1218 only".

Capability set 2 is not implemented. One capability set 2 member is present for
historical reasons (`legID` in the two call information arguments) and marked.

**How it is checked.** A round-trip through the crate's own decoder cannot catch
a mistake the encoder and the decoder share, so every encoding has two
independent checks:

* a byte vector assembled by hand from the ASN.1, with its derivation in a
  comment, that the value must encode to and decode from;
* a dissection by Wireshark: the argument is wrapped in TCAP, SCCP (subsystem
  number 106) and M3UA, handed to `tshark`, and the fields its INAP dissector
  decoded are asserted by name and value, along with the absence of any
  malformed, unknown or BER-error marker.

Both are needed. Wireshark does not check the constructed bit of a context tag,
so it accepts a primitive element where an explicit wrapper is required; the
byte vectors pin that. Wireshark's copy of the INAP ASN.1 is the capability set
4 module set of Q.1248, which keeps the capability set 1 tags but differs in
two places that matter here: it has no member on `[1]` of ApplyChargingArg
(`sendCalculationToSCPIndication` in ETS 300 374-1), and Wireshark 4.6 has a
dissector bug on `bcsmEventCorrelationID`. Those two members rest on the byte
vectors alone. The Wireshark tests are skipped with a `SKIP` line when `tshark`
or `text2pcap` is missing (set `INAP_REQUIRE_TSHARK=1` to fail instead); the
byte vectors always run.

**Decoding is strict.** `rasn` 0.28 reports an OPTIONAL member behind an explicit
tag as absent when its content cannot be decoded, returns a SEQUENCE OF without
a last element it cannot decode, and ignores octets after the value. In INAP
every CHOICE-typed member (`legID`, `partyToCharge`, the event specific
information, `bearerCapability`, `informationToSend`) is explicitly tagged, so a
malformed one would decode as a message without it. `inap::decode` re-encodes
what it decoded and compares the two encodings element by element; anything on
the wire that is not accounted for is an error.
[`tests/decoder_strictness.rs`](tests/decoder_strictness.rs) reproduces each
case.

## Performance

Single-core, `cargo bench` ([`benches/codec.rs`](benches/codec.rs)); the codec is
`rasn` BER pack/unpack of the INAP argument types, no I/O. All fixtures synthetic.

The strict decode costs one extra encode and a walk over both encodings. On an
InitialDP with every Core INAP member (106 octets) `rasn` alone decodes in about
0.73 µs and `inap::decode` in about 1.5 µs on one core of the development
machine (`initial_dp_full/decode_rasn_only` against `initial_dp_full/decode`).

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
INAP_REQUIRE_TSHARK=1 cargo test        # fail instead of skip when tshark is missing
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
