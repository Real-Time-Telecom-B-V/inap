//! Full-stack IN integration benchmark: **INAP → TCAP → SCCP** end to end.
//!
//! This is the headline benchmark. It assembles the classic IN service exchange
//! as it would go on the wire and measures the whole path at volume, "spam a lot
//! of InitialDP + Connect, then TCAP, then SCCP":
//!
//! * **InitialDP** (SSF → SCF): the SSF reports a triggered call. The INAP
//!   `InitialDpArg` is encoded (this crate), wrapped in a TCAP `Invoke` inside a
//!   `Begin` transaction (`tcap`), and carried in an SCCP `UnitData` (UDT) with
//!   GT + SSN addresses (`sccp`) → full wire bytes.
//! * **Connect** (SCF → SSF): the SCP routes the call. The INAP `ConnectArg`
//!   rides a TCAP `Invoke` inside a `Continue` (the dialogue is already open),
//!   again in an SCCP UDT.
//!
//! Two directions are benched at volume:
//!   * **encode**, INAP arg → TCAP component/transaction → SCCP UDT → bytes.
//!   * **decode**, SCCP UDT bytes → TCAP transaction → TCAP Invoke parameter →
//!     INAP arg.
//!
//! All values are **synthetic** (fictional `+1-555-01xx` GT digits, the INAP SSN
//! 106); nothing here is captured traffic. Throughput is reported per full stack
//! message (`Throughput::Elements(1)`), i.e. messages/sec.
//!
//! `tcap` and `sccp` are git dev-dependencies. If either cannot be resolved this
//! bench won't build; the `codec` bench (inap only) still does.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rasn::types::Any;

use inap::operations::{ConnectArg, InitialDpArg};
use inap::types::EventTypeBcsm;
use inap::{application_context, op_codes};

use sccp::{GlobalTitle, SccpAddress, SubsystemNumber, UnitData};
use tcap::{Begin, Component, Continue, Invoke, OperationCode, TcapMessage};

/// The INAP subsystem number (Wireshark's default `inap.ssn`).
const INAP_SSN: u8 = 106;

// ── Synthetic INAP fixtures ──────────────────────────────────────────────────

fn sample_initial_dp() -> InitialDpArg {
    InitialDpArg {
        called_party_number: Some(vec![0x03, 0x55, 0x01, 0x23].into()),
        calling_party_number: Some(vec![0x03, 0x55, 0x01, 0x99].into()),
        calling_partys_category: Some(vec![0x0a].into()),
        ip_ssp_capabilities: Some(vec![0x01].into()),
        ip_available: Some(vec![0x01].into()),
        forward_call_indicators: Some(vec![0x00, 0x01].into()),
        event_type_bcsm: Some(EventTypeBcsm::CollectedInfo),
        ..InitialDpArg::new(42)
    }
}

fn sample_connect() -> ConnectArg {
    ConnectArg::new(vec![0x03, 0x55, 0x01, 0x23].into())
}

// ── SCCP addressing (synthetic GT digits, INAP SSN) ──────────────────────────

/// SSF-side address: an E.164 GT (`+1-555-01xx`) at the INAP subsystem.
fn ssf_address() -> SccpAddress {
    let gt = GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,  // E.164
        encoding_scheme: 1, // BCD odd
        nature_of_address: 4,
        digits: "15550100123".to_string(),
    };
    SccpAddress::with_gt(gt, Some(SubsystemNumber::Other(INAP_SSN)))
}

/// SCF-side address: another synthetic E.164 GT at the INAP subsystem.
fn scf_address() -> SccpAddress {
    let gt = GlobalTitle::Gt0100 {
        translation_type: 0,
        numbering_plan: 1,
        encoding_scheme: 1,
        nature_of_address: 4,
        digits: "15550199001".to_string(),
    };
    SccpAddress::with_gt(gt, Some(SubsystemNumber::Other(INAP_SSN)))
}

// ── Full-stack encode: INAP → TCAP → SCCP → wire bytes ───────────────────────

/// Encode an InitialDP as a full INAP→TCAP(Begin)→SCCP(UDT) message.
///
/// SSF → SCF: the SSF opens the dialogue, so it's a TCAP `Begin` from SSF
/// (called = SCF, calling = SSF).
fn encode_initial_dp_stack(idp: &InitialDpArg) -> Vec<u8> {
    // 1. INAP: encode the operation argument to BER.
    let inap_ber = inap::encode(idp).expect("inap encode");

    // 2. TCAP: wrap in an Invoke(initialDP) inside a Begin transaction.
    let invoke = Invoke {
        invoke_id: 1,
        linked_id: None,
        operation_code: OperationCode::Local(op_codes::INITIAL_DP),
        parameter: Some(Any::new(inap_ber)),
    };
    let begin = Begin {
        otid: vec![0x00, 0x00, 0x10, 0x01].into(),
        dialogue_portion: None,
        components: Some(vec![Component::Invoke(invoke)]),
    };
    let tcap_bytes = tcap::encode(&TcapMessage::Begin(begin)).expect("tcap encode");

    // 3. SCCP: carry the TCAP payload in a UDT (SSF → SCF).
    let udt = UnitData::new(scf_address(), ssf_address(), tcap_bytes);
    udt.encode().expect("sccp encode")
}

/// Encode a Connect as a full INAP→TCAP(Continue)→SCCP(UDT) message.
///
/// SCF → SSF: the dialogue is already open, so it's a TCAP `Continue`
/// (called = SSF, calling = SCF).
fn encode_connect_stack(connect: &ConnectArg) -> Vec<u8> {
    let inap_ber = inap::encode(connect).expect("inap encode");

    let invoke = Invoke {
        invoke_id: 2,
        linked_id: None,
        operation_code: OperationCode::Local(op_codes::CONNECT),
        parameter: Some(Any::new(inap_ber)),
    };
    let cont = Continue {
        otid: vec![0x00, 0x00, 0x20, 0x02].into(),
        dtid: vec![0x00, 0x00, 0x10, 0x01].into(),
        dialogue_portion: None,
        components: Some(vec![Component::Invoke(invoke)]),
    };
    let tcap_bytes = tcap::encode(&TcapMessage::Continue(cont)).expect("tcap encode");

    let udt = UnitData::new(ssf_address(), scf_address(), tcap_bytes);
    udt.encode().expect("sccp encode")
}

// ── Full-stack decode: wire bytes → SCCP → TCAP → INAP ───────────────────────

/// Peel an InitialDP back out of a full stack message: SCCP UDT → TCAP Begin →
/// Invoke parameter → INAP `InitialDpArg`.
fn decode_initial_dp_stack(wire: &[u8]) -> InitialDpArg {
    let udt = UnitData::decode(wire).expect("sccp decode");
    let tcap_msg = tcap::decode(&udt.data).expect("tcap decode");
    let components = match tcap_msg {
        TcapMessage::Begin(b) => b.components.expect("components"),
        other => panic!("expected Begin, got {other}"),
    };
    let param = match &components[0] {
        Component::Invoke(inv) => inv.parameter.as_ref().expect("parameter"),
        other => panic!("expected Invoke, got {other}"),
    };
    inap::decode::<InitialDpArg>(param.as_bytes()).expect("inap decode")
}

/// Peel a Connect back out of a full stack message: SCCP UDT → TCAP Continue →
/// Invoke parameter → INAP `ConnectArg`.
fn decode_connect_stack(wire: &[u8]) -> ConnectArg {
    let udt = UnitData::decode(wire).expect("sccp decode");
    let tcap_msg = tcap::decode(&udt.data).expect("tcap decode");
    let components = match tcap_msg {
        TcapMessage::Continue(c) => c.components.expect("components"),
        other => panic!("expected Continue, got {other}"),
    };
    let param = match &components[0] {
        Component::Invoke(inv) => inv.parameter.as_ref().expect("parameter"),
        other => panic!("expected Invoke, got {other}"),
    };
    inap::decode::<ConnectArg>(param.as_bytes()).expect("inap decode")
}

fn bench_integration(c: &mut Criterion) {
    let idp = sample_initial_dp();
    let connect = sample_connect();

    // Sanity: the stack round-trips before we time it, and the AC helper is wired
    // (the dialogue would carry cs1_ssp_to_scp() in a real setup).
    let idp_wire = encode_initial_dp_stack(&idp);
    let connect_wire = encode_connect_stack(&connect);
    assert_eq!(decode_initial_dp_stack(&idp_wire), idp);
    assert_eq!(decode_connect_stack(&connect_wire), connect);
    let _ac = application_context::cs1_ssp_to_scp();

    let mut g = c.benchmark_group("integration");
    // One full stack message per iteration → messages/sec.
    g.throughput(Throughput::Elements(1));

    // InitialDP: SSF → SCF (Begin).
    g.bench_function("initial_dp/encode_stack", |b| {
        b.iter_batched(
            || idp.clone(),
            |v| encode_initial_dp_stack(&v),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("initial_dp/decode_stack", |b| {
        b.iter(|| decode_initial_dp_stack(&idp_wire))
    });

    // Connect: SCF → SSF (Continue).
    g.bench_function("connect/encode_stack", |b| {
        b.iter_batched(
            || connect.clone(),
            |v| encode_connect_stack(&v),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("connect/decode_stack", |b| {
        b.iter(|| decode_connect_stack(&connect_wire))
    });

    // A combined "one InitialDP + one Connect" exchange, encode both directions,
    // the realistic per-call IN signalling burst.
    g.bench_function("call_exchange/encode_both", |b| {
        b.iter_batched(
            || (idp.clone(), connect.clone()),
            |(a, b2)| {
                let w1 = encode_initial_dp_stack(&a);
                let w2 = encode_connect_stack(&b2);
                (w1, w2)
            },
            BatchSize::SmallInput,
        )
    });

    g.finish();
}

criterion_group!(benches, bench_integration);
criterion_main!(benches);
