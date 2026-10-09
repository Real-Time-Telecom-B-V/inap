//! Codec micro-benchmarks: INAP operation-argument BER encode/decode throughput.
//!
//! Run with `cargo bench`. Numbers feed the README "Performance" table.
//!
//! Every fixture is built from the public API with **synthetic** values (fictional
//! `+1-555-01xx` numbers, made-up keys), so the benches measure exactly the work
//! this crate does, `rasn` BER pack/unpack of the INAP argument types, with no
//! I/O in the path. Covers the classic call-control triad InitialDP / Connect /
//! EventReportBCSM, and the cost of the strict decode on the largest argument
//! the crate has (an InitialDP with every Core INAP member): `decode` is what
//! `inap::decode` costs, `decode_rasn_only` is `rasn` alone, and the
//! difference is the re-encode and comparison that keeps a malformed member
//! from being dropped silently.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use inap::operations::{ConnectArg, EventReportBcsmArg, InitialDpArg};
use inap::types::{
    BearerCapability, CgEncountered, CriticalityType, EventTypeBcsm, ExtensionField,
};
use rasn::types::Any;

/// A representative InitialDP (SSF → SCF): service key + a handful of the common
/// optional fields populated with synthetic wire bytes.
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

/// The largest argument: an InitialDP with every member ETS 300 374-1 defines,
/// including an extension and the explicitly tagged bearer capability.
fn full_initial_dp() -> InitialDpArg {
    InitialDpArg {
        called_party_number: Some(vec![0x04, 0x10, 0x51, 0x55, 0x10, 0x32].into()),
        calling_party_number: Some(vec![0x04, 0x13, 0x51, 0x55, 0x10, 0x99].into()),
        calling_partys_category: Some(vec![0x0a].into()),
        cg_encountered: Some(CgEncountered::ManualCgEncountered),
        ip_ssp_capabilities: Some(vec![0x01].into()),
        ip_available: Some(vec![0x01].into()),
        location_number: Some(vec![0x04, 0x13, 0x51, 0x55, 0x10, 0x11].into()),
        original_called_party_id: Some(vec![0x04, 0x13, 0x51, 0x55, 0x10, 0x44].into()),
        extensions: Some(vec![ExtensionField {
            extension_type: 1.into(),
            criticality: Some(CriticalityType::Abort),
            value: Any::new(vec![0x01, 0x01, 0xff]),
        }]),
        high_layer_compatibility: Some(vec![0x91, 0x81].into()),
        service_interaction_indicators: Some(vec![0x01].into()),
        additional_calling_party_number: Some(
            vec![0x00, 0x04, 0x13, 0x51, 0x55, 0x10, 0x88].into(),
        ),
        forward_call_indicators: Some(vec![0x20, 0x01].into()),
        bearer_capability: Some(BearerCapability::BearerCap(vec![0x80, 0x90, 0xa3].into())),
        event_type_bcsm: Some(EventTypeBcsm::CollectedInfo),
        redirecting_party_id: Some(vec![0x04, 0x13, 0x51, 0x55, 0x10, 0x77].into()),
        redirection_information: Some(vec![0x03, 0x01].into()),
        ..InitialDpArg::new(42)
    }
}

/// A representative Connect (SCF → SSF): a single destination routing address.
fn sample_connect() -> ConnectArg {
    ConnectArg::new(vec![0x03, 0x55, 0x01, 0x23].into())
}

/// A representative EventReportBCSM (SSF → SCF): an O-Answer report.
fn sample_event_report() -> EventReportBcsmArg {
    EventReportBcsmArg::new(EventTypeBcsm::OAnswer)
}

fn bench_codec(c: &mut Criterion) {
    let initial_dp = sample_initial_dp();
    let connect = sample_connect();
    let event_report = sample_event_report();

    let initial_dp_ber = inap::encode(&initial_dp).expect("encode idp");
    let connect_ber = inap::encode(&connect).expect("encode connect");
    let event_report_ber = inap::encode(&event_report).expect("encode erb");

    let mut g = c.benchmark_group("codec");
    g.throughput(Throughput::Elements(1));

    g.bench_function("initial_dp/encode", |b| {
        b.iter_batched(
            || initial_dp.clone(),
            |v| inap::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("initial_dp/decode", |b| {
        b.iter(|| inap::decode::<InitialDpArg>(&initial_dp_ber).unwrap())
    });

    let full = full_initial_dp();
    let full_ber = inap::encode(&full).expect("encode full idp");
    g.bench_function("initial_dp_full/encode", |b| {
        b.iter_batched(
            || full.clone(),
            |v| inap::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("initial_dp_full/decode", |b| {
        b.iter(|| inap::decode::<InitialDpArg>(&full_ber).unwrap())
    });
    g.bench_function("initial_dp_full/decode_rasn_only", |b| {
        b.iter(|| rasn::ber::decode::<InitialDpArg>(&full_ber).unwrap())
    });

    g.bench_function("connect/encode", |b| {
        b.iter_batched(
            || connect.clone(),
            |v| inap::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("connect/decode", |b| {
        b.iter(|| inap::decode::<ConnectArg>(&connect_ber).unwrap())
    });

    g.bench_function("event_report_bcsm/encode", |b| {
        b.iter_batched(
            || event_report.clone(),
            |v| inap::encode(&v).unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("event_report_bcsm/decode", |b| {
        b.iter(|| inap::decode::<EventReportBcsmArg>(&event_report_ber).unwrap())
    });

    g.finish();
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);
