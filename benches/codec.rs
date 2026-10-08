//! Codec micro-benchmarks: INAP operation-argument BER encode/decode throughput.
//!
//! Run with `cargo bench`. Numbers feed the README "Performance" table.
//!
//! Every fixture is built from the public API with **synthetic** values (fictional
//! `+1-555-01xx` numbers, made-up keys), so the benches measure exactly the work
//! this crate does, `rasn` BER pack/unpack of the INAP argument types, with no
//! I/O in the path. Covers the classic call-control triad InitialDP / Connect /
//! EventReportBCSM.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rasn::types::Integer;

use inap::operations::{ConnectArg, EventReportBcsmArg, InitialDpArg};
use inap::types::EventTypeBcsm;

/// A representative InitialDP (SSF → SCF): service key + a handful of the common
/// optional fields populated with synthetic wire bytes.
fn sample_initial_dp() -> InitialDpArg {
    InitialDpArg {
        service_key: Integer::from(42),
        called_party_number: Some(vec![0x03, 0x55, 0x01, 0x23].into()),
        calling_party_number: Some(vec![0x03, 0x55, 0x01, 0x99].into()),
        calling_partys_category: Some(vec![0x0a].into()),
        ip_ssp_capabilities: Some(vec![0x01].into()),
        ip_available: Some(vec![0x01].into()),
        location_number: None,
        original_called_party_id: None,
        high_layer_compatibility: None,
        service_interaction_indicators: None,
        additional_calling_party_number: None,
        forward_call_indicators: Some(vec![0x00, 0x01].into()),
        event_type_bcsm: Some(EventTypeBcsm::CollectedInfo),
        redirecting_party_id: None,
    }
}

/// A representative Connect (SCF → SSF): a single destination routing address.
fn sample_connect() -> ConnectArg {
    ConnectArg {
        destination_routing_address: vec![vec![0x03, 0x55, 0x01, 0x23].into()],
        correlation_id: None,
        original_called_party_id: None,
        scf_id: None,
    }
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
