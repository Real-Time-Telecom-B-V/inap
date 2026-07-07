//! Memory-leak check.
//!
//! A counting global allocator tracks **live bytes** (allocated − freed), RSS is
//! too noisy (the OS/allocator retains freed pages), but live bytes are exact, so
//! a real leak shows up as monotonic growth. Two phases hammer the INAP BER codec:
//!
//!   1. **call control**, encode + decode InitialDP, Connect and EventReportBCSM
//!      for many cycles (the `rasn` BER pack/unpack + `Vec` churn path).
//!   2. **specialised resources**, the same for PlayAnnouncement + ApplyCharging.
//!
//! Each phase asserts live bytes return to a flat baseline. Exits non-zero on a
//! leak. All fixtures are synthetic. Driven by `scripts/mem_leak_test.sh`.
//!
//! Run: `cargo run --release --example leak_check`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, Ordering};

use rasn::types::Integer;

use inap::operations::{
    ApplyChargingArg, ConnectArg, EventReportBcsmArg, InitialDpArg, PlayAnnouncementArg,
};
use inap::types::{EventTypeBcsm, LegId};

// ── Counting allocator ──────────────────────────────────────────────────────
static LIVE: AtomicI64 = AtomicI64::new(0);

struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
        LIVE.fetch_sub(l.size() as i64, Ordering::Relaxed);
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn realloc(&self, ptr: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, l, new_size);
        if !p.is_null() {
            LIVE.fetch_add(new_size as i64 - l.size() as i64, Ordering::Relaxed);
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> i64 {
    LIVE.load(Ordering::Relaxed)
}

// ── Synthetic fixtures ───────────────────────────────────────────────────────
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

fn sample_connect() -> ConnectArg {
    ConnectArg {
        destination_routing_address: vec![vec![0x03, 0x55, 0x01, 0x23].into()],
        correlation_id: None,
        original_called_party_id: None,
        scf_id: None,
    }
}

fn sample_event_report() -> EventReportBcsmArg {
    EventReportBcsmArg {
        event_type_bcsm: EventTypeBcsm::OAnswer,
        leg_id: None,
        misc_call_info: None,
    }
}

fn sample_play_announcement() -> PlayAnnouncementArg {
    PlayAnnouncementArg {
        information_to_send: vec![0xa1, 0x03, 0x80, 0x01, 0x07].into(),
        disconnect_from_ip_forbidden: Some(true),
        request_announcement_complete: Some(true),
    }
}

fn sample_apply_charging() -> ApplyChargingArg {
    ApplyChargingArg {
        ach_billing_charging_characteristics: vec![0x00, 0x01, 0x02].into(),
        party_to_charge: Some(LegId::SendingSideId(vec![0x01].into())),
    }
}

// ── Phase 1: call-control codec ──────────────────────────────────────────────
fn call_control_cycle(iters: usize) {
    let idp = sample_initial_dp();
    let connect = sample_connect();
    let erb = sample_event_report();
    for _ in 0..iters {
        let b = inap::encode(&idp).unwrap();
        std::hint::black_box(inap::decode::<InitialDpArg>(&b).unwrap());
        let b = inap::encode(&connect).unwrap();
        std::hint::black_box(inap::decode::<ConnectArg>(&b).unwrap());
        let b = inap::encode(&erb).unwrap();
        std::hint::black_box(inap::decode::<EventReportBcsmArg>(&b).unwrap());
    }
}

// ── Phase 2: specialised-resource + charging codec ───────────────────────────
fn srf_cycle(iters: usize) {
    let ann = sample_play_announcement();
    let ac = sample_apply_charging();
    for _ in 0..iters {
        let b = inap::encode(&ann).unwrap();
        std::hint::black_box(inap::decode::<PlayAnnouncementArg>(&b).unwrap());
        let b = inap::encode(&ac).unwrap();
        std::hint::black_box(inap::decode::<ApplyChargingArg>(&b).unwrap());
    }
}

fn report(phase: &str, base: i64) -> i64 {
    let growth = live() - base;
    println!("  {phase}: live = {} bytes (Δ {:+})", live(), growth);
    growth
}

fn main() {
    const ITERS: usize = 100_000;
    const CYCLES: usize = 10;
    const BUDGET: i64 = 64 * 1024;

    // Phase 1: call control.
    println!("[call control] {CYCLES} x {ITERS} encode+decode round-trips (InitialDP + Connect + EventReportBCSM)");
    call_control_cycle(ITERS); // warm up
    let cc_base = live();
    for c in 1..=CYCLES {
        call_control_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), cc_base);
    }
    let cc_growth = live() - cc_base;

    // Phase 2: specialised resources + charging.
    println!(
        "\n[srf] {CYCLES} x {ITERS} encode+decode round-trips (PlayAnnouncement + ApplyCharging)"
    );
    srf_cycle(ITERS); // warm up
    let srf_base = live();
    for c in 1..=CYCLES {
        srf_cycle(ITERS);
        report(&format!("cycle {c:>2}/{CYCLES}"), srf_base);
    }
    let srf_growth = live() - srf_base;

    // Verdict.
    println!();
    let mut ok = true;
    if cc_growth > BUDGET {
        eprintln!("FAIL: call-control live bytes grew {cc_growth} (> {BUDGET})");
        ok = false;
    }
    if srf_growth > BUDGET {
        eprintln!("FAIL: SRF live bytes grew {srf_growth} (> {BUDGET})");
        ok = false;
    }
    if !ok {
        std::process::exit(1);
    }
    println!("PASS: call-control Δ {cc_growth} ≤ {BUDGET}; SRF Δ {srf_growth} ≤ {BUDGET}");
}
