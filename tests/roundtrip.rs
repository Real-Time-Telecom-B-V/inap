//! BER round-trip tests for INAP CS-1 operations. All values are synthetic, no
//! real subscriber data (fictional `+1-555-01xx` numbers, made-up keys).
//!
//! These are round-trips (encode → decode → assert-equal). The independent
//! known-answer validation against the Wireshark INAP dissector lives in
//! `tests/vectors.rs`.

use rasn::types::Integer;

use inap::op_codes;
use inap::operations::{
    ApplyChargingArg, ApplyChargingReportArg, AssistRequestInstructionsArg,
    CallInformationReportArg, CallInformationRequestArg, CancelArg, ConnectArg,
    ConnectToResourceArg, EstablishTemporaryConnectionArg, EventReportBcsmArg,
    FurnishChargingInformationArg, InitialDpArg, PlayAnnouncementArg,
    PromptAndCollectUserInformationArg, PromptAndCollectUserInformationRes, ReleaseCallArg,
    RequestReportBcsmEventArg, ResetTimerArg,
};
use inap::types::{
    BcsmEvent, EventTypeBcsm, LegId, MonitorMode, RequestedInformation, RequestedInformationType,
    RequestedInformationValue,
};

fn round_trip<T: rasn::Decode + rasn::Encode + std::fmt::Debug + PartialEq>(v: &T) {
    let ber = inap::encode(v).expect("encode");
    let back: T = inap::decode(&ber).expect("decode");
    assert_eq!(v, &back);
}

#[test]
fn initial_dp_round_trip() {
    let idp = InitialDpArg {
        service_key: Integer::from(42),
        called_party_number: Some(vec![0x03, 0x15, 0x55, 0x01, 0x00].into()), // synthetic
        calling_party_number: Some(vec![0x03, 0x15, 0x55, 0x01, 0x99].into()),
        calling_partys_category: Some(vec![0x0a].into()),
        ip_ssp_capabilities: Some(vec![0x01].into()),
        ip_available: Some(vec![0x01].into()),
        location_number: Some(vec![0x03, 0x15, 0x55, 0x01, 0x11].into()),
        original_called_party_id: None,
        high_layer_compatibility: Some(vec![0x91, 0x81].into()),
        service_interaction_indicators: Some(vec![0x01].into()),
        additional_calling_party_number: None,
        forward_call_indicators: Some(vec![0x00, 0x01].into()),
        event_type_bcsm: Some(EventTypeBcsm::CollectedInfo),
        redirecting_party_id: None,
    };
    round_trip(&idp);
}

#[test]
fn connect_round_trip() {
    let c = ConnectArg {
        destination_routing_address: vec![vec![0x03, 0x15, 0x55, 0x01, 0x23].into()],
        correlation_id: None,
        original_called_party_id: Some(vec![0x03, 0x15, 0x55, 0x01, 0x00].into()),
        scf_id: None,
    };
    round_trip(&c);
}

#[test]
fn release_call_round_trip() {
    round_trip(&ReleaseCallArg(vec![0x90, 0x03].into()));
}

#[test]
fn connect_to_resource_round_trip() {
    round_trip(&ConnectToResourceArg {
        resource_address_ipv4: Some(vec![0x03, 0x15, 0x55, 0x01, 0x77].into()),
        resource_address_none: None,
    });
    round_trip(&ConnectToResourceArg {
        resource_address_ipv4: None,
        resource_address_none: Some(()),
    });
}

#[test]
fn establish_temporary_connection_round_trip() {
    round_trip(&EstablishTemporaryConnectionArg {
        assisting_ssp_ip_routing_address: vec![0x03, 0x15, 0x55, 0x01, 0x55].into(),
        correlation_id: Some(vec![0xDE, 0xAD].into()),
        scf_id: None,
    });
}

#[test]
fn assist_request_instructions_round_trip() {
    round_trip(&AssistRequestInstructionsArg {
        correlation_id: vec![0x00, 0x03, 0x11, 0x55, 0x01].into(),
        ip_ssp_capabilities: Some(vec![0x01].into()),
    });
}

#[test]
fn request_report_bcsm_round_trip() {
    let r = RequestReportBcsmEventArg {
        bcsm_events: vec![
            BcsmEvent {
                event_type_bcsm: EventTypeBcsm::OAnswer,
                monitor_mode: MonitorMode::NotifyAndContinue,
                leg_id: None,
            },
            BcsmEvent {
                event_type_bcsm: EventTypeBcsm::ODisconnect,
                monitor_mode: MonitorMode::Interrupted,
                leg_id: Some(vec![0x01].into()),
            },
        ],
    };
    round_trip(&r);
}

#[test]
fn event_report_bcsm_round_trip() {
    round_trip(&EventReportBcsmArg {
        event_type_bcsm: EventTypeBcsm::OAnswer,
        leg_id: Some(LegId::ReceivingSideId(vec![0x02].into())),
        misc_call_info: Some(vec![0x30, 0x03, 0x80, 0x01, 0x01].into()),
    });
}

#[test]
fn reset_timer_round_trip() {
    round_trip(&ResetTimerArg {
        timer_id: Some(Integer::from(0)),
        timer_value: Integer::from(30),
    });
}

#[test]
fn cancel_round_trip() {
    round_trip(&CancelArg::InvokeId(Integer::from(5)));
    round_trip(&CancelArg::AllRequests(()));
}

#[test]
fn apply_charging_round_trip() {
    round_trip(&ApplyChargingArg {
        ach_billing_charging_characteristics: vec![0x00, 0x01, 0x02].into(),
        party_to_charge: Some(LegId::SendingSideId(vec![0x01].into())),
    });
}

#[test]
fn apply_charging_report_round_trip() {
    round_trip(&ApplyChargingReportArg(vec![0x0a, 0x01, 0x00].into()));
}

#[test]
fn furnish_charging_information_round_trip() {
    round_trip(&FurnishChargingInformationArg(
        vec![0x01, 0x02, 0x03].into(),
    ));
}

#[test]
fn call_information_request_round_trip() {
    round_trip(&CallInformationRequestArg {
        requested_information_type_list: vec![
            RequestedInformationType::CallAttemptElapsedTime,
            RequestedInformationType::CallConnectedElapsedTime,
            RequestedInformationType::ReleaseCause,
        ],
        leg_id: Some(LegId::SendingSideId(vec![0x01].into())),
    });
}

#[test]
fn call_information_report_round_trip() {
    round_trip(&CallInformationReportArg {
        requested_information_list: vec![
            RequestedInformation {
                requested_information_type: RequestedInformationType::CallConnectedElapsedTime,
                requested_information_value:
                    RequestedInformationValue::CallConnectedElapsedTimeValue(Integer::from(1200)),
            },
            RequestedInformation {
                requested_information_type: RequestedInformationType::ReleaseCause,
                requested_information_value: RequestedInformationValue::ReleaseCauseValue(
                    vec![0x90, 0x10].into(),
                ),
            },
        ],
        leg_id: None,
    });
}

#[test]
fn play_announcement_round_trip() {
    round_trip(&PlayAnnouncementArg {
        information_to_send: vec![0xa1, 0x03, 0x80, 0x01, 0x07].into(),
        disconnect_from_ip_forbidden: Some(true),
        request_announcement_complete: Some(true),
    });
}

#[test]
fn prompt_and_collect_round_trip() {
    round_trip(&PromptAndCollectUserInformationArg {
        collected_info: vec![0xa0, 0x03, 0x81, 0x01, 0x0a].into(),
        disconnect_from_ip_forbidden: Some(false),
        information_to_send: None,
    });
    round_trip(&PromptAndCollectUserInformationRes::DigitsResponse(
        vec![0x12, 0x34].into(),
    ));
}

#[test]
fn operation_names() {
    assert_eq!(
        op_codes::operation_name(op_codes::INITIAL_DP),
        Some("initialDP")
    );
    assert_eq!(op_codes::operation_name(op_codes::CONNECT), Some("connect"));
    assert_eq!(
        op_codes::operation_name(op_codes::ESTABLISH_TEMPORARY_CONNECTION),
        Some("establishTemporaryConnection")
    );
    assert_eq!(
        op_codes::operation_name(op_codes::CALL_INFORMATION_REPORT),
        Some("callInformationReport")
    );
    assert_eq!(op_codes::operation_name(999), None);
}
