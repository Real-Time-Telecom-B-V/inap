//! Operation codes against ETS 300 374-1 (September 1994) clause 6.4, module
//! `Core-INAP-CS1-Codes`, one test per constant. ITU-T Q.1218 (10/95) clause
//! 2.1.4 assigns the same values.
//!
//! Each test states the `localValue` the specification assigns (copied from
//! the value assignment quoted beside it), checks the constant and the name
//! this crate gives it, and asks Wireshark what it calls an Invoke carrying
//! that code.

mod common;

use inap::op_codes;

#[track_caller]
fn check(constant: i64, specified: i64, name: &str) {
    assert_eq!(constant, specified, "{name}");
    assert_eq!(op_codes::operation_name(constant), Some(name));
    let Some(info) = common::info_column(constant, None) else {
        return;
    };
    assert!(
        info.ends_with(&format!(" {name}")),
        "Wireshark names operation {constant} differently: {info}"
    );
}

macro_rules! operation {
    ($test:ident, $constant:ident, $specified:literal, $name:literal) => {
        #[test]
        fn $test() {
            check(op_codes::$constant, $specified, $name);
        }
    };
}

// initialDP InitialDP ::= localValue 0
operation!(initial_dp_is_0, INITIAL_DP, 0, "initialDP");
// assistRequestInstructions AssistRequestInstructions ::= localValue 16
operation!(
    assist_request_instructions_is_16,
    ASSIST_REQUEST_INSTRUCTIONS,
    16,
    "assistRequestInstructions"
);
// establishTemporaryConnection EstablishTemporaryConnection ::= localValue 17
operation!(
    establish_temporary_connection_is_17,
    ESTABLISH_TEMPORARY_CONNECTION,
    17,
    "establishTemporaryConnection"
);
// disconnectForwardConnection DisconnectForwardConnection ::= localValue 18
operation!(
    disconnect_forward_connection_is_18,
    DISCONNECT_FORWARD_CONNECTION,
    18,
    "disconnectForwardConnection"
);
// connectToResource ConnectToResource ::= localValue 19
operation!(
    connect_to_resource_is_19,
    CONNECT_TO_RESOURCE,
    19,
    "connectToResource"
);
// connect Connect ::= localValue 20
operation!(connect_is_20, CONNECT, 20, "connect");
// releaseCall ReleaseCall ::= localValue 22
operation!(release_call_is_22, RELEASE_CALL, 22, "releaseCall");
// requestReportBCSMEvent RequestReportBCSMEvent ::= localValue 23
operation!(
    request_report_bcsm_event_is_23,
    REQUEST_REPORT_BCSM_EVENT,
    23,
    "requestReportBCSMEvent"
);
// eventReportBCSM EventReportBCSM ::= localValue 24
operation!(
    event_report_bcsm_is_24,
    EVENT_REPORT_BCSM,
    24,
    "eventReportBCSM"
);
// collectInformation CollectInformation ::= localValue 27
operation!(
    collect_information_is_27,
    COLLECT_INFORMATION,
    27,
    "collectInformation"
);
// continue Continue ::= localValue 31
operation!(continue_is_31, CONTINUE, 31, "continue");
// resetTimer ResetTimer ::= localValue 33
operation!(reset_timer_is_33, RESET_TIMER, 33, "resetTimer");
// furnishChargingInformation FurnishChargingInformation ::= localValue 34
operation!(
    furnish_charging_information_is_34,
    FURNISH_CHARGING_INFORMATION,
    34,
    "furnishChargingInformation"
);
// applyCharging ApplyCharging ::= localValue 35
operation!(apply_charging_is_35, APPLY_CHARGING, 35, "applyCharging");
// applyChargingReport ApplyChargingReport ::= localValue 36
operation!(
    apply_charging_report_is_36,
    APPLY_CHARGING_REPORT,
    36,
    "applyChargingReport"
);
// callInformationReport CallInformationReport ::= localValue 44
operation!(
    call_information_report_is_44,
    CALL_INFORMATION_REPORT,
    44,
    "callInformationReport"
);
// callInformationRequest CallInformationRequest ::= localValue 45
operation!(
    call_information_request_is_45,
    CALL_INFORMATION_REQUEST,
    45,
    "callInformationRequest"
);
// playAnnouncement PlayAnnouncement ::= localValue 47
operation!(
    play_announcement_is_47,
    PLAY_ANNOUNCEMENT,
    47,
    "playAnnouncement"
);
// promptAndCollectUserInformation PromptAndCollectUserInformation ::= localValue 48
operation!(
    prompt_and_collect_user_information_is_48,
    PROMPT_AND_COLLECT_USER_INFORMATION,
    48,
    "promptAndCollectUserInformation"
);
// specializedResourceReport SpecializedResourceReport ::= localValue 49
operation!(
    specialized_resource_report_is_49,
    SPECIALIZED_RESOURCE_REPORT,
    49,
    "specializedResourceReport"
);
// cancel Cancel ::= localValue 53
operation!(cancel_is_53, CANCEL, 53, "cancel");
// activityTest ActivityTest ::= localValue 55
operation!(activity_test_is_55, ACTIVITY_TEST, 55, "activityTest");

#[test]
fn codes_of_operations_this_crate_does_not_have_are_unnamed() {
    // ETS 300 374-1 assigns these too; the crate has neither a constant nor an
    // argument type for them: requestNotificationChargingEvent 25,
    // eventNotificationCharging 26, initiateCallAttempt 32, callGap 41,
    // activateServiceFiltering 42, serviceFilteringResponse 43,
    // sendChargingInformation 46.
    for code in [25, 26, 32, 41, 42, 43, 46] {
        assert_eq!(op_codes::operation_name(code), None, "{code}");
    }
    // Not assigned in capability set 1 at all.
    for code in [1, 21, 28, 54, 56, 250] {
        assert_eq!(op_codes::operation_name(code), None, "{code}");
    }
}
