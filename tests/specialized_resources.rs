//! ConnectToResource (op 19), PlayAnnouncement (op 47) and
//! PromptAndCollectUserInformation (op 48) with its result: ETS 300 374-1
//! (September 1994) clause 6.3 and ITU-T Q.1218 (10/95) clause 2.1.3.
//!
//! Vectors are assembled by hand from the ASN.1; `tests/bcsm_events.rs`
//! explains the tag octet rules.
//!
//! `informationToSend`, `collectedInfo` and `messageID` are CHOICEs behind a
//! context tag, so each is an EXPLICIT, constructed wrapper. Wireshark does
//! not look at the constructed bit and reads `80` where `a0` is required; the
//! byte vectors are what pins it here.

mod common;

use common::{
    dissect, dissect_unchecked, extensions, known_answer, octets, refused, vector, Carrier,
    EXTENSION,
};
use inap::op_codes;
use inap::operations::{
    ConnectToResourceArg, PlayAnnouncementArg, PromptAndCollectUserInformationArg,
    PromptAndCollectUserInformationRes,
};
use inap::types::{
    CollectedDigits, CollectedInfo, ErrorTreatment, InbandInfo, InformationToSend, LegId,
    MessageId, MessageIdText, ResourceAddress, ResourceAddressBoth, Tone, VariableMessage,
    VariablePart,
};
use rasn::types::Ia5String;

fn ia5(text: &str) -> Ia5String {
    Ia5String::try_from(text).unwrap()
}

// ── ConnectToResource ───────────────────────────────────────────────────────

#[test]
fn connect_to_resource_with_an_address_and_every_other_member() {
    let arg = ConnectToResourceArg {
        extensions: Some(extensions()),
        service_interaction_indicators: Some(octets("01")),
        ..ConnectToResourceArg::new(ResourceAddress::IpRoutingAddress(octets(
            "04 10 51 55 10 77",
        )))
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 1a                                  -- 8 + 15 + 3 = 26
           80 06 04 10 51 55 10 77             -- resourceAddress: the CHOICE has no tag of its
                                               --   own, so ipRoutingAddress [0] shows directly
           a4 0d                               -- extensions [4]
              {EXTENSION}
           9e 01 01                            -- serviceInteractionIndicators [30]
        "
        ),
    );
    let Some(d) = dissect(op_codes::CONNECT_TO_RESOURCE, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("inap.resourceAddress", "0")
        .hex("inap.ipRoutingAddress", "041051551077")
        .show("inap.extensions", "1")
        .hex("inap.serviceInteractionIndicators", "01");
}

#[test]
fn connect_to_resource_without_an_address() {
    let ber = known_answer(
        &ConnectToResourceArg::new(ResourceAddress::None(())),
        "30 02 83 00                           -- resourceAddress: none [3] NULL",
    );
    let Some(d) = dissect(op_codes::CONNECT_TO_RESOURCE, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("inap.resourceAddress", "3")
        .present("inap.none_element");
}

#[test]
fn connect_to_resource_q1218_alternatives() {
    // legID [1] and both [2] are Q.1218 only.
    let ber = known_answer(
        &ConnectToResourceArg::new(ResourceAddress::LegId(LegId::sending(1))),
        "
        30 05
           a1 03                               -- legID [1]: LegID is a CHOICE, EXPLICIT
              80 01 01                         --   sendingSideID leg 1
        ",
    );
    if let Some(d) = dissect(op_codes::CONNECT_TO_RESOURCE, Some(&ber), Carrier::Continue) {
        d.show("inap.resourceAddress", "1")
            .show("inap.legID", "0")
            .hex("inap.sendingSideID", "01");
    }

    let ber = known_answer(
        &ConnectToResourceArg::new(ResourceAddress::Both(ResourceAddressBoth {
            ip_routing_address: octets("04 10 51 55 10 77"),
            leg_id: LegId::sending(1),
        })),
        "
        30 0f
           a2 0d                               -- both [2] SEQUENCE, 8 + 5
              80 06 04 10 51 55 10 77          --   ipRoutingAddress [0]
              a1 03 80 01 01                   --   legID [1] EXPLICIT: sendingSideID leg 1
        ",
    );
    if let Some(d) = dissect(op_codes::CONNECT_TO_RESOURCE, Some(&ber), Carrier::Continue) {
        d.show("inap.resourceAddress", "2")
            .hex("inap.ipRoutingAddress", "041051551077")
            .hex("inap.sendingSideID", "01");
    }
}

#[test]
fn connect_to_resource_shapes_1_x_could_emit_are_refused() {
    // 1.x modelled the CHOICE as two independent OPTIONAL members, so it could
    // emit both alternatives, or neither. Neither is a ConnectToResourceArg.
    let both = vector("30 06 80 02 83 10 83 00");
    refused::<ConnectToResourceArg>(&both);
    refused::<ConnectToResourceArg>(&vector("30 00"));
    if let Some(d) = dissect_unchecked(
        op_codes::CONNECT_TO_RESOURCE,
        Some(&both),
        Carrier::Continue,
    ) {
        assert!(!d.problems().is_empty(), "{}", d.summary());
    }

    // With exactly one of the two set, 1.x produced the right octets.
    let old = vector("30 07 80 05 03 15 55 01 77");
    let arg: ConnectToResourceArg = inap::decode(&old).unwrap();
    assert_eq!(
        arg.resource_address,
        ResourceAddress::IpRoutingAddress(octets("03 15 55 01 77"))
    );
}

// ── PlayAnnouncement ────────────────────────────────────────────────────────

#[test]
fn play_announcement_elementary_message_with_every_member() {
    let arg = PlayAnnouncementArg {
        disconnect_from_ip_forbidden: Some(false),
        request_announcement_complete: Some(true),
        extensions: Some(extensions()),
        ..PlayAnnouncementArg::new(InformationToSend::InbandInfo(InbandInfo {
            number_of_repetitions: Some(2),
            duration: Some(10),
            interval: Some(1),
            ..InbandInfo::new(MessageId::ElementaryMessageId(7))
        }))
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 27                                  -- 18 + 3 + 3 + 15 = 39
           a0 10                               -- informationToSend [0]: CHOICE, EXPLICIT
              a0 0e                            --   inbandInfo [0] SEQUENCE, 5 + 3 + 3 + 3
                 a0 03                         --     messageID [0]: CHOICE, EXPLICIT
                    80 01 07                   --       elementaryMessageID [0] 7
                 81 01 02                      --     numberOfRepetitions 2
                 82 01 0a                      --     duration 10 s
                 83 01 01                      --     interval 1 s
           81 01 00                            -- disconnectFromIPForbidden FALSE
           82 01 ff                            -- requestAnnouncementComplete TRUE
           a3 0d                               -- extensions [3]
              {EXTENSION}
        "
        ),
    );
    let Some(d) = dissect(op_codes::PLAY_ANNOUNCEMENT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("inap.informationToSend", "0")
        .present("inap.inbandInfo_element")
        .show("inap.messageID", "0")
        .show("inap.elementaryMessageID", "7")
        .show("inap.numberOfRepetitions", "2")
        .show("inap.inbandInfo.duration", "10")
        .show("inap.inbandInfo.interval", "1")
        .show("inap.disconnectFromIPForbidden", "False")
        .show("inap.requestAnnouncementComplete", "True")
        .show("inap.extensions", "1");
}

#[test]
fn play_announcement_tone() {
    let arg = PlayAnnouncementArg::new(InformationToSend::Tone(Tone {
        tone_id: 1,
        duration: Some(5),
    }));
    let ber = known_answer(
        &arg,
        "
        30 0a
           a0 08                               -- informationToSend [0] EXPLICIT
              a1 06                            --   tone [1] SEQUENCE
                 80 01 01                      --     toneID 1
                 81 01 05                      --     duration 5 s
        ",
    );
    let Some(d) = dissect(op_codes::PLAY_ANNOUNCEMENT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("inap.informationToSend", "1")
        .present("inap.tone_element")
        .show("inap.toneID", "1")
        .show("inap.tone.duration", "5")
        // Both BOOLEANs are absent, so their DEFAULT TRUE applies.
        .absent("inap.disconnectFromIPForbidden")
        .absent("inap.requestAnnouncementComplete");
}

#[test]
fn play_announcement_display_information() {
    let arg = PlayAnnouncementArg::new(InformationToSend::DisplayInformation(ia5("HELLO")));
    let ber = known_answer(
        &arg,
        "
        30 09
           a0 07                               -- informationToSend [0] EXPLICIT
              82 05 48 45 4c 4c 4f             --   displayInformation [2] IA5String \"HELLO\"
        ",
    );
    let Some(d) = dissect(op_codes::PLAY_ANNOUNCEMENT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("inap.informationToSend", "2")
        .show("inap.displayInformation", "HELLO");
}

#[test]
fn play_announcement_text_message() {
    let arg = PlayAnnouncementArg::new(InformationToSend::InbandInfo(InbandInfo::new(
        MessageId::Text(MessageIdText {
            message_content: ia5("HI"),
            attributes: Some(octets("01 02")),
        }),
    )));
    let ber = known_answer(
        &arg,
        "
        30 10
           a0 0e                               -- informationToSend [0] EXPLICIT
              a0 0c                            --   inbandInfo [0]
                 a0 0a                         --     messageID [0] EXPLICIT
                    a1 08                      --       text [1] SEQUENCE
                       80 02 48 49             --         messageContent [0] \"HI\"
                       81 02 01 02             --         attributes [1]
        ",
    );
    let Some(d) = dissect(op_codes::PLAY_ANNOUNCEMENT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("inap.messageID", "1")
        .present("inap.text_element")
        .show("inap.messageContent", "HI")
        .hex("inap.attributes", "0102");
}

#[test]
fn play_announcement_several_elementary_messages() {
    let arg = PlayAnnouncementArg::new(InformationToSend::InbandInfo(InbandInfo::new(
        MessageId::ElementaryMessageIds(vec![7, 300]),
    )));
    let ber = known_answer(
        &arg,
        "
        30 0f
           a0 0d                               -- informationToSend [0] EXPLICIT
              a0 0b                            --   inbandInfo [0]
                 a0 09                         --     messageID [0] EXPLICIT
                    bd 07                      --       elementaryMessageIDs [29] SEQUENCE OF
                                               --         (10 1 11101)
                       02 01 07                --         Integer4 7, a plain INTEGER
                       02 02 01 2c             --         Integer4 300
        ",
    );
    let Some(d) = dissect(op_codes::PLAY_ANNOUNCEMENT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("inap.messageID", "29")
        .show("inap.elementaryMessageIDs", "2")
        .show_all("inap.Integer4", &["7", "300"]);
}

#[test]
fn play_announcement_variable_message() {
    let arg = PlayAnnouncementArg::new(InformationToSend::InbandInfo(InbandInfo::new(
        MessageId::VariableMessage(VariableMessage {
            elementary_message_id: 9,
            variable_parts: vec![
                VariablePart::Integer(5),
                VariablePart::Number(octets("00 04 13 21 43")),
                VariablePart::Time(octets("21 51")),
                VariablePart::Date(octets("39 90 03")),
                VariablePart::Price(octets("00 20 94 05")),
            ],
        }),
    )));
    let ber = known_answer(
        &arg,
        "
        30 26
           a0 24                               -- informationToSend [0] EXPLICIT
              a0 22                            --   inbandInfo [0]
                 a0 20                         --     messageID [0] EXPLICIT
                    be 1e                      --       variableMessage [30] SEQUENCE, 3 + 27
                       80 01 09                --         elementaryMessageID 9
                       a1 19                   --         variableParts [1] SEQUENCE OF, 25:
                                               --         each part is a CHOICE alternative
                                               --         with its own tag
                          80 01 05             --           integer [0] 5
                          81 05 00 04 13 21 43 --           number [1]
                          82 02 21 51          --           time [2] 12:15
                          83 03 39 90 03       --           date [3] 1993-09-30
                          84 04 00 20 94 05    --           price [4] 249.50
        ",
    );
    let Some(d) = dissect(op_codes::PLAY_ANNOUNCEMENT, Some(&ber), Carrier::Continue) else {
        return;
    };
    d.show("inap.messageID", "30")
        .present("inap.variableMessage_element")
        .show("inap.elementaryMessageID", "9")
        .show("inap.variableParts", "5")
        .show_all("inap.VariablePart", &["0", "1", "2", "3", "4"])
        .show("inap.integer", "5")
        .hex("inap.number", "0004132143")
        .hex("inap.time", "2151")
        .hex("inap.date", "399003")
        .hex("inap.price", "00209405");
}

#[test]
fn play_announcement_before_2_0_0_is_refused() {
    // 1.x modelled informationToSend as an OCTET STRING. The caller put the
    // encoding of the CHOICE alternative into it and it went out behind a
    // primitive tag:
    //   30 0d 80 05 a1 03 80 01 07 81 01 ff 82 01 ff
    // An explicit tag is constructed (X.690 8.14.2): a0, not 80.
    let old = vector("30 0d 80 05 a1 03 80 01 07 81 01 ff 82 01 ff");
    let error = refused::<PlayAnnouncementArg>(&old);
    assert!(
        error.contains("[0]") && error.contains("constructed"),
        "{error}"
    );

    // What 2.0.0 emits for the same announcement differs in that one bit.
    let arg = PlayAnnouncementArg {
        disconnect_from_ip_forbidden: Some(true),
        request_announcement_complete: Some(true),
        ..PlayAnnouncementArg::new(InformationToSend::Tone(Tone {
            tone_id: 7,
            duration: None,
        }))
    };
    known_answer(&arg, "30 0d a0 05 a1 03 80 01 07 81 01 ff 82 01 ff");

    // Wireshark reads the old bytes without complaint: this is the vector the
    // 1.x suite called "validated against Wireshark".
    let Some(d) = dissect_unchecked(op_codes::PLAY_ANNOUNCEMENT, Some(&old), Carrier::Continue)
    else {
        return;
    };
    assert!(d.problems().is_empty(), "{:?}", d.problems());
    d.show("inap.toneID", "7");
}

// ── PromptAndCollectUserInformation ─────────────────────────────────────────

#[test]
fn prompt_and_collect_with_every_member() {
    let arg = PromptAndCollectUserInformationArg {
        disconnect_from_ip_forbidden: Some(false),
        information_to_send: Some(InformationToSend::Tone(Tone {
            tone_id: 7,
            duration: None,
        })),
        extensions: Some(extensions()),
        ..PromptAndCollectUserInformationArg::new(CollectedInfo::CollectedDigits(CollectedDigits {
            minimum_nb_of_digits: Some(4),
            end_of_reply_digit: Some(octets("0c")),
            cancel_digit: Some(octets("0b")),
            start_digit: Some(octets("0a")),
            first_digit_time_out: Some(10),
            inter_digit_time_out: Some(5),
            error_treatment: Some(ErrorTreatment::RepeatPrompt),
            interruptable_ann_ind: Some(false),
            voice_information: Some(true),
            voice_back: Some(true),
            ..CollectedDigits::new(10)
        }))
    };
    let ber = known_answer(
        &arg,
        &format!(
            "
        30 3e                                  -- 37 + 3 + 7 + 15 = 62
           a0 23                               -- collectedInfo [0]: CHOICE, EXPLICIT
              a0 21                            --   collectedDigits [0] SEQUENCE, 11 * 3 = 33
                 80 01 04                      --     minimumNbOfDigits 4
                 81 01 0a                      --     maximumNbOfDigits 10
                 82 01 0c                      --     endOfReplyDigit
                 83 01 0b                      --     cancelDigit
                 84 01 0a                      --     startDigit
                 85 01 0a                      --     firstDigitTimeOut 10 s
                 86 01 05                      --     interDigitTimeOut 5 s
                 87 01 02                      --     errortreatment repeatPrompt(2)
                 88 01 00                      --     interruptableAnnInd FALSE
                 89 01 ff                      --     voiceInformation TRUE
                 8a 01 ff                      --     voiceBack TRUE
           81 01 00                            -- disconnectFromIPForbidden FALSE
           a2 05                               -- informationToSend [2]: CHOICE, EXPLICIT
              a1 03 80 01 07                   --   tone [1] {{ toneID 7 }}
           a3 0d                               -- extensions [3]
              {EXTENSION}
        "
        ),
    );
    let Some(d) = dissect(
        op_codes::PROMPT_AND_COLLECT_USER_INFORMATION,
        Some(&ber),
        Carrier::Continue,
    ) else {
        return;
    };
    d.show("inap.collectedInfo", "0")
        .present("inap.collectedDigits_element")
        .show("inap.minimumNbOfDigits", "4")
        .show("inap.maximumNbOfDigits", "10")
        .hex("inap.endOfReplyDigit", "0c")
        .hex("inap.cancelDigit", "0b")
        .hex("inap.startDigit", "0a")
        .show("inap.firstDigitTimeOut", "10")
        .show("inap.interDigitTimeOut", "5")
        .show("inap.errorTreatment", "2")
        .show("inap.interruptableAnnInd", "False")
        .show("inap.voiceInformation", "True")
        .show("inap.voiceBack", "True")
        .show("inap.disconnectFromIPForbidden", "False")
        .show("inap.informationToSend", "1")
        .show("inap.toneID", "7")
        .show("inap.extensions", "1");
}

#[test]
fn prompt_and_collect_minimal() {
    let ber = known_answer(
        &PromptAndCollectUserInformationArg::new(CollectedInfo::CollectedDigits(
            CollectedDigits::new(10),
        )),
        "
        30 07
           a0 05                               -- collectedInfo [0] EXPLICIT
              a0 03                            --   collectedDigits [0]
                 81 01 0a                      --     maximumNbOfDigits 10
        ",
    );
    let Some(d) = dissect(
        op_codes::PROMPT_AND_COLLECT_USER_INFORMATION,
        Some(&ber),
        Carrier::Continue,
    ) else {
        return;
    };
    d.show("inap.maximumNbOfDigits", "10")
        .absent("inap.minimumNbOfDigits")
        .absent("inap.informationToSend");
}

#[test]
fn prompt_and_collect_ia5_information() {
    // iA5Information [1] BOOLEAN is Q.1218 only.
    let ber = known_answer(
        &PromptAndCollectUserInformationArg::new(CollectedInfo::Ia5Information(true)),
        "
        30 05
           a0 03                               -- collectedInfo [0] EXPLICIT
              81 01 ff                         --   iA5Information [1] TRUE
        ",
    );
    let Some(d) = dissect(
        op_codes::PROMPT_AND_COLLECT_USER_INFORMATION,
        Some(&ber),
        Carrier::Continue,
    ) else {
        return;
    };
    d.show("inap.collectedInfo", "1")
        .show("inap.iA5Information", "True");
}

#[test]
fn prompt_and_collect_before_2_0_0_is_refused() {
    // As for PlayAnnouncement: 1.x sent collectedInfo behind a primitive [0].
    //   30 0a 80 05 a0 03 81 01 0a 81 01 00
    let old = vector("30 0a 80 05 a0 03 81 01 0a 81 01 00");
    let error = refused::<PromptAndCollectUserInformationArg>(&old);
    assert!(
        error.contains("[0]") && error.contains("constructed"),
        "{error}"
    );

    let arg = PromptAndCollectUserInformationArg {
        disconnect_from_ip_forbidden: Some(false),
        ..PromptAndCollectUserInformationArg::new(CollectedInfo::CollectedDigits(
            CollectedDigits::new(10),
        ))
    };
    known_answer(&arg, "30 0a a0 05 a0 03 81 01 0a 81 01 00");

    let Some(d) = dissect_unchecked(
        op_codes::PROMPT_AND_COLLECT_USER_INFORMATION,
        Some(&old),
        Carrier::Continue,
    ) else {
        return;
    };
    assert!(d.problems().is_empty(), "{:?}", d.problems());
}

#[test]
fn prompt_and_collect_result_digits() {
    // ReceivedInformationArg, the RESULT of the operation. Generic digits:
    // 00 = BCD even, 21 43 = digits 1234.
    let ber = known_answer(
        &PromptAndCollectUserInformationRes::DigitsResponse(octets("00 21 43")),
        "80 03 00 21 43                        -- digitsResponse [0]; the result is the CHOICE",
    );
    let Some(d) = dissect(
        op_codes::PROMPT_AND_COLLECT_USER_INFORMATION,
        Some(&ber),
        Carrier::Result,
    ) else {
        return;
    };
    d.show("inap.ReceivedInformationArg", "0")
        .hex("inap.digitsResponse", "002143");
}

#[test]
fn prompt_and_collect_result_ia5() {
    // iA5Response [1] IA5String is Q.1218 only.
    let ber = known_answer(
        &PromptAndCollectUserInformationRes::Ia5Response(ia5("1234")),
        "81 04 31 32 33 34                     -- iA5Response [1] \"1234\"",
    );
    let Some(d) = dissect(
        op_codes::PROMPT_AND_COLLECT_USER_INFORMATION,
        Some(&ber),
        Carrier::Result,
    ) else {
        return;
    };
    d.show("inap.ReceivedInformationArg", "1")
        .show("inap.iA5Response", "1234");
}
