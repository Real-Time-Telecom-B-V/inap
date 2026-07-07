# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [1.0.0]

First release, the INAP CS-1 operation codec (ITU-T Q.1218 / ETSI EN 300 374-1).

### Added
- Call establishment: `InitialDpArg`, `ConnectArg`, `ReleaseCallArg`,
  `ConnectToResourceArg`, `EstablishTemporaryConnectionArg`,
  `AssistRequestInstructionsArg`.
- Event handling: `RequestReportBcsmEventArg`, `EventReportBcsmArg`,
  `ResetTimerArg`, `CancelArg` (+ the shared `EventTypeBcsm` / `MonitorMode` /
  `BcsmEvent` types).
- Charging: `ApplyChargingArg`, `ApplyChargingReportArg`,
  `FurnishChargingInformationArg`.
- Call information: `CallInformationRequestArg`, `CallInformationReportArg` (+
  `RequestedInformationType` / `RequestedInformationValue` /
  `RequestedInformation`).
- Specialised resources: `PlayAnnouncementArg`,
  `PromptAndCollectUserInformationArg` / `PromptAndCollectUserInformationRes`.
- `op_codes` constants + `operation_name()`; `encode`/`decode` BER helpers;
  `InapError`; the `cs1-ssp-to-scp` application-context OID helper.
- Known-answer vectors validated against the Wireshark INAP dissector (INAP arg →
  TCAP → SCCP), plus BER round-trip tests over synthetic values.
- PyO3 bindings (`python` feature) and a Rust-backed Python wheel.

[1.0.0]: https://github.com/Real-Time-Telecom-B-V/inap/releases/tag/v1.0.0
