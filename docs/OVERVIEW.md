# inap, overview

An **Intelligent Network Application Part (INAP), Capability Set 1** operation
codec (ETSI ETS 300 374-1 with the additional members of ITU-T Q.1218). It provides the argument/result types
for the SSF ↔ SCF (and SRF) operations and their operation codes; the ASN.1 BER
encode/decode is done by [`rasn`](https://crates.io/crates/rasn).

## Where INAP sits

```
  SCF  ◀── INAP operations ──▶  SSF / SRF     (this crate: the operation layer)
                    │
                   TCAP           (transactions + dialogue; wraps INAP invokes)
                    │
                   SCCP           (GT/SSN addressing)
                    │
               MTP3 / M3UA        (transport)
```

INAP is a peer of MAP and CAP: all three are TCAP application parts. CAP (CAMEL)
was derived from INAP CS-2, so this crate is a near-sibling of the CAP
(`gsm_cap`) operation layer, same shape (rasn types + operation codes), and the
fixed-network operations INAP adds.

## Modules

| Path | Contents |
|---|---|
| `src/types.rs` | The data types: `ServiceKey`, the address aliases (Q.763 / Q.931 `OCTET STRING`s), `LegId`, `BcsmEvent`, `EventSpecificInformationBcsm`, `MiscCallInfo`, `Extensions`, `InformationToSend`, `CollectedInfo`, `RequestedInformation*` and the enumerations. |
| `src/operations.rs` | The operation arguments/results (`InitialDpArg`, `ConnectArg`, `ReleaseCallArg`, the assist / temporary-connection / call-information / charging / specialised-resource ops), each deriving `rasn` BER `Encode`/`Decode`. |
| `src/op_codes.rs` | The operation-code constants + `operation_name()`. |
| `src/application_context.rs` | The application contexts `cs1-ssp-to-scp`, `cs1-assist-handoff-ssp-to-scp` and `cs1-ip-to-scp`. |
| `src/strict.rs` | The guard behind `decode`: nothing on the wire may be dropped. |
| `src/lib.rs` | `encode` / `decode` helpers (BER) + re-exports; `InapError`. |

## Usage shape

1. Build an INAP argument (e.g. `InitialDpArg`).
2. `inap::encode(&arg)` → BER bytes.
3. Put the bytes in a TCAP Invoke component with the matching `op_codes::*` value;
   the TCAP layer handles the dialogue (application context, transaction IDs) and
   SCCP addressing.
4. On receipt, read the operation code, then `inap::decode::<TheArg>(bytes)`.

## Scope

This crate is the INAP **operation codec** only, deliberately transport- and
TCAP-independent, so it is a pure, portable, testable building block. Dialogue
negotiation, transaction state, and routing belong to the TCAP/SCCP layers above
the transport.
