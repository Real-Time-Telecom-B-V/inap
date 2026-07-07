# inap, overview

An **Intelligent Network Application Part (INAP), Capability Set 1** operation
codec (ITU-T Q.1218 / ETSI EN 300 374-1). It provides the argument/result types
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
(`gsm_cap`) operation layer, same shape (rasn types + operation codes), a shared
family of leaf IEs, and the fixed-network operations INAP adds.

## Modules

| Path | Contents |
|---|---|
| `src/types.rs` | Common INAP types: `ServiceKey`, the address aliases (Q.763 / Q.931 `OCTET STRING`s), the `LegId` / `RequestedInformation*` types, and the shared `EventTypeBcsm` / `MonitorMode` / `BcsmEvent` (byte-identical to the CAP definitions). |
| `src/operations.rs` | The operation arguments/results (`InitialDpArg`, `ConnectArg`, `ReleaseCallArg`, the assist / temporary-connection / call-information / charging / specialised-resource ops), each deriving `rasn` BER `Encode`/`Decode`. |
| `src/op_codes.rs` | The operation-code constants + `operation_name()`. |
| `src/application_context.rs` | The `cs1-ssp-to-scp` application-context OID + the `core-INAP-CS1-Codes` abstract-syntax OID. |
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
