# Versioning

`inap` follows [Semantic Versioning 2.0.0](https://semver.org/). The public API, 
the operation types in `operations`, the `types`, the `op_codes`, and the
`encode`/`decode` helpers, is the contract.

## The git tag is the source of truth

`Cargo.toml`'s `version` matches the release tag; the release workflow's
`verify-version` job refuses to publish if they disagree. Bump `version`, commit,
tag `vX.Y.Z`, push the tag.

## The rule

- **MAJOR**, remove/rename/re-signature a `pub` item, or change an operation's
  ASN.1 shape in a way that breaks the wire format.
- **MINOR**, backward-compatible additions (new operations, new optional
  fields, new op-code constants).
- **PATCH**, bug fixes, docs, behaviour-neutral dependency bumps. An ITU-T
  Q.1218 / EN 300 374-1 conformance correction is a PATCH even if it changes wire
  behaviour, documented loudly in the changelog.
