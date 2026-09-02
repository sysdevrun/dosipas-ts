# Changelog

## Upcoming release

### Breaking Changes

- **Level 1 verification now takes key *material*, not bare key bytes.** The
  signing and key algorithms can be supplied alongside the public key, for
  issuers that omit `level1SigningAlg` / `level1KeyAlg` from the barcode and
  share the algorithm out of band. Those barcodes were previously unverifiable
  even with the correct public key.
  - `verifyLevel1Signature(bytes, publicKey)` → `verifyLevel1Signature(bytes, key)`
    where `key` is `{ publicKey, keyAlg?, signingAlg? }`.
  - `VerifyOptions.level1PublicKey` → `VerifyOptions.level1Key`, same shape.
  - `Level1KeyProvider.getPublicKey` now resolves to `Level1KeyMaterial`
    instead of `Uint8Array`.
  - `findKeyInXml` now returns `Level1KeyMaterial | null` instead of
    `Uint8Array | null`. It populates only `publicKey` — the registry's
    `signatureAlgorithm` is free-form vendor text that never records a curve,
    so it is deliberately not interpreted.
  - `ControlOptions` now extends `VerifyOptions`, so `controlTicket` also
    accepts `level1Key` and `level2Algorithms`.
- **`controlTicket` no longer reports a missing `level1SigningAlg` as an
  error.** A v2 header without the OID is now a note on the `securityInfo`
  check; whether the algorithm can actually be resolved is decided by the
  `level1Signature` check, which sees the caller's configuration and the key
  provider. Tickets whose Level 1 signature verifies with configured
  algorithms now pass control. The overall verdict is unchanged when no key
  material is supplied — `level1Signature` still fails at error severity.

### New Features

- **Level 2 algorithms are configurable too**, via `VerifyOptions.level2Algorithms`
  and a new optional second argument to `verifyLevel2Signature`. The Level 2
  public key stays embedded in the barcode, but its OIDs can be absent.
- **Algorithm precedence is strict**: OIDs in the barcode take priority, then
  configured algorithms, then a clear error. Nothing is inferred from the key
  material. If the barcode and the configuration disagree, verification fails
  with an explicit mismatch error rather than silently picking a winner.
  Fields accept dotted-decimal OIDs only — no names or aliases.
- **`SIGNING_ALGORITHMS` and `KEY_ALGORITHMS` are now exported**, along with
  `getSigningAlgorithm` / `getKeyAlgorithm`. Their keys are the accepted values
  for `keyAlg` / `signingAlg`, so the reference is importable rather than
  documentation-only.
- **`SignatureLevelResult` and `CheckResult` gained `algorithm` and
  `algorithmSource`** (`'barcode' | 'configured' | 'mixed'`), so callers can
  see which algorithm verified a signature and where it came from.
- **`cli/decode-ticket.ts` gained `--l1-key-alg` and `--l1-signing-alg`** for
  verifying barcodes that omit their OIDs.
- **New fixtures**: `CAR_JAUNE_TICKET_HEX` and `CAR_JAUNE_SIGNATURES` — a real
  Car Jaune (La Réunion) ticket with no algorithm OIDs and no Level 2 block,
  plus the Level 1 public key recovered from its signatures.

### Bug Fixes

- **`parseKeysXml` no longer throws on the live UIC key registry.** One entry
  (issuer 1182, key 2) has a base64 payload whose length is `1 mod 4`, which
  `atob` rejects — losing all 60 keys. Malformed entries are now skipped, and
  `findKeyInXml` throws a descriptive error for such an entry so a corrupt key
  is never mistaken for a missing one (`src/verifier.ts`).

### Migration

```diff
-const result = await verifyLevel1Signature(bytes, publicKey);
+const result = await verifyLevel1Signature(bytes, { publicKey });

-await verifySignatures(bytes, { level1PublicKey: publicKey });
+await verifySignatures(bytes, { level1Key: { publicKey } });

 const provider: Level1KeyProvider = {
   async getPublicKey(securityProvider, keyId) {
     const key = findKeyInXml(xml, securityProvider.num!, keyId);
     if (!key) throw new Error('Key not found');
-    return key;
+    return key; // now already { publicKey }
   },
 };
```

For a barcode that omits its algorithm OIDs, supply them with the key:

```diff
 await verifyLevel1Signature(bytes, {
   publicKey,
+  keyAlg: '1.2.840.10045.3.1.7',     // P-256
+  signingAlg: '1.2.840.10045.4.3.2', // ECDSA with SHA-256
 });
```

### Maintenance

- **Signature verification accepts both high-S and low-S ECDSA signatures**
  (regression tests added). UIC issuers do not normalize `s` into the low half
  of the curve order — that is a BTC/ETH convention — but `@noble/curves`
  rejects high-S signatures by default, so the verifier passes `lowS: false`
  (`src/verifier.ts`). This has been the behavior since the first release and
  is unchanged; it was simply untested. `tests/verifier.test.ts` now signs a
  ticket, forces every signature into a chosen half (`s` or `n - s`), and
  checks that Level 1 and Level 2 both still verify, so a dependency bump
  cannot silently reintroduce the rejection.

## [1.5.1]

### New Features

- **`controlTicket` — open ticket validity window**: New `openTicketValidity`
  check (check #15) validates that the current time falls within the
  `validFrom → validUntil` window of at least one openTicket transport document.
  Previously, tickets presented outside their valid travel period were not
  detected. Follows UIC IRS 90918-9 semantics: `validFromTime` absent defaults
  to 0 (00:00), `validUntilTime` absent defaults to 1439 (23:59).
- **New helper**: `getOpenTicketValidityWindow()` computes the absolute
  validity window (UTC) for an OpenTicketData given its issuing detail.

### Bug Fixes

- **Published `dist/` is now importable by plain Node** (no bundler required).
  The build previously used `moduleResolution: "bundler"`, which emitted
  extensionless relative imports (`./decoder`) and JSON imports without import
  attributes — both rejected by Node's ESM loader (`ERR_MODULE_NOT_FOUND`,
  `ERR_IMPORT_ATTRIBUTE_MISSING`). The compiler now uses
  `module`/`moduleResolution: "NodeNext"`, relative specifiers carry `.js`
  extensions, and the schema imports use `with { type: 'json' }`. CI now packs
  the artifact and imports it with plain Node so this cannot silently regress.
- **CLI `decode-ticket.ts`**: Fixed crash caused by references to removed types (`SecurityInfo`, `RailTicketData`) and nonexistent properties (`ticket.security`, `ticket.railTickets`, etc.). The CLI now uses the actual `UicBarcodeTicket` type hierarchy (`level2SignedData.level1Data`, `dataSequence[].decoded`, etc.). Also added computed timestamp display (issuing time, end of validity, dynamic content time).

### Maintenance

- **Updated dev dependencies**: `vitest` 3.x → 4.x, `@types/node` 25.2.x → 25.3.x.

## [1.5.0]

### Bug Fixes

- **`getEndOfValidityTime`**: No longer falls back to `issuingTime + validityDuration` when `endOfValidityYear`/`endOfValidityDay` fields are absent. `validityDuration` is a level 2 dynamic content duration, not a ticket end-of-validity. The function now returns `undefined` when explicit end-of-validity fields are missing.

### New Features

- **`controlTicket` — zone & carrier validation**: New `expectedZones` and
  `expectedCarriers` options verify that at least one `openTicket` transport
  document covers the specified zones and carriers. Useful for network pass
  and zonal pass control.
- **New TypeScript types**: `OpenTicketData`, `ZoneData`, `LineData`,
  `ViaStationData`, `ValidRegionChoice` — typed representations of the
  decoded OpenTicketData ASN.1 structure and its validRegion alternatives.

## [1.4.0]

### Breaking Changes

- **`encodeLevel2Data`** now returns `RawBytes` instead of `{ dataFormat: string; data: Uint8Array }` and requires a `format` parameter (e.g. `"U2"`). This aligns it with `encodeLevel1Data` for bit-precise signature reproducibility.
- **`encodeLevel2SignedData`** now accepts `RawBytes` for its `level2Data` option instead of `{ dataFormat: string; data: Uint8Array }`.

### Migration

```diff
-const l2 = encodeLevel2Data(level2Data);
-console.log(l2.dataFormat);  // no longer available
+const l2 = encodeLevel2Data(level2Data, 'U2');
 console.log(l2.data);        // still works — Uint8Array
```
