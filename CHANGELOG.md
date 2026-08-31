# Changelog

## [Unreleased]

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
