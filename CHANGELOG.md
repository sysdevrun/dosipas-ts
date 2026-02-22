# Changelog

## [Unreleased]

### Bug Fixes

- **CLI `decode-ticket.ts`**: Fixed crash caused by references to removed types (`SecurityInfo`, `RailTicketData`) and nonexistent properties (`ticket.security`, `ticket.railTickets`, etc.). The CLI now uses the actual `UicBarcodeTicket` type hierarchy (`level2SignedData.level1Data`, `dataSequence[].decoded`, etc.). Also added computed timestamp display (issuing time, end of validity, dynamic content time).

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
