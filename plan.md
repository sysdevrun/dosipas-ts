# Plan: Extend `controlTicket` for Network Pass & Zonal Pass Validation

## Goal

Extend the existing `controlTicket()` method to verify that a scanned ticket is
valid for a specific set of **zones** and/or **carriers**. The controller supplies
the expected/allowed zones and carriers, and the check verifies that at least one
`openTicket` transport document in the ticket covers all of them.

---

## 1. New Types (in `src/types.ts`)

### 1a. `OpenTicketData` interface — typed view over `ticket.value`

Currently `TransportDocumentData.ticket.value` is `Record<string, unknown>`.
The PER decoder already produces all the OpenTicketData ASN.1 fields as properties
on this object — they are just untyped.  We do **not** need to change the decoder.
Instead we define a TypeScript interface that the control code casts the value to
when `ticket.key === 'openTicket'`.

```typescript
/** Typed representation of the decoded OpenTicketData SEQUENCE. */
export interface OpenTicketData {
  referenceNum?: number;
  referenceIA5?: string;
  productOwnerNum?: number;
  productOwnerIA5?: string;
  productIdNum?: number;
  productIdIA5?: string;
  extIssuerId?: number;
  issuerAuthorizationId?: number;
  returnIncluded: boolean;
  stationCodeTable?: string;
  fromStationNum?: number;
  fromStationIA5?: string;
  toStationNum?: number;
  toStationIA5?: string;
  fromStationNameUTF8?: string;
  toStationNameUTF8?: string;
  validRegionDesc?: string;
  validRegion?: ValidRegionChoice[];
  returnDescription?: Record<string, unknown>;
  validFromDay?: number;
  validFromTime?: number;
  validFromUTCOffset?: number;
  validUntilDay?: number;
  validUntilTime?: number;
  validUntilUTCOffset?: number;
  activatedDay?: number[];
  classCode?: string;
  serviceLevel?: string;
  carrierNum?: number[];
  carrierIA5?: string[];
  includedServiceBrands?: number[];
  excludedServiceBrands?: number[];
  tariffs?: Record<string, unknown>[];
  price?: number;
  infoText?: string;
}
```

### 1b. `ValidRegionChoice` and sub-types

```typescript
/** CHOICE from the validRegion SEQUENCE OF. Each element is one of: */
export interface ValidRegionChoice {
  key: string;                     // "zones" | "lines" | "viaStations" | "trainLink" | "polygone"
  value: ZoneData | LineData | ViaStationData | TrainLinkData | PolygoneData;
}

/** "zones" alternative within validRegion. */
export interface ZoneData {
  carrierNum?: number;
  carrierIA5?: string;
  stationCodeTable?: string;
  entryStationNum?: number;
  entryStationIA5?: string;
  terminatingStationNum?: number;
  terminatingStationIA5?: string;
  city?: number;
  zoneId?: number[];
  binaryZoneId?: Uint8Array;
  nutsCode?: string;
}

/** "lines" alternative within validRegion. */
export interface LineData {
  carrierNum?: number;
  carrierIA5?: string;
  lineId?: number[];
  stationCodeTable?: string;
  entryStationNum?: number;
  entryStationIA5?: string;
  terminatingStationNum?: number;
  terminatingStationIA5?: string;
  city?: number;
}

/** "viaStations" alternative within validRegion. */
export interface ViaStationData {
  stationCodeTable?: string;
  stationNum?: number;
  stationIA5?: string;
  border?: boolean;
  carrierNum?: number[];
  carrierIA5?: string[];
  seriesId?: number;
  routeId?: number;
  includedServiceBrands?: number[];
  excludedServiceBrands?: number[];
  alternativeRoutes?: ViaStationData[];
  route?: ViaStationData[];
}

/** "trainLink" alternative within validRegion. */
export interface TrainLinkData {
  trainNum?: number;
  trainIA5?: string;
  travelDate: number;
  departureTime: number;
  departureUTCOffset?: number;
  fromStationNum?: number;
  fromStationIA5?: string;
  toStationNum?: number;
  toStationIA5?: string;
  fromStationNameUTF8?: string;
  toStationNameUTF8?: string;
}

/** Geo-coordinate edge used in PolygoneData. */
export interface GeoEdge {
  longitude: number;
  latitude: number;
}

/** First edge of a polygone with full coordinate metadata. */
export interface GeoFirstEdge {
  geoUnit?: string;
  coordinateSystem?: string;
  hemisphereLongitude?: string;
  hemisphereLatitude?: string;
  longitude: number;
  latitude: number;
  accuracy?: string;
}

/** "polygone" alternative within validRegion (FCB v3 only). */
export interface PolygoneData {
  firstEdge: GeoFirstEdge;
  edges: GeoEdge[];
}
```

### 1c. Extend `ControlOptions`

Add two new optional fields:

```typescript
export interface ControlOptions {
  // ... existing fields ...

  /**
   * Expected/allowed carrier identifiers (RICS codes as numbers and/or IA5 strings).
   * When provided, at least one openTicket must authorize all of these carriers.
   */
  expectedCarriers?: Array<number | string>;

  /**
   * Expected/allowed zone identifiers (integer zone IDs).
   * When provided, at least one openTicket must contain a `zones` validRegion
   * entry whose `zoneId` array includes all of the expected zones.
   */
  expectedZones?: Array<number | string>;
}
```

The caller passes the carriers and zones for their network.  Types are
`number | string` to accommodate both `carrierNum` / `carrierIA5` and
`zoneId` (integer) / `nutsCode` (string) representations.

---

## 2. New Check Function (in `src/control.ts`)

### 2a. Helper: extract open tickets

```typescript
/** Get all openTicket transport documents from the first rail ticket. */
function getOpenTickets(ticket: UicBarcodeTicket): OpenTicketData[] {
  const docs = firstRailTicket(ticket)?.transportDocument;
  if (!docs) return [];
  return docs
    .filter(d => d.ticket.key === 'openTicket')
    .map(d => d.ticket.value as OpenTicketData);
}
```

### 2b. `checkZonesAndCarriers` — the new check function

This is the core validation logic.  It examines every `openTicket` in the
ticket and tries to find at least **one** that satisfies all of the expected
constraints.

**Carrier matching** — an open ticket authorizes a carrier if:
1. `openTicketData.carrierNum` contains the expected carrier number, OR
2. `openTicketData.carrierIA5` contains the expected carrier string, OR
3. A `validRegion` entry of type `zones`, `lines`, or `viaStations`
   lists the carrier in its `carrierNum` / `carrierIA5`.
4. The `productOwnerNum` / `productOwnerIA5` matches (product owner is
   implicitly a valid carrier).

**Zone matching** — an open ticket authorizes zones if at least one
`validRegion` entry with `key === 'zones'` has a `zoneId` array that
includes all the expected zone IDs.  For string-based zone matching, check
`nutsCode`.

**Combined logic** — both carrier and zone constraints must be satisfied by
the **same** open ticket (they are not checked independently across
different tickets). This is because a network pass is a single product that
authorizes specific carriers + zones together.

```typescript
function checkZonesAndCarriers(
  ticket: UicBarcodeTicket,
  options: ControlOptions,
): CheckResult {
  const expectedCarriers = options.expectedCarriers;
  const expectedZones = options.expectedZones;

  // If no zone/carrier constraints requested, pass trivially
  if (!expectedCarriers?.length && !expectedZones?.length) {
    return {
      name: 'Zones & Carriers',
      passed: true,
      severity: 'info',
      message: 'No zone/carrier constraints specified',
    };
  }

  const openTickets = getOpenTickets(ticket);
  if (openTickets.length === 0) {
    return {
      name: 'Zones & Carriers',
      passed: false,
      severity: 'error',
      message: 'No openTicket transport documents found',
    };
  }

  // Try each openTicket — at least one must satisfy ALL constraints
  for (const ot of openTickets) {
    const carrierOk = !expectedCarriers?.length || carriersMatch(ot, expectedCarriers);
    const zonesOk   = !expectedZones?.length    || zonesMatch(ot, expectedZones);
    if (carrierOk && zonesOk) {
      return {
        name: 'Zones & Carriers',
        passed: true,
        severity: 'error',
      };
    }
  }

  // Build a helpful message about what failed
  const issues: string[] = [];
  if (expectedCarriers?.length) issues.push(`carriers: ${expectedCarriers.join(', ')}`);
  if (expectedZones?.length)    issues.push(`zones: ${expectedZones.join(', ')}`);

  return {
    name: 'Zones & Carriers',
    passed: false,
    severity: 'error',
    message: `No openTicket covers the expected ${issues.join(' and ')}`,
  };
}
```

### 2c. Pure helper functions for matching

```typescript
/** Check whether an open ticket authorizes ALL expected carriers. */
function carriersMatch(
  ot: OpenTicketData,
  expected: Array<number | string>,
): boolean {
  return expected.every(carrier => {
    // Check top-level OpenTicketData carrier lists
    if (typeof carrier === 'number') {
      if (ot.carrierNum?.includes(carrier)) return true;
      if (ot.productOwnerNum === carrier) return true;
    } else {
      if (ot.carrierIA5?.includes(carrier)) return true;
      if (ot.productOwnerIA5 === carrier) return true;
    }

    // Check validRegion entries for carrier
    if (ot.validRegion) {
      for (const region of ot.validRegion) {
        const v = region.value as any;
        if (typeof carrier === 'number') {
          // zones and lines have single carrierNum; viaStations has carrierNum[]
          if (v.carrierNum === carrier) return true;
          if (Array.isArray(v.carrierNum) && v.carrierNum.includes(carrier)) return true;
        } else {
          if (v.carrierIA5 === carrier) return true;
          if (Array.isArray(v.carrierIA5) && v.carrierIA5.includes(carrier)) return true;
        }
      }
    }
    return false;
  });
}

/** Check whether an open ticket authorizes ALL expected zones. */
function zonesMatch(
  ot: OpenTicketData,
  expected: Array<number | string>,
): boolean {
  if (!ot.validRegion) return false;

  // Collect all zone IDs and NUTS codes from all "zones" entries in validRegion
  const allZoneIds = new Set<number>();
  const allNutsCodes = new Set<string>();

  for (const region of ot.validRegion) {
    if (region.key !== 'zones') continue;
    const z = region.value as ZoneData;
    if (z.zoneId) z.zoneId.forEach(id => allZoneIds.add(id));
    if (z.nutsCode) allNutsCodes.add(z.nutsCode);
  }

  return expected.every(zone => {
    if (typeof zone === 'number') return allZoneIds.has(zone);
    return allNutsCodes.has(zone);
  });
}
```

---

## 3. Integration into `controlTicket()` (in `src/control.ts`)

Add the new check as **check #14** in the `controlTicket()` function, after
the existing transport document check (step 10):

```typescript
// 14. Zones & Carriers
checks.zonesAndCarriers = checkZonesAndCarriers(ticket, opts);
```

The check has severity `'error'` when constraints are provided (failing it
blocks `valid: true`), and `'info'` when no constraints are specified
(doesn't affect overall validity).

No changes to existing checks required — the new check is purely additive.

---

## 4. Export New Types (in `src/index.ts`)

Add the new interfaces to the type-only export block:

```typescript
export type {
  // ... existing ...
  OpenTicketData,
  ZoneData,
  LineData,
  ViaStationData,
  TrainLinkData,
  PolygoneData,
  GeoFirstEdge,
  GeoEdge,
  ValidRegionChoice,
} from './types';
```

---

## 5. Tests (in `tests/control.test.ts`)

### 5a. Test with synthetic tickets (using `makeTicket` + `signAndEncodeTicket`)

Update the `makeTicket` helper to accept optional `openTicketValue` so we
can construct tickets with specific zone/carrier data:

```typescript
function makeTicket(opts: {
  // ... existing fields ...
  openTicketValue?: Record<string, unknown>;
}): UicBarcodeTicket {
  // ... use opts.openTicketValue ?? { returnIncluded: false } ...
}
```

**Test cases to add:**

1. **No constraints specified → info/pass**
   ```
   controlTicket(hex)  // no expectedZones or expectedCarriers
   → checks.zonesAndCarriers.passed === true, severity === 'info'
   ```

2. **Expected carriers match top-level carrierNum → pass**
   ```
   openTicketValue: { returnIncluded: false, carrierNum: [1080] }
   expectedCarriers: [1080]
   → checks.zonesAndCarriers.passed === true
   ```

3. **Expected carriers don't match → fail**
   ```
   openTicketValue: { returnIncluded: false, carrierNum: [1080] }
   expectedCarriers: [9999]
   → checks.zonesAndCarriers.passed === false
   ```

4. **Expected carriers match via productOwnerNum → pass**
   ```
   openTicketValue: { returnIncluded: false, productOwnerNum: 1080 }
   expectedCarriers: [1080]
   → pass
   ```

5. **Expected carriers match via IA5 → pass**
   ```
   openTicketValue: { returnIncluded: false, carrierIA5: ['SNCF'] }
   expectedCarriers: ['SNCF']
   → pass
   ```

6. **Expected zones match zoneId → pass**
   ```
   openTicketValue: {
     returnIncluded: false,
     validRegion: [
       { key: 'zones', value: { zoneId: [1, 2, 3] } }
     ]
   }
   expectedZones: [1, 2]
   → pass
   ```

7. **Expected zones partially missing → fail**
   ```
   openTicketValue: {
     returnIncluded: false,
     validRegion: [
       { key: 'zones', value: { zoneId: [1, 2] } }
     ]
   }
   expectedZones: [1, 2, 5]
   → fail (zone 5 not covered)
   ```

8. **Multiple zone entries aggregated → pass**
   ```
   openTicketValue: {
     returnIncluded: false,
     validRegion: [
       { key: 'zones', value: { zoneId: [1, 2] } },
       { key: 'zones', value: { zoneId: [3, 4] } }
     ]
   }
   expectedZones: [1, 3]
   → pass (zone 1 from first entry, zone 3 from second)
   ```

9. **Both zones AND carriers required, both satisfied → pass**
   ```
   openTicketValue: {
     returnIncluded: false,
     carrierNum: [1080],
     validRegion: [
       { key: 'zones', value: { zoneId: [1, 2, 3] } }
     ]
   }
   expectedCarriers: [1080]
   expectedZones: [1, 2]
   → pass
   ```

10. **Both required, carrier matches but zone doesn't → fail**
    ```
    expectedCarriers: [1080], expectedZones: [99]
    → fail
    ```

11. **Carrier found in validRegion zones entry → pass**
    ```
    openTicketValue: {
      returnIncluded: false,
      validRegion: [
        { key: 'zones', value: { carrierNum: 1080, zoneId: [1, 2] } }
      ]
    }
    expectedCarriers: [1080]
    → pass
    ```

12. **No openTicket document at all → fail**
    ```
    ticket with ticket.key = 'trainTicket' only
    expectedZones: [1]
    → fail ('No openTicket transport documents found')
    ```

13. **String-based zone matching via nutsCode → pass**
    ```
    openTicketValue: {
      returnIncluded: false,
      validRegion: [
        { key: 'zones', value: { nutsCode: 'FR101' } }
      ]
    }
    expectedZones: ['FR101']
    → pass
    ```

### 5b. Test with real fixture tickets

Decode `SAMPLE_TICKET_HEX` and inspect what zones/carriers are present in
the actual decoded data.  Add tests that verify `checkZonesAndCarriers`
against those real values.  If the sample ticket has no zones, verify that
requesting zones correctly fails.

---

## 6. Update overall test count assertion

The existing test `'all 13 checks are present'` must be updated to expect
**14** checks and include `'zonesAndCarriers'` in the expected keys list.

---

## 7. CHANGELOG.md

Add a new entry:

```markdown
## [1.5.0]

### New Features

- **`controlTicket` — zone & carrier validation**: New `expectedZones` and
  `expectedCarriers` options verify that at least one `openTicket` transport
  document covers the specified zones and carriers. Useful for network pass
  and zonal pass control.
- **New TypeScript types**: `OpenTicketData`, `ZoneData`, `LineData`,
  `ViaStationData`, `TrainLinkData`, `PolygoneData`, `GeoFirstEdge`,
  `GeoEdge`, `ValidRegionChoice` — typed representations of the decoded
  OpenTicketData ASN.1 structure and all its validRegion alternatives.
```

---

## 8. Files Changed (summary)

| File | Action |
|------|--------|
| `src/types.ts` | Add `OpenTicketData`, `ZoneData`, `LineData`, `ViaStationData`, `TrainLinkData`, `PolygoneData`, `GeoFirstEdge`, `GeoEdge`, `ValidRegionChoice` interfaces; extend `ControlOptions` |
| `src/control.ts` | Add `getOpenTickets()`, `carriersMatch()`, `zonesMatch()`, `checkZonesAndCarriers()` functions; wire into `controlTicket()` as check #14 |
| `src/index.ts` | Add new types to the export block |
| `tests/control.test.ts` | Add ~13 new test cases for zone/carrier validation; update `makeTicket` helper; update "all checks" test |
| `CHANGELOG.md` | Add [1.5.0] section |

---

## 9. Where to Find More Data If Needed

| What | Where |
|------|-------|
| Full OpenTicketData ASN.1 field list (FCB v3) | `schemas/uic-barcode/uicRailTicketData_v3.schema.json` line 21520 |
| Full OpenTicketData ASN.1 field list (FCB v2) | `schemas/uic-barcode/uicRailTicketData_v2.schema.json` line 20946 |
| Full OpenTicketData ASN.1 field list (FCB v1) | `schemas/uic-barcode/uicRailTicketData_v1.schema.json` line 20862 |
| ZoneType SEQUENCE (zones alternative) | v3 schema line 21884 (and in return region ~22477) |
| LineType SEQUENCE (lines alternative) | v3 schema line 21986 |
| ViaStationType SEQUENCE (viaStations) | v3 schema line 21757 |
| How validRegion CHOICE is decoded by PER | The `asn1-per-ts` codec returns `{ key: string; value: object }` for CHOICE types — same pattern as `ticket: { key, value }` |
| Real ticket data samples | `src/fixtures.ts` — decode them to inspect actual OpenTicketData content |
| UIC specification for OpenTicketData semantics | UIC IRS 90918-9 (ERA TAP TSI Annex B.6) — defines the business rules for each field |
| Official zone ID allocation | Managed by each network operator; no central registry in the codebase |
| Carrier RICS code registry | UIC public key XML also contains carrier RICS codes; see `parseKeysXml()` in verifier.ts |
| FCB version differences affecting OpenTicketData | v1: `productIdNum` max=32000; v3: max=65535. v3 adds `polygone` to validRegion. Zone/carrier fields are identical across all 3 versions |

---

## 10. Implementation Order

1. Add types to `src/types.ts`
2. Add check functions to `src/control.ts` and wire into `controlTicket()`
3. Update exports in `src/index.ts`
4. Add tests to `tests/control.test.ts`
5. Run `npx tsc --noEmit` to type-check
6. Run `npm test` to verify all tests pass
7. Update `CHANGELOG.md`
