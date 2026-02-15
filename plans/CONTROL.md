# Plan: Ticket Validity Control Helpers

## Overview

Add a new `controlTicket()` function and supporting helpers that perform comprehensive validation of a dosipas ticket. The function takes a hex string, decodes it once, then runs a series of focused check functions — each responsible for verifying one specific aspect of the ticket. Results are collected into a structured report.

The design supports all ticket variants the library handles: FDC1 dynamic content, Intercode 6 extensions (`+FRII1`, `_<RICS>II1`), Intercode dynamic data (`_<RICS>.ID1`), tickets without level 2 signatures (v1 headers where `level2SigningAlg` is not set), and multiple FCB versions (1, 2, 3).

---

## New file: `src/control.ts`

### Main entry point

```ts
controlTicket(hex: string, options?: ControlOptions): Promise<ControlResult>
```

1. Decode the ticket from the hex string via `decodeTicket(hex)` — if decoding fails, return early with a fatal `decode` check failure.
2. Convert the hex to bytes (for signature verification which needs raw bytes).
3. Run each check function sequentially, passing the decoded `UicBarcodeTicket` (and bytes + options where needed).
4. Collect all individual `CheckResult` entries into the final `ControlResult`.

### Options

```ts
interface ControlOptions {
  /** Reference date/time for temporal checks. Defaults to `new Date()`. */
  now?: Date;

  /** Level 1 key provider callback — used to retrieve the public key for level 1 signature verification. */
  level1KeyProvider?: Level1KeyProvider;

  /**
   * Set of expected Intercode network IDs (hex strings, e.g. "250502").
   * When provided, `intercodeIssuing` must be present and its `networkId`
   * must match one of the expected values.
   */
  expectedIntercodeNetworkIds?: Set<string>;
}
```

### Result types

```ts
/** Overall control result aggregating all individual checks. */
interface ControlResult {
  /** True only if every check with `severity: 'error'` passed. */
  valid: boolean;

  /** The decoded ticket (undefined if decoding itself failed). */
  ticket?: UicBarcodeTicket;

  /** Individual check results, keyed by check name. */
  checks: Record<string, CheckResult>;
}

/** Result of a single check. */
interface CheckResult {
  /** Human-readable check name. */
  name: string;

  /** Whether this check passed. */
  passed: boolean;

  /**
   * 'error' — a failed check makes the ticket invalid.
   * 'warning' — a failed check is informational but does not make the ticket invalid.
   * 'info' — purely informational, never causes invalidity.
   */
  severity: 'error' | 'warning' | 'info';

  /** Details / reason when the check fails (or informational message). */
  message?: string;
}
```

---

## Individual check functions

Each function receives the decoded ticket (and extra context as needed) and returns one or more `CheckResult` entries. They are pure helpers called by `controlTicket` — not exported individually.

### 1. `checkDecode`

**Key**: `decode`
**Severity**: `error`
**What it checks**: Whether the hex string can be decoded at all. This is handled by the try/catch around `decodeTicket()` in the main function — if it throws, a failed `decode` check is added and all other checks are skipped.

**Passes when**: `decodeTicket(hex)` succeeds without throwing.

---

### 2. `checkHeader`

**Key**: `header`
**Severity**: `error`
**What it checks**: The header format and version are recognized.

- `ticket.format` matches `U1` or `U2`.
- `ticket.headerVersion` is 1 or 2.

**Passes when**: Both conditions are met.

---

### 3. `checkSecurityInfo`

**Key**: `securityInfo`
**Severity**: `error`
**What it checks**: The required security metadata is present, validating level 1 and level 2 independently.

**Level 1 (mandatory):**
- `security.securityProviderNum` or `security.securityProviderIA5` is set.
- `security.keyId` is set.
- `security.level1SigningAlg` is present.
- `security.level1KeyAlg` is present.
- `security.level1Signature` is present.

**Level 2 (conditional):**
- If `security.level2SigningAlg` is set, then `security.level2KeyAlg`, `security.level2PublicKey`, and `ticket.level2Signature` must also be present.
- If `security.level2SigningAlg` is not set, level 2 fields are not required.

**Passes when**: All level 1 conditions are met, and level 2 conditions are met if applicable.

---

### 4. `checkLevel1Signature`

**Key**: `level1Signature`
**Severity**: `error`
**What it checks**: Level 1 signature validity. The level 1 signature is **mandatory** — a ticket cannot be considered valid unless its level 1 signature is verified.

- If no `level1KeyProvider` is provided in options, the check **fails** with an error message ("No level 1 key provider — cannot verify mandatory level 1 signature").
- If a key provider is provided, retrieves the public key and calls `verifyLevel1Signature(bytes, publicKey)`.
- For DSA-signed tickets (e.g. SNCF TER), the check will fail since DSA verification is not supported by the library.

**Implementation**: Reuses `verifyLevel1Signature()` from `verifier.ts`.

**Passes when**: The level 1 signature is cryptographically verified.

---

### 5. `checkLevel2Signature`

**Key**: `level2Signature`
**Severity**: `error` when required, `info` when not applicable
**What it checks**: Level 2 signature validity using the existing `verifyLevel2Signature()`.

- If `security.level2SigningAlg` is **set**: level 2 signature, public key, and algorithm OIDs must be present and the signature must verify. Failure is an error.
- If `security.level2SigningAlg` is **not set**: level 2 is not required. The check passes with an info message ("Level 2 signature not required — level2SigningAlg not set").

**Implementation**: Calls `verifyLevel2Signature(bytes)` from the existing `verifier.ts`.

---

### 6. `checkNotExpired`

**Key**: `notExpired`
**Severity**: `error`
**What it checks**: The ticket has not exceeded its validity period.

- For **v2 headers**: uses `security.endOfValidityYear`, `security.endOfValidityDay`, and `security.endOfValidityTime` to compute the expiry instant. The `endOfValidityTime` is in minutes from midnight. If `security.validityDuration` is also set, adds it (in minutes) to the end-of-validity time to get the final expiry.
- For **v1 headers**: uses the issuing date (`issuingYear`, `issuingDay`) + `security.validityDuration` from security info (if available). If no duration is available, the check is skipped with an info message.
- Compares to `options.now ?? new Date()`.

**Passes when**: The current time is before the computed expiry.

---

### 7. `checkNotSpecimen`

**Key**: `notSpecimen`
**Severity**: `error`
**What it checks**: The ticket is not a specimen/test ticket.

- Reads `issuingDetail.specimen` from the first rail ticket.

**Passes when**: `specimen` is `false` (or absent).

---

### 8. `checkActivated`

**Key**: `activated`
**Severity**: `error`
**What it checks**: The ticket has been activated (is usable).

- Reads `issuingDetail.activated` from the first rail ticket.

**Passes when**: `activated` is `true`.

---

### 9. `checkIssuingDetail`

**Key**: `issuingDetail`
**Severity**: `error`
**What it checks**: Essential issuing fields are present.

- At least one rail ticket exists.
- First rail ticket has an `issuingDetail`.
- `issuingYear` and `issuingDay` are present and in plausible ranges (year >= 2016, day 1-366).
- `issuerNum` or `issuerIA5` is present.

**Passes when**: All conditions are met.

---

### 10. `checkTransportDocument`

**Key**: `transportDocument`
**Severity**: `error`
**What it checks**: At least one transport document is present in the rail ticket.

- `railTickets[0].transportDocument` exists and has length >= 1.
- Each entry has a non-empty `ticketType`.

**Passes when**: At least one transport document with a valid type is found.

---

### 11. `checkIntercodeExtension`

**Key**: `intercodeExtension`
**Severity**: `error` when `expectedIntercodeNetworkIds` is provided, `warning` otherwise
**What it checks**: Intercode 6 issuing extension decoding and optional network ID validation.

**Decoding check:**
- If `issuingDetail.intercodeIssuing` is present, the extension decoded correctly.
- If `issuingDetail.extension` is present and its `extensionId` matches `_<RICS>II1` or `+<CC>II1`, the check fails — the extension should have been decoded as Intercode but fell through to raw.
- If neither is present and `expectedIntercodeNetworkIds` is provided, the check fails — Intercode issuing data is required but absent.
- If neither is present and no expected IDs are provided, the check passes with an info message ("No issuing extension present").

**Network ID validation (when `expectedIntercodeNetworkIds` is provided):**
- `intercodeIssuing` must be present (checked above).
- `intercodeIssuing.networkId` is converted to hex string (e.g. `Uint8Array [0x25, 0x05, 0x02]` -> `"250502"`) and checked against the expected set.
- If the network ID is not in the expected set, the check fails with the actual vs expected values in the message.

**Passes when**: Intercode extension is absent (and not expected) or successfully decoded with a matching network ID.

---

### 12. `checkDynamicData`

**Key**: `dynamicData`
**Severity**: `warning`
**What it checks**: Level 2 dynamic data presence and consistency.

- If `ticket.level2DataBlock` is present:
  - For FDC1 format: `ticket.dynamicContentData` must be populated (decoded successfully).
  - For `_<RICS>.ID1` format: `ticket.dynamicData` must be populated.
  - If the data block exists but decoding failed (the typed field is undefined), the check fails.
- If no level 2 data block is present, the check passes with an info message.

**Passes when**: Dynamic data is either absent or decoded successfully.

---

### 13. `checkDynamicContentFreshness`

**Key**: `dynamicContentFreshness`
**Severity**: `warning`
**What it checks**: The dynamic content timestamp (from FDC1 or Intercode ID1) is recent enough for anti-replay protection.

The maximum allowed age is derived from `security.validityDuration` (in minutes). If `validityDuration` is not set, the check is skipped with an info message.

- For **FDC1**: reads `dynamicContentData.dynamicContentTimeStamp` (day + time in seconds). Computes the absolute timestamp using the issuing year as epoch base. Checks that the dynamic content time is within `validityDuration` minutes of `now`.
- For **Intercode ID1**: reads `dynamicData.dynamicContentDay` and `dynamicData.dynamicContentTime` (minutes from midnight) with optional UTC offset. Same freshness check using `validityDuration`.
- If no dynamic data is present, the check is skipped with an info message.
- Uses the issuing date from `issuingDetail` as the reference epoch for day-offset fields.

**Passes when**: The dynamic content timestamp is within the `validityDuration` window relative to `now`.

---

## Execution order in `controlTicket()`

```
1. checkDecode          (fatal — all others skipped on failure)
2. checkHeader
3. checkSecurityInfo
4. checkLevel1Signature (async — needs raw bytes + key provider)
5. checkLevel2Signature (async — needs raw bytes)
6. checkNotExpired
7. checkNotSpecimen
8. checkActivated
9. checkIssuingDetail
10. checkTransportDocument
11. checkIntercodeExtension
12. checkDynamicData
13. checkDynamicContentFreshness
```

The `valid` field on `ControlResult` is computed as: every check with `severity: 'error'` has `passed: true`.

---

## Types to add to `src/types.ts`

```ts
// ---------------------------------------------------------------------------
// Ticket control types
// ---------------------------------------------------------------------------

/** Options for ticket control / validation. */
export interface ControlOptions {
  /** Reference date/time for temporal checks. Defaults to `new Date()`. */
  now?: Date;
  /** Level 1 key provider callback for signature verification. */
  level1KeyProvider?: Level1KeyProvider;
  /**
   * Set of expected Intercode network IDs (hex strings, e.g. "250502").
   * When provided, intercodeIssuing must be present and its networkId must
   * match one of the expected values.
   */
  expectedIntercodeNetworkIds?: Set<string>;
}

/** Result of a single validation check. */
export interface CheckResult {
  name: string;
  passed: boolean;
  severity: 'error' | 'warning' | 'info';
  message?: string;
}

/** Aggregated control result for a ticket. */
export interface ControlResult {
  /** True only if every check with severity 'error' passed. */
  valid: boolean;
  /** The decoded ticket (undefined if decoding failed). */
  ticket?: UicBarcodeTicket;
  /** Individual check results keyed by check name. */
  checks: Record<string, CheckResult>;
}
```

---

## Exports to add to `src/index.ts`

```ts
export { controlTicket } from './control';
export type { ControlOptions, ControlResult, CheckResult } from './types';
```

---

## Test file: `tests/control.test.ts`

### Test categories

1. **Decode failure**: Pass an invalid hex string, verify `decode` check fails and `valid` is `false`.

2. **Valid ticket (SAMPLE_TICKET_HEX)**: U1 header, FCB2, Intercode 6, _3703.ID1 dynamic data.
   - `decode` passes
   - `header` passes (U1, v1)
   - `securityInfo` passes
   - `level1Signature` — fails (no key provider, error)
   - `level2Signature` — info (level2SigningAlg not set)
   - `issuingDetail` passes
   - `activated` passes
   - `notSpecimen` passes
   - `transportDocument` passes (openTicket)
   - `intercodeExtension` passes (_3703II1 decoded)
   - `dynamicData` passes (_3703.ID1 decoded)

3. **Soléa ticket (SOLEA_TICKET_HEX)**: U2 header, +FRII1, FDC1.
   - `level2Signature` passes (ECDSA P-256)
   - `level1Signature` — fails (no key provider, error)
   - `intercodeExtension` passes (+FRII1 decoded)
   - `dynamicData` passes (FDC1 decoded)

4. **CTS ticket (CTS_TICKET_HEX)**: U2 header, +FRII1, FDC1.
   - Similar to Solea, verifies second FDC1 + FRII1 variant.

5. **SNCF TER ticket (SNCF_TER_TICKET_HEX)**: U1 header, DSA level 1, no level 2 signature.
   - `level2Signature` — info (level2SigningAlg not set)
   - `level1Signature` — error (DSA not supported even if key provider returns a key)

6. **Grand Est ticket (GRAND_EST_U1_FCB3_HEX)**: U1 header, FCB3, _3703II1, FDC1.
   - Tests FCB3 path + FDC1 in a U1 header context.

7. **Expiry check**: Use a controlled `now` option to test `notExpired` for both expired and valid tickets.

8. **Specimen ticket**: Encode (using existing `signAndEncodeTicket`) a ticket with `specimen: true`, verify `notSpecimen` fails.

9. **Tampered ticket**: Flip a byte in a known-good ticket, verify `level2Signature` fails.

10. **Network ID validation**: Pass `expectedIntercodeNetworkIds` with a matching set -> passes. Pass with a non-matching set -> fails with error.

11. **Missing network ID**: Pass `expectedIntercodeNetworkIds` on a ticket without Intercode extension -> fails.

12. **Dynamic content freshness**: Use a controlled `now` option relative to the dynamic content timestamp and `validityDuration` to test both fresh and stale scenarios.

---

## Summary of files to create/modify

| File | Action |
|---|---|
| `src/types.ts` | Add `ControlOptions`, `CheckResult`, `ControlResult` interfaces |
| `src/control.ts` | **New file** — `controlTicket()` + all check helper functions |
| `src/index.ts` | Add exports for `controlTicket` and the new types |
| `tests/control.test.ts` | **New file** — comprehensive tests covering all check functions across all ticket variants |
