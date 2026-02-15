# Plan: Ticket Validity Control Helpers

## Overview

Add a new `controlTicket()` function and supporting helpers that perform comprehensive validation of a dosipas ticket. The function takes a hex string, decodes it once, then runs a series of focused check functions — each responsible for verifying one specific aspect of the ticket. Results are collected into a structured report.

The design supports all ticket variants the library handles: FDC1 dynamic content, Intercode 6 extensions (`+FRII1`, `_<RICS>II1`), Intercode dynamic data (`_<RICS>.ID1`), tickets without level 2 signatures (v1 headers / DSA-only), and multiple FCB versions (1, 2, 3).

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

  /** Level 1 public key bytes — forwarded to signature verification. */
  level1PublicKey?: Uint8Array;

  /** Level 1 key provider — forwarded to signature verification. */
  level1KeyProvider?: Level1KeyProvider;

  /**
   * Maximum age in minutes for dynamic content data (FDC1 or Intercode ID1).
   * If the dynamic content timestamp is older than this, the freshness check fails.
   * Defaults to 60 (1 hour).
   */
  dynamicContentMaxAge?: number;
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
**What it checks**: The minimum required security metadata is present.

- `security.securityProviderNum` or `security.securityProviderIA5` is set.
- `security.keyId` is set.
- At least one signing algorithm OID is present (`level1SigningAlg` or `level2SigningAlg`).
- At least one key algorithm OID is present (`level1KeyAlg` or `level2KeyAlg`).

**Passes when**: All conditions are met.

---

### 4. `checkLevel2Signature`

**Key**: `level2Signature`
**Severity**: `error` for v2 headers, `info` for v1 headers
**What it checks**: Level 2 signature validity using the existing `verifyLevel2Signature()`.

- For **v2 header** tickets: level 2 signature, public key, and algorithm OIDs must be present and the signature must verify. Failure is an error.
- For **v1 header** tickets: level 2 data may be absent. If absent, the check passes with an info message ("Level 2 signature not present — v1 header"). If present, it is verified normally.

**Implementation**: Calls `verifyLevel2Signature(bytes)` from the existing `verifier.ts`.

---

### 5. `checkLevel1Signature`

**Key**: `level1Signature`
**Severity**: `warning` (since the level 1 public key may not be available)
**What it checks**: Level 1 signature validity using the existing `verifyLevel1Signature()`.

- If no `level1PublicKey` and no `level1KeyProvider` are provided in options, the check passes with an info message ("No level 1 key provided — skipped").
- If a key is available, calls `verifyLevel1Signature(bytes, publicKey)`.
- For DSA-signed tickets (e.g. SNCF TER), the check will fail with a warning since DSA verification is not supported by the library.

**Implementation**: Reuses logic from `verifySignatures()` in `verifier.ts`, but surfaces the result as a `CheckResult`.

---

### 6. `checkNotExpired`

**Key**: `notExpired`
**Severity**: `error`
**What it checks**: The ticket has not exceeded its validity period.

- For **v2 headers**: uses `security.endOfValidityYear`, `security.endOfValidityDay`, `security.endOfValidityTime` to compute the expiry instant. If `validityDuration` is also set, adds it to get the final expiry.
- For **v1 headers**: uses the issuing date (`issuingYear`, `issuingDay`) + `validityDuration` from security info (if available). If no duration is available, the check is skipped with an info message.
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
- `issuingYear` and `issuingDay` are present and in plausible ranges (year ≥ 2016, day 1–366).
- `issuerNum` or `issuerIA5` is present.

**Passes when**: All conditions are met.

---

### 10. `checkTransportDocument`

**Key**: `transportDocument`
**Severity**: `error`
**What it checks**: At least one transport document is present in the rail ticket.

- `railTickets[0].transportDocument` exists and has length ≥ 1.
- Each entry has a non-empty `ticketType`.

**Passes when**: At least one transport document with a valid type is found.

---

### 11. `checkIntercodeExtension`

**Key**: `intercodeExtension`
**Severity**: `warning`
**What it checks**: If an Intercode 6 issuing extension is expected (based on the extension ID pattern), it was successfully decoded.

- If `issuingDetail.intercodeIssuing` is present, the check passes — the extension decoded correctly.
- If `issuingDetail.extension` is present and its `extensionId` matches `_<RICS>II1` or `+<CC>II1`, the check fails — the extension should have been decoded as Intercode but fell through to raw.
- If neither is present, the check passes with an info message ("No issuing extension present").

**Passes when**: Intercode extension is either absent or successfully decoded.

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

- For **FDC1**: reads `dynamicContentData.dynamicContentTimeStamp` (day + time in seconds). Computes the absolute timestamp and checks it is within `dynamicContentMaxAge` minutes of `now`.
- For **Intercode ID1**: reads `dynamicData.dynamicContentDay` and `dynamicData.dynamicContentTime` (minutes from midnight) with optional UTC offset. Same freshness check.
- If no dynamic data is present, the check is skipped with an info message.
- Uses the issuing date from `issuingDetail` as the reference epoch for day-offset fields.

**Passes when**: The dynamic content timestamp is within the allowed age window.

---

## Execution order in `controlTicket()`

```
1. checkDecode          (fatal — all others skipped on failure)
2. checkHeader
3. checkSecurityInfo
4. checkLevel2Signature (async — needs raw bytes)
5. checkLevel1Signature (async — needs raw bytes + options)
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
  /** Level 1 public key bytes — forwarded to signature verification. */
  level1PublicKey?: Uint8Array;
  /** Level 1 key provider — forwarded to signature verification. */
  level1KeyProvider?: Level1KeyProvider;
  /**
   * Maximum age in minutes for dynamic content freshness.
   * Defaults to 60.
   */
  dynamicContentMaxAge?: number;
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
   - `level2Signature` — depends on v1 behavior (info or verified)
   - `level1Signature` — skipped (no key provided, warning/info)
   - `issuingDetail` passes
   - `activated` passes
   - `notSpecimen` passes
   - `transportDocument` passes (openTicket)
   - `intercodeExtension` passes (_3703II1 decoded)
   - `dynamicData` passes (_3703.ID1 decoded)

3. **Soléa ticket (SOLEA_TICKET_HEX)**: U2 header, +FRII1, FDC1.
   - `level2Signature` passes (ECDSA P-256)
   - `intercodeExtension` passes (+FRII1 decoded)
   - `dynamicData` passes (FDC1 decoded)

4. **CTS ticket (CTS_TICKET_HEX)**: U2 header, +FRII1, FDC1.
   - Similar to Soléa, verifies second FDC1 + FRII1 variant.

5. **SNCF TER ticket (SNCF_TER_TICKET_HEX)**: U1 header, DSA level 1, no level 2 signature.
   - `level2Signature` — info (v1 header, no L2 data)
   - `level1Signature` — warning (DSA not supported) if key provided, info if skipped

6. **Grand Est ticket (GRAND_EST_U1_FCB3_HEX)**: U1 header, FCB3, _3703II1, FDC1.
   - Tests FCB3 path + FDC1 in a U1 header context.

7. **Expiry check**: Use a controlled `now` option to test `notExpired` for both expired and valid tickets.

8. **Specimen ticket**: Encode (using existing `signAndEncodeTicket`) a ticket with `specimen: true`, verify `notSpecimen` fails.

9. **Tampered ticket**: Flip a byte in a known-good ticket, verify `level2Signature` fails.

10. **No key provided**: Verify `level1Signature` returns info/skipped message when no key is provided.

---

## Summary of files to create/modify

| File | Action |
|---|---|
| `src/types.ts` | Add `ControlOptions`, `CheckResult`, `ControlResult` interfaces |
| `src/control.ts` | **New file** — `controlTicket()` + all check helper functions |
| `src/index.ts` | Add exports for `controlTicket` and the new types |
| `tests/control.test.ts` | **New file** — comprehensive tests covering all check functions across all ticket variants |
