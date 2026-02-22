# Plan: Add OpenTicket Validity Window Check to `controlTicket`

## Problem

`controlTicket()` does not validate whether the current time falls within the
openTicket's `validFrom → validUntil` window. The fields `validFromDay`,
`validFromTime`, `validUntilDay`, `validUntilTime` (and their UTC offset
variants) on `OpenTicketData` are completely ignored. A ticket could be
presented outside its valid travel period and pass all checks.

---

## ASN.1 Field Semantics (from UIC IRS 90918-9)

| Field | Type | Default | Range | Meaning |
|---|---|---|---|---|
| `validFromDay` | INTEGER | 0 | -367 .. 700 | Day offset from **issuing date** |
| `validFromTime` | INTEGER | _(absent)_ | 0 .. 1439 | Minutes from midnight. Absent → start of day (00:00) |
| `validFromUTCOffset` | INTEGER | _(absent)_ | -60 .. 60 | Quarter-hours. `UTC = local − offset * 15min`. Absent → treat as UTC |
| `validUntilDay` | INTEGER | 0 | -1 .. 500 | Day offset from **validFrom date** (not from issuing date) |
| `validUntilTime` | INTEGER | _(absent)_ | 0 .. 1439 | Minutes from midnight. Absent → end of day (1439 = 23:59) |
| `validUntilUTCOffset` | INTEGER | _(absent)_ | -60 .. 60 | Quarter-hours. Same convention as `validFromUTCOffset`. Absent → use `validFromUTCOffset` if set, else UTC |

**Computed absolute times (UTC):**

```
issuingDate = Date.UTC(issuingYear, 0, issuingDay)

validFromDate = issuingDate + validFromDay * 86400000
validFrom     = validFromDate
              + (validFromTime ?? 0) * 60000
              - (validFromUTCOffset ?? 0) * 15 * 60000

validUntilDate = validFromDate + (validUntilDay ?? 0) * 86400000
validUntil     = validUntilDate
               + (validUntilTime ?? 1439) * 60000
               - (validUntilUTCOffset ?? validFromUTCOffset ?? 0) * 15 * 60000
```

When `validUntilTime` is absent, we use 1439 (23:59) as the default — the
ticket is valid until end of day.

---

## 1. New Time Helper (in `src/time-helpers.ts`)

### `getOpenTicketValidityWindow`

```typescript
/**
 * Compute the validFrom and validUntil absolute timestamps (UTC)
 * for an OpenTicketData, given the issuing detail.
 *
 * Returns undefined if issuingDetail is missing.
 */
export function getOpenTicketValidityWindow(
  openTicket: OpenTicketData,
  issuingDetail: IssuingDetail,
): { validFrom: Date; validUntil: Date } | undefined
```

**Logic:**
1. Compute `issuingDate = Date.UTC(issuingYear, 0, issuingDay)`.
2. Compute `validFromDate = issuingDate + (openTicket.validFromDay ?? 0) * 86_400_000`.
3. Compute `validFrom = validFromDate + (openTicket.validFromTime ?? 0) * 60_000 - (openTicket.validFromUTCOffset ?? 0) * 15 * 60_000`.
4. Compute `validUntilDate = validFromDate + (openTicket.validUntilDay ?? 0) * 86_400_000`.
5. Compute `validUntil = validUntilDate + (openTicket.validUntilTime ?? 1439) * 60_000 - (openTicket.validUntilUTCOffset ?? openTicket.validFromUTCOffset ?? 0) * 15 * 60_000`.
6. Return `{ validFrom: new Date(validFrom), validUntil: new Date(validUntil) }`.

Add `OpenTicketData` and `IssuingDetail` to the imports from `./types`.

---

## 2. New Check Function (in `src/control.ts`)

### `checkOpenTicketValidity`

```typescript
function checkOpenTicketValidity(
  ticket: UicBarcodeTicket,
  now: Date,
): CheckResult
```

**Key**: `openTicketValidity`
**Severity**: `error`

**Logic:**
1. Get `issuingDetail` from `firstRailTicket(ticket)`.
2. Get all openTickets via `getOpenTickets(ticket)`.
3. If no openTickets exist, return `passed: true` with severity `info` and message "No openTicket transport documents — skipping validity window check". (We don't want to fail here — that's `checkTransportDocument`'s job.)
4. If `issuingDetail` is missing, return `passed: true` with severity `info` and message "Cannot determine validity window — missing issuingDetail".
5. For each openTicket, compute the validity window via `getOpenTicketValidityWindow(ot, issuingDetail)`.
6. If **at least one** openTicket's window contains `now` (`validFrom <= now` and `now <= validUntil`), pass.
7. If **none** of the openTickets' windows contain `now`, fail with an error message listing the windows.

**Why `<=` on both sides**: The `validUntilTime` of 1211 means "valid until 20:11", inclusive of that minute. This matches standard rail practice where the end time is inclusive.

---

## 3. Integration into `controlTicket()` (in `src/control.ts`)

Add as **check #15**, after `zonesAndCarriers` (check #14):

```typescript
// 15. Open Ticket Validity Window
checks.openTicketValidity = checkOpenTicketValidity(ticket, now);
```

Import `getOpenTicketValidityWindow` from `./time-helpers`.

---

## 4. Exports (in `src/index.ts`)

Export the new time helper:

```typescript
export { getIssuingTime, getEndOfValidityTime, getDynamicContentTime, getOpenTicketValidityWindow } from './time-helpers';
```

---

## 5. Tests

### 5a. Unit tests for `getOpenTicketValidityWindow` (in `tests/time-helpers.test.ts`)

Add a new describe block. Test cases:

1. **Basic same-day ticket**: `validFromDay: 0, validFromTime: 600, validUntilDay: 0, validUntilTime: 720` with issuing 2025-01-15 → validFrom = 2025-01-15T10:00Z, validUntil = 2025-01-15T12:00Z.
2. **Multi-day ticket**: `validFromDay: 1, validUntilDay: 2` with no times → validFrom = day+1 00:00, validUntil = day+3 23:59.
3. **With UTC offset**: `validFromUTCOffset: 4` (= +1h from UTC) → times shifted by -1h in UTC.
4. **Defaults**: `validFromDay` absent (→ 0), `validUntilDay` absent (→ 0), `validFromTime` absent (→ 0), `validUntilTime` absent (→ 1439).
5. **validUntilUTCOffset falls back to validFromUTCOffset**.
6. **Negative validFromDay**: `validFromDay: -1` → valid from the day before issuing.

### 5b. Integration tests for `checkOpenTicketValidity` (in `tests/control.test.ts`)

Add a new describe block `controlTicket — open ticket validity`. Use the existing `controlWithOpenTicket` helper pattern. Test cases:

1. **Within validity window → pass**: Set `validFromDay: 0, validFromTime: 0, validUntilDay: 365, validUntilTime: 1439` with `now` inside the window.
2. **Before validity window → fail**: Set `now` before `validFrom`.
3. **After validity window → fail**: Set `now` after `validUntil`.
4. **No openTicket → info/pass**: Ticket with `reservation` key only, no expectedCarriers → passes with info.
5. **No times set (defaults) → full day**: `validFromDay: 0, validUntilDay: 0` with no time fields → valid from midnight to 23:59 on issuing day.
6. **With UTC offset**: Verify the offset shifts the window correctly.
7. **Multiple openTickets, one valid → pass**: Two openTickets where the first is expired but the second is current.

### 5c. Update "all N checks" test

Update the existing test `'all 14 checks are present'` to expect **15** checks and include `'openTicketValidity'` in the expected keys list.

---

## 6. CHANGELOG.md

Add entry:

```markdown
### Bug Fixes

- **`controlTicket` — open ticket validity window**: New `openTicketValidity`
  check validates that the current time falls within the `validFrom → validUntil`
  window of at least one openTicket transport document. Previously, tickets
  presented outside their valid travel period were not detected.
- **New helper**: `getOpenTicketValidityWindow()` computes the absolute
  validity window (UTC) for an OpenTicketData given its issuing detail.
```

---

## 7. Files Changed (summary)

| File | Action |
|------|--------|
| `src/time-helpers.ts` | Add `getOpenTicketValidityWindow()` function |
| `src/control.ts` | Add `checkOpenTicketValidity()` function; wire into `controlTicket()` as check #15; add import for `getOpenTicketValidityWindow` |
| `src/index.ts` | Add `getOpenTicketValidityWindow` to exports |
| `tests/time-helpers.test.ts` | Add tests for `getOpenTicketValidityWindow` (new file or append to existing) |
| `tests/control.test.ts` | Add ~7 integration tests; update "all checks" count to 15 |
| `CHANGELOG.md` | Add entry |

---

## 8. Implementation Order

1. Add `getOpenTicketValidityWindow()` to `src/time-helpers.ts`
2. Add `checkOpenTicketValidity()` to `src/control.ts` and wire into `controlTicket()`
3. Update exports in `src/index.ts`
4. Add unit tests for the time helper
5. Add integration tests in `tests/control.test.ts`
6. Run `npx tsc --noEmit` to type-check
7. Run `npm test` to verify all tests pass
8. Update `CHANGELOG.md`
