/**
 * Time computation helpers for decoded UIC barcode tickets.
 *
 * Each function accepts a decoded {@link UicBarcodeTicket} and returns
 * a `Date` (UTC) or `undefined` when required fields are missing.
 */
import type {
  UicBarcodeTicket,
  UicRailTicketData,
  UicDynamicContentData,
  IntercodeDynamicData,
  OpenTicketData,
  IssuingDetail,
} from './types.js';

// ---------------------------------------------------------------------------
// Internal accessors
// ---------------------------------------------------------------------------

function firstRailTicket(ticket: UicBarcodeTicket): UicRailTicketData | undefined {
  for (const entry of ticket.level2SignedData.level1Data.dataSequence) {
    if (entry.decoded) return entry.decoded;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Public helpers
// ---------------------------------------------------------------------------

/**
 * Compute the issuing timestamp as a UTC Date.
 *
 * Built from `issuingDetail.issuingYear` + `issuingDay` (day-of-year) +
 * optional `issuingTime` (minutes since midnight).
 *
 * Returns `undefined` when `issuingDetail` is absent.
 */
export function getIssuingTime(ticket: UicBarcodeTicket): Date | undefined {
  const iss = firstRailTicket(ticket)?.issuingDetail;
  if (!iss) return undefined;
  return new Date(Date.UTC(iss.issuingYear, 0, iss.issuingDay, 0, iss.issuingTime ?? 0));
}

/**
 * Compute the end-of-validity timestamp as a UTC Date.
 *
 * Uses only the explicit `endOfValidityYear` + `endOfValidityDay` +
 * `endOfValidityTime` (minutes) fields from the header.
 *
 * `validityDuration` is **not** used here — it represents the
 * level 2 dynamic content validity duration, not the ticket end of validity.
 *
 * Returns `undefined` when required fields are missing.
 */
export function getEndOfValidityTime(ticket: UicBarcodeTicket): Date | undefined {
  const l1 = ticket.level2SignedData.level1Data;

  if (l1.endOfValidityYear != null && l1.endOfValidityDay != null) {
    return new Date(
      Date.UTC(l1.endOfValidityYear, 0, l1.endOfValidityDay, 0, l1.endOfValidityTime ?? 0),
    );
  }

  return undefined;
}

/**
 * Compute the dynamic content generation timestamp as a UTC Date.
 *
 * Supports both formats:
 * - **FDC1** (`UicDynamicContentData`): `issuingYear` + `day` (day-of-year) +
 *   `time` (seconds since midnight).
 * - **ID1** (`IntercodeDynamicData`): issuing date + `dynamicContentDay` (days offset) +
 *   `dynamicContentTime` (local seconds since midnight) +
 *   `dynamicContentUTCOffset` (quarter-hours, local + offset = UTC).
 *
 * Returns `undefined` when dynamic content or required fields are absent.
 */
export function getDynamicContentTime(ticket: UicBarcodeTicket): Date | undefined {
  const iss = firstRailTicket(ticket)?.issuingDetail;
  const l2 = ticket.level2SignedData.level2Data;
  if (!l2?.decoded || !iss) return undefined;

  // FDC1
  if (l2.dataFormat === 'FDC1') {
    const fdc = l2.decoded as UicDynamicContentData;
    const ts = fdc.dynamicContentTimeStamp;
    if (!ts) return undefined;
    return new Date(Date.UTC(iss.issuingYear, 0, ts.day, 0, 0, ts.time));
  }

  // Intercode _RICS.ID1
  if (/^_\d+\.ID1$/.test(l2.dataFormat)) {
    const dd = l2.decoded as IntercodeDynamicData;
    const issuingDate = new Date(Date.UTC(iss.issuingYear, 0, iss.issuingDay));
    const genTimeMs = issuingDate.getTime()
      + (dd.dynamicContentDay ?? 0) * 86400_000
      + (dd.dynamicContentTime ?? 0) * 1000
      + (dd.dynamicContentUTCOffset ?? 0) * 15 * 60_000;
    return new Date(genTimeMs);
  }

  return undefined;
}

/**
 * Compute the validFrom and validUntil absolute timestamps (UTC)
 * for an OpenTicketData, given the issuing detail.
 *
 * Follows UIC IRS 90918-9 semantics:
 * - `validFromDay` defaults to 0 (same day as issuing).
 * - `validFromTime` absent → 0 (start of day, 00:00).
 * - `validUntilDay` defaults to 0 (same day as validFrom).
 * - `validUntilTime` absent → 1439 (end of day, 23:59).
 * - `validUntilUTCOffset` absent → falls back to `validFromUTCOffset`, then 0.
 *
 * Returns `undefined` when `issuingDetail` is missing required fields.
 */
export function getOpenTicketValidityWindow(
  openTicket: OpenTicketData,
  issuingDetail: IssuingDetail,
): { validFrom: Date; validUntil: Date } | undefined {
  if (issuingDetail.issuingYear == null || issuingDetail.issuingDay == null) {
    return undefined;
  }

  const issuingDate = Date.UTC(issuingDetail.issuingYear, 0, issuingDetail.issuingDay);

  const validFromDate = issuingDate + (openTicket.validFromDay ?? 0) * 86_400_000;
  const validFrom = validFromDate
    + (openTicket.validFromTime ?? 0) * 60_000
    - (openTicket.validFromUTCOffset ?? 0) * 15 * 60_000;

  const validUntilDate = validFromDate + (openTicket.validUntilDay ?? 0) * 86_400_000;
  const validUntil = validUntilDate
    + (openTicket.validUntilTime ?? 1439) * 60_000
    - (openTicket.validUntilUTCOffset ?? openTicket.validFromUTCOffset ?? 0) * 15 * 60_000;

  return { validFrom: new Date(validFrom), validUntil: new Date(validUntil) };
}
