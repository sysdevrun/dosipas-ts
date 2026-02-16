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
} from './types';

// ---------------------------------------------------------------------------
// Internal accessors (duplicated from control.ts to avoid coupling)
// ---------------------------------------------------------------------------

function headerVersion(ticket: UicBarcodeTicket): number {
  const m = ticket.format.match(/^U(\d)$/);
  return m ? parseInt(m[1], 10) : 0;
}

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
 * - **v2 headers**: `endOfValidityYear` + `endOfValidityDay` +
 *   `endOfValidityTime` (minutes) + `validityDuration` (seconds).
 * - **v1 headers**: issuing time + `validityDuration` (seconds).
 *
 * Returns `undefined` when required fields are missing.
 */
export function getEndOfValidityTime(ticket: UicBarcodeTicket): Date | undefined {
  const l1 = ticket.level2SignedData.level1Data;

  if (headerVersion(ticket) >= 2 && l1.endOfValidityYear != null && l1.endOfValidityDay != null) {
    return new Date(
      Date.UTC(l1.endOfValidityYear, 0, l1.endOfValidityDay, 0, l1.endOfValidityTime ?? 0)
      + (l1.validityDuration ?? 0) * 1000,
    );
  }

  // v1: issuing time + validityDuration
  if (l1.validityDuration != null) {
    const issuing = getIssuingTime(ticket);
    if (issuing) {
      return new Date(issuing.getTime() + l1.validityDuration * 1000);
    }
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
