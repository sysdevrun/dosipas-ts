import {
  decodeTicket,
  getIssuingTime,
  getEndOfValidityTime,
  getDynamicContentTime,
  getOpenTicketValidityWindow,
  signAndEncodeTicket,
  generateKeyPair,
  SAMPLE_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
} from '../src';
import type { UicBarcodeTicket, OpenTicketData, IssuingDetail } from '../src';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Helper to build a minimal UicBarcodeTicket for testing. */
function makeTicket(opts: {
  headerVersion?: number;
  fcbVersion?: number;
  securityProviderNum?: number;
  keyId?: number;
  endOfValidityYear?: number;
  endOfValidityDay?: number;
  endOfValidityTime?: number;
  validityDuration?: number;
  issuingYear: number;
  issuingDay: number;
  issuingTime?: number;
  activated?: boolean;
  specimen?: boolean;
  transportDocument?: { ticket: { key: string; value: Record<string, unknown> } }[];
  level2Data?: UicBarcodeTicket['level2SignedData']['level2Data'];
}): UicBarcodeTicket {
  const hv = opts.headerVersion ?? 2;
  const fcb = opts.fcbVersion ?? 2;
  return {
    format: `U${hv}`,
    level2SignedData: {
      level1Data: {
        securityProviderNum: opts.securityProviderNum ?? 9999,
        keyId: opts.keyId ?? 0,
        endOfValidityYear: opts.endOfValidityYear,
        endOfValidityDay: opts.endOfValidityDay,
        endOfValidityTime: opts.endOfValidityTime,
        validityDuration: opts.validityDuration,
        dataSequence: [{
          dataFormat: `FCB${fcb}`,
          decoded: {
            issuingDetail: {
              issuingYear: opts.issuingYear,
              issuingDay: opts.issuingDay,
              issuingTime: opts.issuingTime,
              specimen: opts.specimen ?? false,
              securePaperTicket: false,
              activated: opts.activated ?? true,
            },
            transportDocument: opts.transportDocument ?? [
              { ticket: { key: 'openTicket', value: { returnIncluded: false } } },
            ],
          },
        }],
      },
      level2Data: opts.level2Data,
    },
  };
}

// ---------------------------------------------------------------------------
// getIssuingTime
// ---------------------------------------------------------------------------

describe('getIssuingTime', () => {
  it('computes issuing time from SAMPLE_TICKET_HEX', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    const time = getIssuingTime(ticket);
    expect(time).toBeDefined();
    // issuingYear=2020, issuingDay=121, issuingTime=995 minutes
    // Day 121 = April 30, 995 min = 16:35
    expect(time!.toISOString()).toBe('2020-04-30T16:35:00.000Z');
  });

  it('computes issuing time from SOLEA_TICKET_HEX', () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const time = getIssuingTime(ticket);
    expect(time).toBeDefined();
    expect(time!.getUTCFullYear()).toBeGreaterThanOrEqual(2020);
  });

  it('returns undefined when no rail ticket is decoded', () => {
    const keys = generateKeyPair('P-256');
    const ticket = makeTicket({
      issuingYear: 2025,
      issuingDay: 100,
    });
    const encoded = signAndEncodeTicket(ticket, keys);
    const hex = bytesToHex(encoded);
    const decoded = decodeTicket(hex);
    const time = getIssuingTime(decoded);
    // Should be defined since issuingDetail exists
    expect(time).toBeDefined();
    // Day 100 of 2025 = April 10
    expect(time!.toISOString()).toBe('2025-04-10T00:00:00.000Z');
  });

  it('handles issuingTime=0 (midnight)', () => {
    const keys = generateKeyPair('P-256');
    const ticket = makeTicket({
      issuingYear: 2025,
      issuingDay: 1,
      issuingTime: 0,
    });
    const encoded = signAndEncodeTicket(ticket, keys);
    const decoded = decodeTicket(bytesToHex(encoded));
    const time = getIssuingTime(decoded);
    expect(time).toBeDefined();
    expect(time!.toISOString()).toBe('2025-01-01T00:00:00.000Z');
  });
});

// ---------------------------------------------------------------------------
// getEndOfValidityTime
// ---------------------------------------------------------------------------

describe('getEndOfValidityTime', () => {
  it('computes v2 end-of-validity from encoded ticket', () => {
    const keys = generateKeyPair('P-256');
    const ticket = makeTicket({
      issuingYear: 2025,
      issuingDay: 200,
      endOfValidityYear: 2025,
      endOfValidityDay: 200,
      endOfValidityTime: 720, // 12:00 noon in minutes
      validityDuration: 3600, // 3600 seconds = 1 hour
    });
    const encoded = signAndEncodeTicket(ticket, keys);
    const decoded = decodeTicket(bytesToHex(encoded));
    const time = getEndOfValidityTime(decoded);
    expect(time).toBeDefined();
    // Day 200 of 2025 = July 19, 12:00 — validityDuration is NOT added
    expect(time!.toISOString()).toBe('2025-07-19T12:00:00.000Z');
  });

  it('returns undefined when only validityDuration is present (no endOfValidity fields)', () => {
    const keys = generateKeyPair('P-256');
    const ticket = makeTicket({
      issuingYear: 2025,
      issuingDay: 1,
      issuingTime: 60, // 1:00 AM
      validityDuration: 600, // 600 seconds — level2 dynamic duration, not used here
    });
    const encoded = signAndEncodeTicket(ticket, keys);
    const decoded = decodeTicket(bytesToHex(encoded));
    const time = getEndOfValidityTime(decoded);
    // validityDuration alone does not produce an end-of-validity
    expect(time).toBeUndefined();
  });

  it('returns undefined when no validity duration and no end-of-validity fields', () => {
    const keys = generateKeyPair('P-256');
    const ticket = makeTicket({
      issuingYear: 2025,
      issuingDay: 1,
    });
    const encoded = signAndEncodeTicket(ticket, keys);
    const decoded = decodeTicket(bytesToHex(encoded));
    const time = getEndOfValidityTime(decoded);
    expect(time).toBeUndefined();
  });

  it('computes from real Solea ticket (v2 header)', () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const time = getEndOfValidityTime(ticket);
    // Solea has v2 header with end-of-validity fields
    expect(time).toBeDefined();
    expect(time!.getUTCFullYear()).toBeGreaterThanOrEqual(2020);
  });
});

// ---------------------------------------------------------------------------
// getDynamicContentTime
// ---------------------------------------------------------------------------

describe('getDynamicContentTime', () => {
  it('computes Intercode dynamic content time from SAMPLE_TICKET_HEX', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    const time = getDynamicContentTime(ticket);
    expect(time).toBeDefined();
    // issuingDate = Date.UTC(2020, 0, 121) = Apr 30 2020
    // dynamicContentDay=0, dynamicContentTime=59710s (16h35m10s), dynamicContentUTCOffset=-8 (-120min)
    // genTimeMs = Apr 30 00:00 + 59710s + (-8)*15*60s = Apr 30 + 59710000 - 7200000 ms
    //           = Apr 30 + 52510000 ms = Apr 30 14:35:10 UTC
    expect(time!.toISOString()).toBe('2020-04-30T14:35:10.000Z');
  });

  it('computes FDC1 dynamic content time from SOLEA_TICKET_HEX', () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const time = getDynamicContentTime(ticket);
    // SOLEA has FDC1 with dynamicContentTimeStamp
    if (time) {
      expect(time).toBeInstanceOf(Date);
      expect(time.getUTCFullYear()).toBeGreaterThanOrEqual(2020);
    }
  });

  it('computes FDC1 dynamic content time from CTS_TICKET_HEX', () => {
    const ticket = decodeTicket(CTS_TICKET_HEX);
    const time = getDynamicContentTime(ticket);
    if (time) {
      expect(time).toBeInstanceOf(Date);
    }
  });

  it('returns undefined when no level2Data present', () => {
    const keys = generateKeyPair('P-256');
    const ticket = makeTicket({
      issuingYear: 2025,
      issuingDay: 1,
    });
    const encoded = signAndEncodeTicket(ticket, keys);
    const decoded = decodeTicket(bytesToHex(encoded));
    const time = getDynamicContentTime(decoded);
    expect(time).toBeUndefined();
  });

  it('computes FDC1 time from encoded ticket with dynamicContentTimeStamp', () => {
    const keys = generateKeyPair('P-256');
    const ticket = makeTicket({
      issuingYear: 2025,
      issuingDay: 50,
      level2Data: {
        dataFormat: 'FDC1',
        decoded: {
          dynamicContentTimeStamp: {
            day: 50,
            time: 43200, // 12:00:00 noon in seconds
          },
        },
      },
    });
    const encoded = signAndEncodeTicket(ticket, keys);
    const decoded = decodeTicket(bytesToHex(encoded));
    const time = getDynamicContentTime(decoded);
    expect(time).toBeDefined();
    // Date.UTC(2025, 0, 50, 0, 0, 43200) = Feb 19 2025 12:00:00
    expect(time!.toISOString()).toBe('2025-02-19T12:00:00.000Z');
  });

  it('computes Intercode time from encoded ticket with dynamic data', () => {
    const keys = generateKeyPair('P-256');
    const ticket = makeTicket({
      issuingYear: 2025,
      issuingDay: 50, // Feb 19
      level2Data: {
        dataFormat: '_9999.ID1',
        decoded: {
          dynamicContentDay: 1, // 1 day after issuing
          dynamicContentTime: 36000, // 10:00:00 AM local
          dynamicContentUTCOffset: -4, // UTC = local + (-4*15min) = local - 1h => local is UTC+1
        },
      },
    });
    const encoded = signAndEncodeTicket(ticket, keys);
    const decoded = decodeTicket(bytesToHex(encoded));
    const time = getDynamicContentTime(decoded);
    expect(time).toBeDefined();
    // issuingDate = Feb 19 2025 00:00 UTC
    // genTimeMs = Feb 19 + 1 day + 36000s + (-4)*15*60s
    //           = Feb 20 00:00 + 36000000 + (-3600000) ms
    //           = Feb 20 00:00 + 32400000 ms = Feb 20 09:00:00 UTC
    expect(time!.toISOString()).toBe('2025-02-20T09:00:00.000Z');
  });
});

// ---------------------------------------------------------------------------
// getOpenTicketValidityWindow
// ---------------------------------------------------------------------------

describe('getOpenTicketValidityWindow', () => {
  const baseIssuing: IssuingDetail = {
    issuingYear: 2025,
    issuingDay: 15, // Jan 15
    specimen: false,
    securePaperTicket: false,
    activated: true,
  };

  it('computes same-day ticket with explicit times', () => {
    const ot: OpenTicketData = {
      returnIncluded: false,
      validFromDay: 0,
      validFromTime: 600,   // 10:00
      validUntilDay: 0,
      validUntilTime: 720,  // 12:00
    };
    const w = getOpenTicketValidityWindow(ot, baseIssuing);
    expect(w).toBeDefined();
    // issuingDate = 2025-01-15 → validFrom = Jan 15 10:00 UTC, validUntil = Jan 15 12:00 UTC
    expect(w!.validFrom.toISOString()).toBe('2025-01-15T10:00:00.000Z');
    expect(w!.validUntil.toISOString()).toBe('2025-01-15T12:00:00.000Z');
  });

  it('computes multi-day ticket with default times (absent → 00:00 / 23:59)', () => {
    const ot: OpenTicketData = {
      returnIncluded: false,
      validFromDay: 1,
      validUntilDay: 2,
      // validFromTime absent → 0, validUntilTime absent → 1439
    };
    const w = getOpenTicketValidityWindow(ot, baseIssuing);
    expect(w).toBeDefined();
    // validFromDate = Jan 15 + 1 day = Jan 16 00:00 UTC
    // validUntilDate = Jan 16 + 2 days = Jan 18, + 1439 min = Jan 18 23:59 UTC
    expect(w!.validFrom.toISOString()).toBe('2025-01-16T00:00:00.000Z');
    expect(w!.validUntil.toISOString()).toBe('2025-01-18T23:59:00.000Z');
  });

  it('applies validFromUTCOffset correctly', () => {
    const ot: OpenTicketData = {
      returnIncluded: false,
      validFromDay: 0,
      validFromTime: 600,   // 10:00 local
      validFromUTCOffset: 4, // +1h (4 quarter-hours)
      validUntilDay: 0,
      validUntilTime: 720,  // 12:00 local
    };
    const w = getOpenTicketValidityWindow(ot, baseIssuing);
    expect(w).toBeDefined();
    // validFrom = 600min - 4*15min = 600 - 60 = 540min = 09:00 UTC
    // validUntil = 720min - 4*15min = 720 - 60 = 660min = 11:00 UTC
    expect(w!.validFrom.toISOString()).toBe('2025-01-15T09:00:00.000Z');
    expect(w!.validUntil.toISOString()).toBe('2025-01-15T11:00:00.000Z');
  });

  it('defaults all fields when absent', () => {
    const ot: OpenTicketData = {
      returnIncluded: false,
      // All time fields absent → validFromDay=0, validFromTime=0, validUntilDay=0, validUntilTime=1439
    };
    const w = getOpenTicketValidityWindow(ot, baseIssuing);
    expect(w).toBeDefined();
    // Same day as issuing: Jan 15 00:00 → Jan 15 23:59
    expect(w!.validFrom.toISOString()).toBe('2025-01-15T00:00:00.000Z');
    expect(w!.validUntil.toISOString()).toBe('2025-01-15T23:59:00.000Z');
  });

  it('validUntilUTCOffset falls back to validFromUTCOffset', () => {
    const ot: OpenTicketData = {
      returnIncluded: false,
      validFromDay: 0,
      validFromTime: 600,
      validFromUTCOffset: 4, // +1h
      validUntilDay: 0,
      validUntilTime: 720,
      // validUntilUTCOffset absent → falls back to validFromUTCOffset (4)
    };
    const w = getOpenTicketValidityWindow(ot, baseIssuing);
    expect(w).toBeDefined();
    // Both use offset 4 → -60min
    expect(w!.validFrom.toISOString()).toBe('2025-01-15T09:00:00.000Z');
    expect(w!.validUntil.toISOString()).toBe('2025-01-15T11:00:00.000Z');
  });

  it('handles negative validFromDay (day before issuing)', () => {
    const ot: OpenTicketData = {
      returnIncluded: false,
      validFromDay: -1,
      validFromTime: 0,
      validUntilDay: 0,
      validUntilTime: 1439,
    };
    const w = getOpenTicketValidityWindow(ot, baseIssuing);
    expect(w).toBeDefined();
    // validFromDate = Jan 15 - 1 day = Jan 14
    // validUntilDate = Jan 14 + 0 = Jan 14 23:59
    expect(w!.validFrom.toISOString()).toBe('2025-01-14T00:00:00.000Z');
    expect(w!.validUntil.toISOString()).toBe('2025-01-14T23:59:00.000Z');
  });

  it('uses distinct validUntilUTCOffset when provided', () => {
    const ot: OpenTicketData = {
      returnIncluded: false,
      validFromDay: 0,
      validFromTime: 600,
      validFromUTCOffset: 4,   // +1h
      validUntilDay: 0,
      validUntilTime: 720,
      validUntilUTCOffset: 8,  // +2h
    };
    const w = getOpenTicketValidityWindow(ot, baseIssuing);
    expect(w).toBeDefined();
    // validFrom = 600 - 60 = 540min = 09:00 UTC
    // validUntil = 720 - 120 = 600min = 10:00 UTC
    expect(w!.validFrom.toISOString()).toBe('2025-01-15T09:00:00.000Z');
    expect(w!.validUntil.toISOString()).toBe('2025-01-15T10:00:00.000Z');
  });
});
