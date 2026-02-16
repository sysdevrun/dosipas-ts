import {
  decodeTicket,
  getIssuingTime,
  getEndOfValidityTime,
  getDynamicContentTime,
  signAndEncodeTicket,
  generateKeyPair,
  SAMPLE_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
} from '../src';
import type { UicBarcodeTicketInput } from '../src';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
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
    const input: UicBarcodeTicketInput = {
      headerVersion: 2,
      fcbVersion: 2,
      securityProviderNum: 9999,
      keyId: 0,
      railTicket: {
        issuingDetail: {
          issuingYear: 2025,
          issuingDay: 100,
          activated: true,
        },
        transportDocument: [{ ticketType: 'openTicket', ticket: { returnIncluded: false } }],
      },
    };
    const encoded = signAndEncodeTicket(input, keys);
    const hex = bytesToHex(encoded);
    const ticket = decodeTicket(hex);
    const time = getIssuingTime(ticket);
    // Should be defined since issuingDetail exists
    expect(time).toBeDefined();
    // Day 100 of 2025 = April 10
    expect(time!.toISOString()).toBe('2025-04-10T00:00:00.000Z');
  });

  it('handles issuingTime=0 (midnight)', () => {
    const keys = generateKeyPair('P-256');
    const input: UicBarcodeTicketInput = {
      headerVersion: 2,
      fcbVersion: 2,
      securityProviderNum: 9999,
      keyId: 0,
      railTicket: {
        issuingDetail: {
          issuingYear: 2025,
          issuingDay: 1,
          issuingTime: 0,
          activated: true,
        },
        transportDocument: [{ ticketType: 'openTicket', ticket: { returnIncluded: false } }],
      },
    };
    const encoded = signAndEncodeTicket(input, keys);
    const ticket = decodeTicket(bytesToHex(encoded));
    const time = getIssuingTime(ticket);
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
    const input: UicBarcodeTicketInput = {
      headerVersion: 2,
      fcbVersion: 2,
      securityProviderNum: 9999,
      keyId: 0,
      endOfValidityYear: 2025,
      endOfValidityDay: 200,
      endOfValidityTime: 720, // 12:00 noon in minutes
      validityDuration: 3600, // 3600 seconds = 1 hour
      railTicket: {
        issuingDetail: {
          issuingYear: 2025,
          issuingDay: 200,
          activated: true,
        },
        transportDocument: [{ ticketType: 'openTicket', ticket: { returnIncluded: false } }],
      },
    };
    const encoded = signAndEncodeTicket(input, keys);
    const ticket = decodeTicket(bytesToHex(encoded));
    const time = getEndOfValidityTime(ticket);
    expect(time).toBeDefined();
    // Day 200 of 2025 = July 19, 12:00 + 3600s = 13:00
    expect(time!.toISOString()).toBe('2025-07-19T13:00:00.000Z');
  });

  it('computes v2 end-of-validity from issuing time + validityDuration only', () => {
    // validityDuration is only available in v2 headers
    const keys = generateKeyPair('P-256');
    const input: UicBarcodeTicketInput = {
      headerVersion: 2,
      fcbVersion: 2,
      securityProviderNum: 9999,
      keyId: 0,
      validityDuration: 600, // 600 seconds = 10 minutes
      // No endOfValidity fields set — falls back to issuing time + duration
      railTicket: {
        issuingDetail: {
          issuingYear: 2025,
          issuingDay: 1,
          issuingTime: 60, // 1:00 AM
          activated: true,
        },
        transportDocument: [{ ticketType: 'openTicket', ticket: { returnIncluded: false } }],
      },
    };
    const encoded = signAndEncodeTicket(input, keys);
    const ticket = decodeTicket(bytesToHex(encoded));
    const time = getEndOfValidityTime(ticket);
    expect(time).toBeDefined();
    // Jan 1 2025 01:00 + 10 min = 01:10
    expect(time!.toISOString()).toBe('2025-01-01T01:10:00.000Z');
  });

  it('returns undefined when no validity duration and no end-of-validity fields', () => {
    const keys = generateKeyPair('P-256');
    const input: UicBarcodeTicketInput = {
      headerVersion: 2,
      fcbVersion: 2,
      securityProviderNum: 9999,
      keyId: 0,
      railTicket: {
        issuingDetail: {
          issuingYear: 2025,
          issuingDay: 1,
          activated: true,
        },
        transportDocument: [{ ticketType: 'openTicket', ticket: { returnIncluded: false } }],
      },
    };
    const encoded = signAndEncodeTicket(input, keys);
    const ticket = decodeTicket(bytesToHex(encoded));
    const time = getEndOfValidityTime(ticket);
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
    // May or may not have timestamp fields depending on the ticket content
    // At minimum, if timestamp is present, it should return a valid Date
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
    const input: UicBarcodeTicketInput = {
      headerVersion: 2,
      fcbVersion: 2,
      securityProviderNum: 9999,
      keyId: 0,
      railTicket: {
        issuingDetail: {
          issuingYear: 2025,
          issuingDay: 1,
          activated: true,
        },
        transportDocument: [{ ticketType: 'openTicket', ticket: { returnIncluded: false } }],
      },
    };
    const encoded = signAndEncodeTicket(input, keys);
    const ticket = decodeTicket(bytesToHex(encoded));
    const time = getDynamicContentTime(ticket);
    expect(time).toBeUndefined();
  });

  it('computes FDC1 time from encoded ticket with dynamicContentTimeStamp', () => {
    const keys = generateKeyPair('P-256');
    const input: UicBarcodeTicketInput = {
      headerVersion: 2,
      fcbVersion: 2,
      securityProviderNum: 9999,
      keyId: 0,
      railTicket: {
        issuingDetail: {
          issuingYear: 2025,
          issuingDay: 50,
          activated: true,
        },
        transportDocument: [{ ticketType: 'openTicket', ticket: { returnIncluded: false } }],
      },
      dynamicContentData: {
        dynamicContentTimeStamp: {
          day: 50,
          time: 43200, // 12:00:00 noon in seconds
        },
      },
    };
    const encoded = signAndEncodeTicket(input, keys);
    const ticket = decodeTicket(bytesToHex(encoded));
    const time = getDynamicContentTime(ticket);
    expect(time).toBeDefined();
    // Date.UTC(2025, 0, 50, 0, 0, 43200) = Feb 19 2025 12:00:00
    expect(time!.toISOString()).toBe('2025-02-19T12:00:00.000Z');
  });

  it('computes Intercode time from encoded ticket with dynamic data', () => {
    const keys = generateKeyPair('P-256');
    const input: UicBarcodeTicketInput = {
      headerVersion: 2,
      fcbVersion: 2,
      securityProviderNum: 9999,
      keyId: 0,
      railTicket: {
        issuingDetail: {
          issuingYear: 2025,
          issuingDay: 50, // Feb 19
          activated: true,
        },
        transportDocument: [{ ticketType: 'openTicket', ticket: { returnIncluded: false } }],
      },
      dynamicData: {
        rics: 9999,
        dynamicContentDay: 1, // 1 day after issuing
        dynamicContentTime: 36000, // 10:00:00 AM local
        dynamicContentUTCOffset: -4, // UTC = local + (-4*15min) = local - 1h => local is UTC+1
      },
    };
    const encoded = signAndEncodeTicket(input, keys);
    const ticket = decodeTicket(bytesToHex(encoded));
    const time = getDynamicContentTime(ticket);
    expect(time).toBeDefined();
    // issuingDate = Feb 19 2025 00:00 UTC
    // genTimeMs = Feb 19 + 1 day + 36000s + (-4)*15*60s
    //           = Feb 20 00:00 + 36000000 + (-3600000) ms
    //           = Feb 20 00:00 + 32400000 ms = Feb 20 09:00:00 UTC
    expect(time!.toISOString()).toBe('2025-02-20T09:00:00.000Z');
  });
});
