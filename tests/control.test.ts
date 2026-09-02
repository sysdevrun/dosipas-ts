import {
  controlTicket,
  signAndEncodeTicket,
  generateKeyPair,
  SAMPLE_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
  CAR_JAUNE_TICKET_HEX,
  CAR_JAUNE_SIGNATURES,
} from '../src';
import type { UicBarcodeTicket, Level1KeyProvider } from '../src';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

/** Helper to build a minimal UicBarcodeTicket for testing. */
function makeTicket(opts: {
  securityProviderNum?: number;
  keyId?: number;
  endOfValidityYear?: number;
  endOfValidityDay?: number;
  issuerNum?: number;
  issuingYear: number;
  issuingDay: number;
  specimen?: boolean;
  activated?: boolean;
  openTicketValue?: Record<string, unknown>;
  /** When set, use this ticket key instead of 'openTicket'. */
  ticketKey?: string;
}): UicBarcodeTicket {
  return {
    format: 'U2',
    level2SignedData: {
      level1Data: {
        securityProviderNum: opts.securityProviderNum ?? 9999,
        keyId: opts.keyId ?? 0,
        endOfValidityYear: opts.endOfValidityYear,
        endOfValidityDay: opts.endOfValidityDay,
        dataSequence: [{
          dataFormat: 'FCB2',
          decoded: {
            issuingDetail: {
              issuerNum: opts.issuerNum,
              issuingYear: opts.issuingYear,
              issuingDay: opts.issuingDay,
              specimen: opts.specimen ?? false,
              securePaperTicket: false,
              activated: opts.activated ?? true,
            },
            transportDocument: [
              {
                ticket: {
                  key: opts.ticketKey ?? 'openTicket',
                  value: opts.openTicketValue ?? { returnIncluded: false },
                },
              },
            ],
          },
        }],
      },
    },
  };
}

// ---------------------------------------------------------------------------
// 1. Decode failure
// ---------------------------------------------------------------------------

describe('controlTicket — decode failure', () => {
  it('returns failed decode check for invalid hex', async () => {
    const result = await controlTicket('zzzz');
    expect(result.valid).toBe(false);
    expect(result.ticket).toBeUndefined();
    expect(result.checks.decode.passed).toBe(false);
    expect(result.checks.decode.severity).toBe('error');
    // All other checks should be absent
    expect(Object.keys(result.checks)).toEqual(['decode']);
  });

  it('returns failed decode check for empty string', async () => {
    const result = await controlTicket('');
    expect(result.valid).toBe(false);
    expect(result.checks.decode.passed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2. SAMPLE_TICKET_HEX — U1, FCB2, Intercode 6, _3703.ID1
// ---------------------------------------------------------------------------

describe('controlTicket — SAMPLE_TICKET_HEX', () => {
  it('decodes and validates structural checks', async () => {
    const result = await controlTicket(SAMPLE_TICKET_HEX);

    expect(result.ticket).toBeDefined();
    expect(result.checks.decode.passed).toBe(true);
    expect(result.checks.header.passed).toBe(true);
    expect(result.checks.securityInfo.passed).toBe(true);
    expect(result.checks.issuingDetail.passed).toBe(true);
    expect(result.checks.activated.passed).toBe(true);
    expect(result.checks.notSpecimen.passed).toBe(true);
    expect(result.checks.transportDocument.passed).toBe(true);
    expect(result.checks.intercodeExtension.passed).toBe(true);
    expect(result.checks.dynamicData.passed).toBe(true);
  });

  it('level1Signature fails without key provider', async () => {
    const result = await controlTicket(SAMPLE_TICKET_HEX);
    expect(result.checks.level1Signature.passed).toBe(false);
    expect(result.checks.level1Signature.severity).toBe('error');
    expect(result.checks.level1Signature.message).toContain('No level 1 key material');
  });

  it('level2Signature fails for sample ticket (synthetic signatures)', async () => {
    // SAMPLE_TICKET_HEX has level2SigningAlg set but uses synthetic signature data,
    // so L2 verification should fail
    const result = await controlTicket(SAMPLE_TICKET_HEX);
    expect(result.checks.level2Signature.passed).toBe(false);
    expect(result.checks.level2Signature.severity).toBe('error');
  });
});

// ---------------------------------------------------------------------------
// 3. Soléa ticket — U2, +FRII1, FDC1
// ---------------------------------------------------------------------------

describe('controlTicket — SOLEA_TICKET_HEX', () => {
  it('level2Signature passes (ECDSA P-256)', async () => {
    const result = await controlTicket(SOLEA_TICKET_HEX);

    expect(result.checks.decode.passed).toBe(true);
    expect(result.checks.level2Signature.passed).toBe(true);
    expect(result.checks.level2Signature.severity).toBe('error');
    expect(result.checks.level1Signature.passed).toBe(false);
    expect(result.checks.intercodeExtension.passed).toBe(true);
    expect(result.checks.dynamicData.passed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 4. CTS ticket — U2, +FRII1, FDC1
// ---------------------------------------------------------------------------

describe('controlTicket — CTS_TICKET_HEX', () => {
  it('validates CTS ticket structure', async () => {
    const result = await controlTicket(CTS_TICKET_HEX);

    expect(result.checks.decode.passed).toBe(true);
    expect(result.checks.level2Signature.passed).toBe(true);
    expect(result.checks.intercodeExtension.passed).toBe(true);
    expect(result.checks.dynamicData.passed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 5. SNCF TER — U1, DSA level 1, no level 2 signature
// ---------------------------------------------------------------------------

describe('controlTicket — SNCF_TER_TICKET_HEX', () => {
  it('level2Signature is info (level2SigningAlg not set)', async () => {
    const result = await controlTicket(SNCF_TER_TICKET_HEX);
    expect(result.checks.level2Signature.passed).toBe(true);
    expect(result.checks.level2Signature.severity).toBe('info');
  });

  it('level1Signature fails when key provider returns a key (v1 header, no OID)', async () => {
    // SNCF TER uses a v1 header which doesn't include OID fields,
    // so the verifier can't determine the signing algorithm
    const dummyProvider: Level1KeyProvider = {
      async getPublicKey() {
        return { publicKey: new Uint8Array(65) };
      },
    };
    const result = await controlTicket(SNCF_TER_TICKET_HEX, {
      level1KeyProvider: dummyProvider,
    });
    expect(result.checks.level1Signature.passed).toBe(false);
    expect(result.checks.level1Signature.severity).toBe('error');
  });
});

// ---------------------------------------------------------------------------
// 6. Grand Est — U1, FCB3, _3703II1, FDC1
// ---------------------------------------------------------------------------

describe('controlTicket — GRAND_EST_U1_FCB3_HEX', () => {
  it('validates Grand Est ticket with FCB3', async () => {
    const result = await controlTicket(GRAND_EST_U1_FCB3_HEX);

    expect(result.checks.decode.passed).toBe(true);
    expect(result.checks.header.passed).toBe(true);
    expect(result.checks.issuingDetail.passed).toBe(true);
    expect(result.checks.intercodeExtension.passed).toBe(true);
    expect(result.checks.dynamicData.passed).toBe(true);
    // Grand Est is a specimen ticket
    expect(result.checks.notSpecimen.passed).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 7. Expiry check
// ---------------------------------------------------------------------------

describe('controlTicket — expiry', () => {
  it('ticket is not expired when now is in the past', async () => {
    // Use a very early date to ensure the ticket is not expired
    const result = await controlTicket(SOLEA_TICKET_HEX, {
      now: new Date('2020-01-01T00:00:00Z'),
    });
    expect(result.checks.notExpired.passed).toBe(true);
  });

  it('ticket is expired when now is far in the future', async () => {
    const result = await controlTicket(SOLEA_TICKET_HEX, {
      now: new Date('2099-12-31T23:59:59Z'),
    });
    expect(result.checks.notExpired.passed).toBe(false);
    expect(result.checks.notExpired.severity).toBe('error');
  });
});

// ---------------------------------------------------------------------------
// 8. Specimen ticket
// ---------------------------------------------------------------------------

describe('controlTicket — specimen', () => {
  it('fails notSpecimen for a specimen ticket', async () => {
    const keys = generateKeyPair('P-256');
    const ticket = makeTicket({
      issuerNum: 9999,
      issuingYear: 2025,
      issuingDay: 100,
      specimen: true,
      endOfValidityYear: 2099,
      endOfValidityDay: 365,
    });
    const encoded = signAndEncodeTicket(ticket, keys);
    const hex = bytesToHex(encoded);

    const result = await controlTicket(hex);
    expect(result.checks.notSpecimen.passed).toBe(false);
    expect(result.checks.notSpecimen.severity).toBe('error');
  });
});

// ---------------------------------------------------------------------------
// 9. Tampered ticket
// ---------------------------------------------------------------------------

describe('controlTicket — tampered ticket', () => {
  it('fails level2Signature for tampered Soléa ticket', async () => {
    // Flip a byte in the middle of the ticket
    const hexArr = SOLEA_TICKET_HEX.split('');
    // Flip a byte in the data region (well past the header)
    const pos = 200;
    hexArr[pos] = hexArr[pos] === 'a' ? 'b' : 'a';
    const tampered = hexArr.join('');

    const result = await controlTicket(tampered);
    // The ticket should still decode, but L2 signature should fail
    if (result.checks.decode.passed) {
      expect(result.checks.level2Signature.passed).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// 10. Network ID validation — matching
// ---------------------------------------------------------------------------

describe('controlTicket — network ID validation', () => {
  it('passes when network ID matches expected set', async () => {
    // SAMPLE_TICKET_HEX has _3703II1 intercode extension, network ID needs to be extracted
    const result = await controlTicket(SAMPLE_TICKET_HEX);
    const rt = result.ticket?.level2SignedData.level1Data.dataSequence
      .find(e => e.decoded)?.decoded;
    const iss = rt?.issuingDetail;
    expect(iss?.intercodeIssuing).toBeDefined();

    const networkHex = Array.from(iss!.intercodeIssuing!.networkId)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    const result2 = await controlTicket(SAMPLE_TICKET_HEX, {
      expectedIntercodeNetworkIds: new Set([networkHex]),
    });
    expect(result2.checks.intercodeExtension.passed).toBe(true);
  });

  it('fails when network ID does not match expected set', async () => {
    const result = await controlTicket(SAMPLE_TICKET_HEX, {
      expectedIntercodeNetworkIds: new Set(['ffffff']),
    });
    expect(result.checks.intercodeExtension.passed).toBe(false);
    expect(result.checks.intercodeExtension.severity).toBe('error');
  });
});

// ---------------------------------------------------------------------------
// 11. Missing network ID
// ---------------------------------------------------------------------------

describe('controlTicket — missing network ID', () => {
  it('fails when expected network IDs set on ticket without Intercode', async () => {
    // Create a ticket without Intercode extension
    const keys = generateKeyPair('P-256');
    const ticket = makeTicket({
      issuerNum: 9999,
      issuingYear: 2025,
      issuingDay: 100,
      endOfValidityYear: 2099,
      endOfValidityDay: 365,
    });
    const encoded = signAndEncodeTicket(ticket, keys);
    const hex = bytesToHex(encoded);

    const result = await controlTicket(hex, {
      expectedIntercodeNetworkIds: new Set(['250502']),
    });
    expect(result.checks.intercodeExtension.passed).toBe(false);
    expect(result.checks.intercodeExtension.message).toContain('absent');
  });
});

// ---------------------------------------------------------------------------
// 12. Dynamic content freshness
// ---------------------------------------------------------------------------

describe('controlTicket — dynamic content freshness', () => {
  it('dynamic content is fresh when now is in the past', async () => {
    const result = await controlTicket(SAMPLE_TICKET_HEX, {
      now: new Date('2020-01-01T00:00:00Z'),
    });
    // If dynamic data has freshness info, it should pass with an old now
    // Otherwise it's info (no duration available)
    expect(result.checks.dynamicContentFreshness.passed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Overall validity
// ---------------------------------------------------------------------------

describe('controlTicket — overall validity', () => {
  it('valid is false when level1 signature fails (no key provider)', async () => {
    const result = await controlTicket(SAMPLE_TICKET_HEX);
    // level1Signature fails = error severity => valid is false
    expect(result.valid).toBe(false);
  });

  it('all 15 checks are present', async () => {
    const result = await controlTicket(SAMPLE_TICKET_HEX);
    const expectedKeys = [
      'decode', 'header', 'securityInfo', 'level1Signature', 'level2Signature',
      'notExpired', 'notSpecimen', 'activated', 'issuingDetail',
      'transportDocument', 'intercodeExtension', 'dynamicData', 'dynamicContentFreshness',
      'zonesAndCarriers', 'openTicketValidity',
    ];
    for (const key of expectedKeys) {
      expect(result.checks[key]).toBeDefined();
    }
  });
});

// ---------------------------------------------------------------------------
// Zones & Carriers validation
// ---------------------------------------------------------------------------

describe('controlTicket — zones & carriers', () => {
  const baseOpts = {
    issuingYear: 2025,
    issuingDay: 100,
    endOfValidityYear: 2099,
    endOfValidityDay: 365,
  };

  async function controlWithOpenTicket(
    openTicketValue: Record<string, unknown>,
    controlOpts?: Partial<import('../src').ControlOptions>,
    ticketKey?: string,
  ) {
    const keys = generateKeyPair('P-256');
    const ticket = makeTicket({ ...baseOpts, openTicketValue, ticketKey });
    const encoded = signAndEncodeTicket(ticket, keys);
    const hex = bytesToHex(encoded);
    return controlTicket(hex, controlOpts);
  }

  it('passes with no constraints specified (info)', async () => {
    const result = await controlWithOpenTicket({ returnIncluded: false });
    expect(result.checks.zonesAndCarriers.passed).toBe(true);
    expect(result.checks.zonesAndCarriers.severity).toBe('info');
  });

  it('passes when expected carriers match top-level carrierNum', async () => {
    const result = await controlWithOpenTicket(
      { returnIncluded: false, carrierNum: [1080] },
      { expectedCarriers: [1080] },
    );
    expect(result.checks.zonesAndCarriers.passed).toBe(true);
  });

  it('fails when expected carriers do not match', async () => {
    const result = await controlWithOpenTicket(
      { returnIncluded: false, carrierNum: [1080] },
      { expectedCarriers: [9999] },
    );
    expect(result.checks.zonesAndCarriers.passed).toBe(false);
    expect(result.checks.zonesAndCarriers.severity).toBe('error');
  });

  it('passes when expected carriers match via productOwnerNum', async () => {
    const result = await controlWithOpenTicket(
      { returnIncluded: false, productOwnerNum: 1080 },
      { expectedCarriers: [1080] },
    );
    expect(result.checks.zonesAndCarriers.passed).toBe(true);
  });

  it('passes when expected carriers match via IA5', async () => {
    const result = await controlWithOpenTicket(
      { returnIncluded: false, carrierIA5: ['SNCF'] },
      { expectedCarriers: ['SNCF'] },
    );
    expect(result.checks.zonesAndCarriers.passed).toBe(true);
  });

  it('passes when expected zones match zoneId', async () => {
    const result = await controlWithOpenTicket(
      {
        returnIncluded: false,
        validRegion: [
          { key: 'zones', value: { zoneId: [1, 2, 3] } },
        ],
      },
      { expectedZones: [1, 2] },
    );
    expect(result.checks.zonesAndCarriers.passed).toBe(true);
  });

  it('fails when expected zones are partially missing', async () => {
    const result = await controlWithOpenTicket(
      {
        returnIncluded: false,
        validRegion: [
          { key: 'zones', value: { zoneId: [1, 2] } },
        ],
      },
      { expectedZones: [1, 2, 5] },
    );
    expect(result.checks.zonesAndCarriers.passed).toBe(false);
  });

  it('passes when multiple zone entries are aggregated', async () => {
    const result = await controlWithOpenTicket(
      {
        returnIncluded: false,
        validRegion: [
          { key: 'zones', value: { zoneId: [1, 2] } },
          { key: 'zones', value: { zoneId: [3, 4] } },
        ],
      },
      { expectedZones: [1, 3] },
    );
    expect(result.checks.zonesAndCarriers.passed).toBe(true);
  });

  it('passes when both zones AND carriers are satisfied', async () => {
    const result = await controlWithOpenTicket(
      {
        returnIncluded: false,
        carrierNum: [1080],
        validRegion: [
          { key: 'zones', value: { zoneId: [1, 2, 3] } },
        ],
      },
      { expectedCarriers: [1080], expectedZones: [1, 2] },
    );
    expect(result.checks.zonesAndCarriers.passed).toBe(true);
  });

  it('fails when carrier matches but zone does not', async () => {
    const result = await controlWithOpenTicket(
      {
        returnIncluded: false,
        carrierNum: [1080],
        validRegion: [
          { key: 'zones', value: { zoneId: [1, 2] } },
        ],
      },
      { expectedCarriers: [1080], expectedZones: [99] },
    );
    expect(result.checks.zonesAndCarriers.passed).toBe(false);
  });

  it('passes when carrier is found in validRegion zones entry', async () => {
    const result = await controlWithOpenTicket(
      {
        returnIncluded: false,
        validRegion: [
          { key: 'zones', value: { carrierNum: 1080, zoneId: [1, 2] } },
        ],
      },
      { expectedCarriers: [1080] },
    );
    expect(result.checks.zonesAndCarriers.passed).toBe(true);
  });

  it('fails when no openTicket document exists', async () => {
    const result = await controlWithOpenTicket(
      { departureTime: 0 },
      { expectedZones: [1] },
      'reservation',
    );
    expect(result.checks.zonesAndCarriers.passed).toBe(false);
    expect(result.checks.zonesAndCarriers.message).toContain('No openTicket');
  });

  it('passes with string-based zone matching via nutsCode', async () => {
    const result = await controlWithOpenTicket(
      {
        returnIncluded: false,
        validRegion: [
          { key: 'zones', value: { nutsCode: 'FR101' } },
        ],
      },
      { expectedZones: ['FR101'] },
    );
    expect(result.checks.zonesAndCarriers.passed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Open ticket validity window
// ---------------------------------------------------------------------------

describe('controlTicket — open ticket validity', () => {
  const baseOpts = {
    issuingYear: 2025,
    issuingDay: 100, // April 10
    endOfValidityYear: 2099,
    endOfValidityDay: 365,
  };

  async function controlWithOpenTicket(
    openTicketValue: Record<string, unknown>,
    controlOpts?: Partial<import('../src').ControlOptions>,
    ticketKey?: string,
  ) {
    const keys = generateKeyPair('P-256');
    const ticket = makeTicket({ ...baseOpts, openTicketValue, ticketKey });
    const encoded = signAndEncodeTicket(ticket, keys);
    const hex = bytesToHex(encoded);
    return controlTicket(hex, controlOpts);
  }

  it('passes when now is within validity window', async () => {
    // validFrom = day 100 (Apr 10) 00:00, validUntil = day 100 + 365 days + 1439 min
    const result = await controlWithOpenTicket(
      { returnIncluded: false, validFromDay: 0, validFromTime: 0, validUntilDay: 365, validUntilTime: 1439 },
      { now: new Date('2025-06-15T12:00:00Z') },
    );
    expect(result.checks.openTicketValidity.passed).toBe(true);
  });

  it('fails when now is before validity window', async () => {
    // Ticket valid from day+10 to day+20
    const result = await controlWithOpenTicket(
      { returnIncluded: false, validFromDay: 10, validFromTime: 0, validUntilDay: 10, validUntilTime: 1439 },
      { now: new Date('2025-04-10T00:00:00Z') }, // Apr 10, ticket starts Apr 20
    );
    expect(result.checks.openTicketValidity.passed).toBe(false);
    expect(result.checks.openTicketValidity.severity).toBe('error');
    expect(result.checks.openTicketValidity.message).toContain('outside validity window');
  });

  it('fails when now is after validity window', async () => {
    // Ticket valid on issuing day only
    const result = await controlWithOpenTicket(
      { returnIncluded: false, validFromDay: 0, validFromTime: 0, validUntilDay: 0, validUntilTime: 1439 },
      { now: new Date('2025-04-11T12:00:00Z') }, // Apr 11, ticket ended Apr 10 23:59
    );
    expect(result.checks.openTicketValidity.passed).toBe(false);
    expect(result.checks.openTicketValidity.severity).toBe('error');
  });

  it('passes with info when no openTicket exists (reservation)', async () => {
    const result = await controlWithOpenTicket(
      { departureTime: 0 },
      { now: new Date('2025-06-15T12:00:00Z') },
      'reservation',
    );
    expect(result.checks.openTicketValidity.passed).toBe(true);
    expect(result.checks.openTicketValidity.severity).toBe('info');
    expect(result.checks.openTicketValidity.message).toContain('No openTicket');
  });

  it('defaults to full day when no times are set', async () => {
    // validFromDay=0, validUntilDay=0 → issuing day 00:00 to 23:59
    const result = await controlWithOpenTicket(
      { returnIncluded: false, validFromDay: 0, validUntilDay: 0 },
      { now: new Date('2025-04-10T15:30:00Z') }, // Apr 10 15:30, should be in range
    );
    expect(result.checks.openTicketValidity.passed).toBe(true);
  });

  it('applies UTC offset correctly', async () => {
    // validFromTime=600 (10:00 local), offset=4 (+1h) → 09:00 UTC
    // validUntilTime=720 (12:00 local), offset=4 (+1h) → 11:00 UTC
    const result = await controlWithOpenTicket(
      {
        returnIncluded: false,
        validFromDay: 0, validFromTime: 600, validFromUTCOffset: 4,
        validUntilDay: 0, validUntilTime: 720,
        // validUntilUTCOffset absent → falls back to validFromUTCOffset
      },
      { now: new Date('2025-04-10T10:00:00Z') }, // 10:00 UTC, between 09:00-11:00
    );
    expect(result.checks.openTicketValidity.passed).toBe(true);
  });

  it('passes when one of multiple openTickets is valid', async () => {
    // Build a ticket with two openTickets manually
    const keys = generateKeyPair('P-256');
    const ticket: UicBarcodeTicket = {
      format: 'U2',
      level2SignedData: {
        level1Data: {
          securityProviderNum: 9999,
          keyId: 0,
          endOfValidityYear: 2099,
          endOfValidityDay: 365,
          dataSequence: [{
            dataFormat: 'FCB2',
            decoded: {
              issuingDetail: {
                issuingYear: 2025,
                issuingDay: 100,
                specimen: false,
                securePaperTicket: false,
                activated: true,
              },
              transportDocument: [
                {
                  ticket: {
                    key: 'openTicket',
                    value: {
                      returnIncluded: false,
                      validFromDay: 0, validFromTime: 0,
                      validUntilDay: 0, validUntilTime: 60, // Expired: Apr 10 00:00-01:00
                    },
                  },
                },
                {
                  ticket: {
                    key: 'openTicket',
                    value: {
                      returnIncluded: false,
                      validFromDay: 0, validFromTime: 0,
                      validUntilDay: 365, validUntilTime: 1439, // Valid: full year
                    },
                  },
                },
              ],
            },
          }],
        },
      },
    };
    const encoded = signAndEncodeTicket(ticket, keys);
    const hex = bytesToHex(encoded);
    const result = await controlTicket(hex, { now: new Date('2025-06-15T12:00:00Z') });
    expect(result.checks.openTicketValidity.passed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Barcodes that omit their algorithm OIDs
// ---------------------------------------------------------------------------

describe('controlTicket — barcode without algorithm OIDs', () => {
  const level1Key = {
    publicKey: hexToBytes(CAR_JAUNE_SIGNATURES.level1PublicKeyHex),
    keyAlg: CAR_JAUNE_SIGNATURES.level1KeyAlg,
    signingAlg: CAR_JAUNE_SIGNATURES.level1SigningAlg,
  };

  it('passes security info and level 1 when algorithms are configured', async () => {
    const result = await controlTicket(CAR_JAUNE_TICKET_HEX, { level1Key });

    expect(result.checks.securityInfo.passed).toBe(true);
    expect(result.checks.level1Signature.passed).toBe(true);
    expect(result.checks.level1Signature.algorithm).toBe('ECDSA P-256 with SHA-256');
    expect(result.checks.level1Signature.algorithmSource).toBe('configured');
    // Static barcode — no Level 2 block, so the check is informational.
    expect(result.checks.level2Signature.severity).toBe('info');
  });

  it('notes the absent OIDs on security info without failing that check', async () => {
    const result = await controlTicket(CAR_JAUNE_TICKET_HEX, { level1Key });
    expect(result.checks.securityInfo.message).toContain('level1SigningAlg absent');
    expect(result.checks.securityInfo.message).toContain('level1KeyAlg absent');
  });

  // Relaxing checkSecurityInfo must not weaken the overall verdict: without
  // key material the ticket is still not valid, it just fails in one place.
  it('is still invalid with no key material at all', async () => {
    const result = await controlTicket(CAR_JAUNE_TICKET_HEX);

    expect(result.checks.securityInfo.passed).toBe(true);
    expect(result.checks.level1Signature.passed).toBe(false);
    expect(result.checks.level1Signature.message).toContain('No level 1 key material');
    expect(result.valid).toBe(false);
  });

  it('reports a wrong key as invalid rather than unverifiable', async () => {
    const wrong = generateKeyPair('P-256');
    const result = await controlTicket(CAR_JAUNE_TICKET_HEX, {
      level1Key: { ...level1Key, publicKey: wrong.publicKey },
    });
    expect(result.checks.level1Signature.passed).toBe(false);
    expect(result.valid).toBe(false);
  });
});
