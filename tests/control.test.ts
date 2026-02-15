import {
  controlTicket,
  signAndEncodeTicket,
  generateKeyPair,
  SAMPLE_TICKET_HEX,
  SNCF_TER_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  GRAND_EST_U1_FCB3_HEX,
} from '../src';
import type { UicBarcodeTicketInput, Level1KeyProvider } from '../src';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
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
    // Sample ticket has no issuerNum/issuerIA5
    expect(result.checks.issuingDetail.passed).toBe(false);
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
    expect(result.checks.level1Signature.message).toContain('No level 1 key provider');
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
        return new Uint8Array(65);
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
    // Grand Est ticket has no issuerNum/issuerIA5, so issuingDetail fails
    expect(result.checks.issuingDetail.passed).toBe(false);
    expect(result.checks.issuingDetail.message).toContain('missing issuer');
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
    const input: UicBarcodeTicketInput = {
      headerVersion: 2,
      fcbVersion: 2,
      securityProviderNum: 9999,
      keyId: 0,
      endOfValidityYear: 2099,
      endOfValidityDay: 365,
      railTicket: {
        issuingDetail: {
          issuerNum: 9999,
          issuingYear: 2025,
          issuingDay: 100,
          specimen: true,
          activated: true,
        },
        transportDocument: [{ ticketType: 'openTicket', ticket: { returnIncluded: false } }],
      },
    };
    const encoded = signAndEncodeTicket(input, keys);
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
    const iss = result.ticket?.railTickets[0]?.issuingDetail;
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
    const input: UicBarcodeTicketInput = {
      headerVersion: 2,
      fcbVersion: 2,
      securityProviderNum: 9999,
      keyId: 0,
      endOfValidityYear: 2099,
      endOfValidityDay: 365,
      railTicket: {
        issuingDetail: {
          issuerNum: 9999,
          issuingYear: 2025,
          issuingDay: 100,
          activated: true,
        },
        transportDocument: [{ ticketType: 'openTicket', ticket: { returnIncluded: false } }],
      },
    };
    const encoded = signAndEncodeTicket(input, keys);
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

  it('all 13 checks are present', async () => {
    const result = await controlTicket(SAMPLE_TICKET_HEX);
    const expectedKeys = [
      'decode', 'header', 'securityInfo', 'level1Signature', 'level2Signature',
      'notExpired', 'notSpecimen', 'activated', 'issuingDetail',
      'transportDocument', 'intercodeExtension', 'dynamicData', 'dynamicContentFreshness',
    ];
    for (const key of expectedKeys) {
      expect(result.checks[key]).toBeDefined();
    }
  });
});
