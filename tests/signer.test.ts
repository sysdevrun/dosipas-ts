import {
  decodeTicket,
  decodeTicketFromBytes,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  SAMPLE_TICKET_HEX,
  signLevel1,
  signLevel2,
  signAndEncodeTicket,
  generateKeyPair,
  getPublicKey,
  verifyLevel1Signature,
  verifyLevel2Signature,
  CURVES,
} from '../src';
import type { UicBarcodeTicketInput, SigningKeyPair } from '../src';

/** NIST FIPS 186-4 ECDSA P-256 test vector private keys. */
const FIPS_L1_PRIV = hexToBytes('c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357');
const FIPS_L2_PRIV = hexToBytes('710735c8388f48c684a97bd66751cc5f5a122d6b9a96a2dbe73662f78217446d');

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert a decoded UicBarcodeTicket into a UicBarcodeTicketInput suitable
 * for re-encoding. Strips signatures (they will be re-signed).
 */
function decodedToInput(hex: string): UicBarcodeTicketInput {
  const ticket = decodeTicket(hex);
  const rt = ticket.railTickets[0];

  const input: UicBarcodeTicketInput = {
    headerVersion: ticket.headerVersion,
    fcbVersion: rt.fcbVersion,
    securityProviderNum: ticket.security.securityProviderNum,
    keyId: ticket.security.keyId,
    endOfValidityYear: ticket.security.endOfValidityYear,
    endOfValidityDay: ticket.security.endOfValidityDay,
    endOfValidityTime: ticket.security.endOfValidityTime,
    validityDuration: ticket.security.validityDuration,
    railTicket: {
      issuingDetail: {
        securityProviderNum: rt.issuingDetail?.securityProviderNum,
        issuerNum: rt.issuingDetail?.issuerNum,
        issuingYear: rt.issuingDetail?.issuingYear ?? 2020,
        issuingDay: rt.issuingDetail?.issuingDay ?? 1,
        issuingTime: rt.issuingDetail?.issuingTime,
        issuerName: rt.issuingDetail?.issuerName,
        specimen: rt.issuingDetail?.specimen,
        securePaperTicket: rt.issuingDetail?.securePaperTicket,
        activated: rt.issuingDetail?.activated,
        currency: rt.issuingDetail?.currency,
        currencyFract: rt.issuingDetail?.currencyFract,
        issuerPNR: rt.issuingDetail?.issuerPNR,
        intercodeIssuing: rt.issuingDetail?.intercodeIssuing
          ? {
              intercodeVersion: rt.issuingDetail.intercodeIssuing.intercodeVersion,
              intercodeInstanciation: rt.issuingDetail.intercodeIssuing.intercodeInstanciation,
              networkId: rt.issuingDetail.intercodeIssuing.networkId,
              productRetailer: rt.issuingDetail.intercodeIssuing.productRetailer,
            }
          : undefined,
      },
      travelerDetail: rt.travelerDetail
        ? {
            traveler: rt.travelerDetail.traveler,
            preferredLanguage: rt.travelerDetail.preferredLanguage,
            groupName: rt.travelerDetail.groupName,
          }
        : undefined,
      transportDocument: rt.transportDocument?.map(doc => ({
        ticketType: doc.ticketType,
        ticket: doc.ticket,
      })),
      controlDetail: rt.controlDetail as Record<string, unknown> | undefined,
    },
  };

  // Add dynamic data if present (FDC1 or Intercode)
  if (ticket.dynamicContentData) {
    input.dynamicContentData = ticket.dynamicContentData;
  } else if (ticket.dynamicData && ticket.level2DataBlock) {
    const ricsMatch = ticket.level2DataBlock.dataFormat.match(/^_(\d+)\.ID1$/);
    const rics = ricsMatch ? parseInt(ricsMatch[1], 10) : ticket.security.securityProviderNum ?? 0;
    input.dynamicData = {
      rics,
      dynamicContentDay: ticket.dynamicData.dynamicContentDay,
      dynamicContentTime: ticket.dynamicData.dynamicContentTime,
      dynamicContentUTCOffset: ticket.dynamicData.dynamicContentUTCOffset,
      dynamicContentDuration: ticket.dynamicData.dynamicContentDuration,
    };
  }

  return input;
}

function makeKeyPair(privateKey: Uint8Array, curve: 'P-256' | 'P-384' | 'P-521'): SigningKeyPair {
  return {
    privateKey,
    publicKey: getPublicKey(privateKey, curve),
    curve,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('signLevel1', () => {
  it('produces a DER signature for Solea ticket data', () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    const sig = signLevel1(input, FIPS_L1_PRIV, 'P-256');

    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBeGreaterThan(0);
    // DER signature starts with SEQUENCE tag
    expect(sig[0]).toBe(0x30);
  });
});

describe('signLevel2', () => {
  it('requires level1Signature to be set', () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    expect(() => signLevel2(input, FIPS_L2_PRIV, 'P-256')).toThrow(
      'Level 1 signature must be set',
    );
  });

  it('produces a DER signature when L1 is set', () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    const l1Sig = signLevel1(input, FIPS_L1_PRIV, 'P-256');

    const inputWithL1 = { ...input, level1Signature: l1Sig };
    const l2Sig = signLevel2(inputWithL1, FIPS_L2_PRIV, 'P-256');

    expect(l2Sig).toBeInstanceOf(Uint8Array);
    expect(l2Sig[0]).toBe(0x30);
  });
});

describe('signAndEncodeTicket', () => {
  it('encodes a signed ticket from Solea data', () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const bytes = signAndEncodeTicket(input, l1Key, l2Key);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBeGreaterThan(100);
  });

  it('works without Level 2 key (static barcode)', () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    // Remove dynamic data for static mode
    delete (input as any).dynamicData;
    delete (input as any).dynamicContentData;
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');

    const bytes = signAndEncodeTicket(input, l1Key);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBeGreaterThan(100);
  });
});

describe('decode → re-encode → decode round-trip', () => {
  it('Solea ticket round-trips through encode/decode', () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    // Encode with new signatures
    const encoded = signAndEncodeTicket(input, l1Key, l2Key);

    // Decode the re-encoded ticket
    const decoded = decodeTicketFromBytes(encoded);

    expect(decoded.format).toBe('U2');
    expect(decoded.headerVersion).toBe(2);
    expect(decoded.railTickets).toHaveLength(1);

    const rt = decoded.railTickets[0];
    expect(rt.issuingDetail).toBeDefined();
    expect(rt.transportDocument).toBeDefined();
    expect(rt.transportDocument!.length).toBeGreaterThan(0);

    // Verify Intercode 6 data survived
    expect(rt.issuingDetail!.intercodeIssuing).toBeDefined();
    expect(rt.issuingDetail!.intercodeIssuing!.intercodeVersion).toBe(1);

    // Verify FDC1 dynamic content data survived the round-trip
    expect(decoded.dynamicContentData).toBeDefined();
    expect(decoded.level2DataBlock!.dataFormat).toBe('FDC1');
    // Intercode dynamic data should not be set for FDC1
    expect(decoded.dynamicData).toBeUndefined();
  });

  it('CTS ticket round-trips through encode/decode', () => {
    const input = decodedToInput(CTS_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(input, l1Key, l2Key);
    const decoded = decodeTicketFromBytes(encoded);

    expect(decoded.format).toBe('U2');
    expect(decoded.railTickets).toHaveLength(1);
    expect(decoded.railTickets[0].issuingDetail!.intercodeIssuing).toBeDefined();
  });

  it('Sample ticket round-trips through encode/decode', () => {
    const input = decodedToInput(SAMPLE_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(input, l1Key, l2Key);
    const decoded = decodeTicketFromBytes(encoded);

    expect(decoded.railTickets).toHaveLength(1);
    const rt = decoded.railTickets[0];
    expect(rt.issuingDetail!.intercodeIssuing).toBeDefined();
    expect(decoded.dynamicData).toBeDefined();
  });
});

describe('signature verification on re-encoded tickets', () => {
  it('Level 1 signature verifies on re-encoded Solea ticket', async () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(input, l1Key, l2Key);
    const result = await verifyLevel1Signature(encoded, l1Key.publicKey);

    expect(result.valid).toBe(true);
    expect(result.algorithm).toContain('ECDSA');
  });

  it('Level 2 signature verifies on re-encoded Solea ticket', async () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(input, l1Key, l2Key);
    const result = await verifyLevel2Signature(encoded);

    expect(result.valid).toBe(true);
    expect(result.algorithm).toContain('ECDSA');
  });

  it('both levels verify on re-encoded CTS ticket', async () => {
    const input = decodedToInput(CTS_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(input, l1Key, l2Key);

    const l1Result = await verifyLevel1Signature(encoded, l1Key.publicKey);
    const l2Result = await verifyLevel2Signature(encoded);

    expect(l1Result.valid).toBe(true);
    expect(l2Result.valid).toBe(true);
  });

  it('Level 1 only (static) verifies on re-encoded ticket', async () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    delete (input as any).dynamicData;
    delete (input as any).dynamicContentData;
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(input, l1Key);
    const result = await verifyLevel1Signature(encoded, l1Key.publicKey);

    expect(result.valid).toBe(true);
  });

  it('P-384 signatures verify on re-encoded ticket', async () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    const l1Key = generateKeyPair('P-384');
    const l2Key = generateKeyPair('P-384');

    const encoded = signAndEncodeTicket(input, l1Key, l2Key);

    const l1Result = await verifyLevel1Signature(encoded, l1Key.publicKey);
    const l2Result = await verifyLevel2Signature(encoded);

    expect(l1Result.valid).toBe(true);
    expect(l2Result.valid).toBe(true);
  });
});
