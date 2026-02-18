import {
  decodeTicket,
  decodeTicketFromBytes,
  encodeTicketToBytes,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  SAMPLE_TICKET_HEX,
  signLevel1,
  signLevel2,
  signAndEncodeTicket,
  signPayload,
  encodeLevel2Data,
  encodeLevel1Data,
  encodeLevel2SignedData,
  encodeUicBarcode,
  extractSignedData,
  generateKeyPair,
  getPublicKey,
  verifyLevel1Signature,
  verifyLevel2Signature,
  CURVES,
} from '../src';
import type { UicBarcodeTicketInput, SigningKeyPair, IntercodeDynamicData } from '../src';

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
  const l1 = ticket.level2SignedData.level1Data;
  const ds = l1.dataSequence[0];
  const fcbMatch = ds.dataFormat.match(/^FCB(\d+)$/);
  const fcbVersion = fcbMatch ? parseInt(fcbMatch[1], 10) : 2;
  const rt = ds.decoded!;

  const input: UicBarcodeTicketInput = {
    headerVersion: parseInt(ticket.format.replace('U', ''), 10),
    fcbVersion,
    securityProviderNum: l1.securityProviderNum,
    keyId: l1.keyId,
    endOfValidityYear: l1.endOfValidityYear,
    endOfValidityDay: l1.endOfValidityDay,
    endOfValidityTime: l1.endOfValidityTime,
    validityDuration: l1.validityDuration,
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
              extensionId: rt.issuingDetail.intercodeIssuing.extensionId,
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
        ticketType: doc.ticket.key,
        ticket: doc.ticket.value,
      })),
      controlDetail: rt.controlDetail as Record<string, unknown> | undefined,
    },
  };

  // Add dynamic data if present (FDC1 or Intercode)
  const l2Data = ticket.level2SignedData.level2Data;
  if (l2Data?.decoded) {
    if (l2Data.dataFormat === 'FDC1') {
      input.dynamicContentData = l2Data.decoded as any;
    } else {
      const ricsMatch = l2Data.dataFormat.match(/^_(\d+)\.ID1$/);
      const rics = ricsMatch ? parseInt(ricsMatch[1], 10) : l1.securityProviderNum ?? 0;
      const dynamic = l2Data.decoded as IntercodeDynamicData;
      input.dynamicData = {
        rics,
        dynamicContentDay: dynamic.dynamicContentDay,
        dynamicContentTime: dynamic.dynamicContentTime,
        dynamicContentUTCOffset: dynamic.dynamicContentUTCOffset,
        dynamicContentDuration: dynamic.dynamicContentDuration,
      };
    }
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

describe('decode -> re-encode -> decode round-trip', () => {
  it('Solea ticket round-trips through encode/decode', () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    // Encode with new signatures
    const encoded = signAndEncodeTicket(input, l1Key, l2Key);

    // Decode the re-encoded ticket
    const decoded = decodeTicketFromBytes(encoded);

    expect(decoded.format).toBe('U2');
    const ds = decoded.level2SignedData.level1Data.dataSequence;
    expect(ds).toHaveLength(1);

    const rt = ds[0].decoded!;
    expect(rt.issuingDetail).toBeDefined();
    expect(rt.transportDocument).toBeDefined();
    expect(rt.transportDocument!.length).toBeGreaterThan(0);

    // Verify Intercode 6 data survived
    expect(rt.issuingDetail!.intercodeIssuing).toBeDefined();
    expect(rt.issuingDetail!.intercodeIssuing!.intercodeVersion).toBe(1);

    // Verify FDC1 dynamic content data survived the round-trip
    const l2Data = decoded.level2SignedData.level2Data;
    expect(l2Data).toBeDefined();
    expect(l2Data!.dataFormat).toBe('FDC1');
    expect(l2Data!.decoded).toBeDefined();
  });

  it('CTS ticket round-trips through encode/decode', () => {
    const input = decodedToInput(CTS_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(input, l1Key, l2Key);
    const decoded = decodeTicketFromBytes(encoded);

    expect(decoded.format).toBe('U2');
    expect(decoded.level2SignedData.level1Data.dataSequence).toHaveLength(1);
    expect(decoded.level2SignedData.level1Data.dataSequence[0].decoded!.issuingDetail!.intercodeIssuing).toBeDefined();
  });

  it('Sample ticket round-trips through encode/decode', () => {
    const input = decodedToInput(SAMPLE_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(input, l1Key, l2Key);
    const decoded = decodeTicketFromBytes(encoded);

    expect(decoded.level2SignedData.level1Data.dataSequence).toHaveLength(1);
    const rt = decoded.level2SignedData.level1Data.dataSequence[0].decoded!;
    expect(rt.issuingDetail!.intercodeIssuing).toBeDefined();
    expect(decoded.level2SignedData.level2Data?.decoded).toBeDefined();
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

// ---------------------------------------------------------------------------
// Composable primitives tests
// ---------------------------------------------------------------------------

describe('signPayload', () => {
  it('produces a DER signature for arbitrary data', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const sig = signPayload(data, FIPS_L1_PRIV, 'P-256');

    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig[0]).toBe(0x30); // DER SEQUENCE tag
  });
});

describe('encodeLevel1Data', () => {
  it('produces bytes matching extractSignedData for Solea ticket', () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l1Curve = CURVES['P-256'];

    // Encode level1Data with the new primitive (all fields from input)
    const level1Raw = encodeLevel1Data({
      headerVersion: input.headerVersion,
      fcbVersion: input.fcbVersion,
      securityProviderNum: input.securityProviderNum,
      keyId: input.keyId,
      level1KeyAlg: l1Curve.keyAlgOid,
      level1SigningAlg: l1Curve.sigAlgOid,
      endOfValidityYear: input.endOfValidityYear,
      endOfValidityDay: input.endOfValidityDay,
      endOfValidityTime: input.endOfValidityTime,
      validityDuration: input.validityDuration,
      railTicket: input.railTicket,
    });

    // Encode via old path and extract level1DataBytes for comparison
    const l1Sig = signLevel1(
      { ...input, level1KeyAlg: l1Curve.keyAlgOid, level1SigningAlg: l1Curve.sigAlgOid },
      l1Key.privateKey,
      'P-256',
    );
    const fullBytes = encodeTicketToBytes({
      ...input,
      level1KeyAlg: l1Curve.keyAlgOid,
      level1SigningAlg: l1Curve.sigAlgOid,
      level1Signature: l1Sig,
      level2Signature: new Uint8Array(0),
    });
    const extracted = extractSignedData(fullBytes);

    expect(level1Raw.data).toEqual(extracted.level1DataBytes);
  });

  it('produces bytes matching extractSignedData for CTS ticket', () => {
    const input = decodedToInput(CTS_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l1Curve = CURVES['P-256'];

    const level1Raw = encodeLevel1Data({
      headerVersion: input.headerVersion,
      fcbVersion: input.fcbVersion,
      securityProviderNum: input.securityProviderNum,
      keyId: input.keyId,
      level1KeyAlg: l1Curve.keyAlgOid,
      level1SigningAlg: l1Curve.sigAlgOid,
      endOfValidityYear: input.endOfValidityYear,
      endOfValidityDay: input.endOfValidityDay,
      endOfValidityTime: input.endOfValidityTime,
      validityDuration: input.validityDuration,
      railTicket: input.railTicket,
    });

    const l1Sig = signLevel1(
      { ...input, level1KeyAlg: l1Curve.keyAlgOid, level1SigningAlg: l1Curve.sigAlgOid },
      l1Key.privateKey,
      'P-256',
    );
    const fullBytes = encodeTicketToBytes({
      ...input,
      level1KeyAlg: l1Curve.keyAlgOid,
      level1SigningAlg: l1Curve.sigAlgOid,
      level1Signature: l1Sig,
      level2Signature: new Uint8Array(0),
    });
    const extracted = extractSignedData(fullBytes);

    expect(level1Raw.data).toEqual(extracted.level1DataBytes);
  });
});

describe('composable flow end-to-end', () => {
  it('produces a ticket with verifiable L1 and L2 signatures', async () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    // Remove dynamic content so we use the new path
    delete (input as any).dynamicData;
    delete (input as any).dynamicContentData;

    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');
    const l1Curve = CURVES['P-256'];
    const l2Curve = CURVES['P-256'];

    // Step 1: Encode level1Data
    const level1Raw = encodeLevel1Data({
      headerVersion: input.headerVersion,
      fcbVersion: input.fcbVersion,
      securityProviderNum: input.securityProviderNum,
      keyId: input.keyId,
      level1KeyAlg: l1Curve.keyAlgOid,
      level2KeyAlg: l2Curve.keyAlgOid,
      level1SigningAlg: l1Curve.sigAlgOid,
      level2SigningAlg: l2Curve.sigAlgOid,
      level2PublicKey: l2Key.publicKey,
      railTicket: input.railTicket,
    });

    // Step 2: Sign level1Data
    const level1Sig = signPayload(level1Raw.data, l1Key.privateKey, 'P-256');

    // Step 3: Encode level2SignedData
    const level2Raw = encodeLevel2SignedData({
      headerVersion: input.headerVersion,
      level1Data: level1Raw,
      level1Signature: level1Sig,
    });

    // Step 4: Sign level2SignedData
    const level2Sig = signPayload(level2Raw.data, l2Key.privateKey, 'P-256');

    // Step 5: Encode final barcode
    const barcode = encodeUicBarcode({
      format: `U${input.headerVersion ?? 2}`,
      level2SignedData: level2Raw,
      level2Signature: level2Sig,
    });

    // Verify the result decodes correctly
    const decoded = decodeTicketFromBytes(barcode);
    expect(decoded.format).toBe('U2');
    expect(decoded.level2SignedData.level1Data.dataSequence).toHaveLength(1);

    // Verify signatures
    const l1Result = await verifyLevel1Signature(barcode, l1Key.publicKey);
    expect(l1Result.valid).toBe(true);

    const l2Result = await verifyLevel2Signature(barcode);
    expect(l2Result.valid).toBe(true);
  });

  it('produces a ticket with FDC1 dynamic content and verifiable signatures', async () => {
    const input = decodedToInput(SOLEA_TICKET_HEX);
    // Solea ticket has FDC1 dynamic content
    expect(input.dynamicContentData).toBeDefined();

    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');
    const l1Curve = CURVES['P-256'];
    const l2Curve = CURVES['P-256'];

    // Step 1: Encode level1Data
    const level1Raw = encodeLevel1Data({
      headerVersion: input.headerVersion,
      fcbVersion: input.fcbVersion,
      securityProviderNum: input.securityProviderNum,
      keyId: input.keyId,
      level1KeyAlg: l1Curve.keyAlgOid,
      level2KeyAlg: l2Curve.keyAlgOid,
      level1SigningAlg: l1Curve.sigAlgOid,
      level2SigningAlg: l2Curve.sigAlgOid,
      level2PublicKey: l2Key.publicKey,
      railTicket: input.railTicket,
    });

    // Step 2: Sign level1Data
    const level1Sig = signPayload(level1Raw.data, l1Key.privateKey, 'P-256');

    // Step 3: Encode level2Data (FDC1)
    const level2Data = encodeLevel2Data(input.dynamicContentData!);
    expect(level2Data.dataFormat).toBe('FDC1');

    // Step 4: Encode level2SignedData with level2Data
    const level2Raw = encodeLevel2SignedData({
      headerVersion: input.headerVersion,
      level1Data: level1Raw,
      level1Signature: level1Sig,
      level2Data,
    });

    // Step 5: Sign level2SignedData
    const level2Sig = signPayload(level2Raw.data, l2Key.privateKey, 'P-256');

    // Step 6: Encode final barcode
    const barcode = encodeUicBarcode({
      format: `U${input.headerVersion ?? 2}`,
      level2SignedData: level2Raw,
      level2Signature: level2Sig,
    });

    // Verify the result decodes correctly with FDC1 data
    const decoded = decodeTicketFromBytes(barcode);
    expect(decoded.format).toBe('U2');
    expect(decoded.level2SignedData.level2Data).toBeDefined();
    expect(decoded.level2SignedData.level2Data!.dataFormat).toBe('FDC1');
    expect(decoded.level2SignedData.level2Data!.decoded).toBeDefined();

    // Verify signatures
    const l1Result = await verifyLevel1Signature(barcode, l1Key.publicKey);
    expect(l1Result.valid).toBe(true);

    const l2Result = await verifyLevel2Signature(barcode);
    expect(l2Result.valid).toBe(true);
  });

  it('produces a static barcode with verifiable L1 signature', async () => {
    const input = decodedToInput(CTS_TICKET_HEX);
    delete (input as any).dynamicData;
    delete (input as any).dynamicContentData;

    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l1Curve = CURVES['P-256'];

    const level1Raw = encodeLevel1Data({
      headerVersion: input.headerVersion,
      fcbVersion: input.fcbVersion,
      securityProviderNum: input.securityProviderNum,
      keyId: input.keyId,
      level1KeyAlg: l1Curve.keyAlgOid,
      level1SigningAlg: l1Curve.sigAlgOid,
      railTicket: input.railTicket,
    });

    const level1Sig = signPayload(level1Raw.data, l1Key.privateKey, 'P-256');

    const level2Raw = encodeLevel2SignedData({
      headerVersion: input.headerVersion,
      level1Data: level1Raw,
      level1Signature: level1Sig,
    });

    const barcode = encodeUicBarcode({
      format: `U${input.headerVersion ?? 2}`,
      level2SignedData: level2Raw,
    });

    const decoded = decodeTicketFromBytes(barcode);
    expect(decoded.format).toBe('U2');

    const l1Result = await verifyLevel1Signature(barcode, l1Key.publicKey);
    expect(l1Result.valid).toBe(true);
  });
});
