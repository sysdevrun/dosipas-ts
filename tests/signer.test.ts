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
import type { UicBarcodeTicket, SigningKeyPair } from '../src';

/** NIST FIPS 186-4 ECDSA P-256 test vector private keys. */
const FIPS_L1_PRIV = hexToBytes('c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357');
const FIPS_L2_PRIV = hexToBytes('710735c8388f48c684a97bd66751cc5f5a122d6b9a96a2dbe73662f78217446d');

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
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
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const sig = signLevel1(ticket, FIPS_L1_PRIV, 'P-256');

    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBeGreaterThan(0);
    // DER signature starts with SEQUENCE tag
    expect(sig[0]).toBe(0x30);
  });
});

describe('signLevel2', () => {
  it('requires level1Signature to be set', () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    // Clear level1Signature
    const noSig: UicBarcodeTicket = {
      ...ticket,
      level2SignedData: { ...ticket.level2SignedData, level1Signature: undefined },
    };
    expect(() => signLevel2(noSig, FIPS_L2_PRIV, 'P-256')).toThrow(
      'Level 1 signature must be set',
    );
  });

  it('produces a DER signature when L1 is set', () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const l1Sig = signLevel1(ticket, FIPS_L1_PRIV, 'P-256');

    const ticketWithL1: UicBarcodeTicket = {
      ...ticket,
      level2SignedData: { ...ticket.level2SignedData, level1Signature: l1Sig },
    };
    const l2Sig = signLevel2(ticketWithL1, FIPS_L2_PRIV, 'P-256');

    expect(l2Sig).toBeInstanceOf(Uint8Array);
    expect(l2Sig[0]).toBe(0x30);
  });
});

describe('signAndEncodeTicket', () => {
  it('encodes a signed ticket from Solea data', () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const bytes = signAndEncodeTicket(ticket, l1Key, l2Key);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBeGreaterThan(100);
  });

  it('works without Level 2 key (static barcode)', () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    // Remove level2Data for static mode
    const staticTicket: UicBarcodeTicket = {
      ...ticket,
      level2SignedData: { ...ticket.level2SignedData, level2Data: undefined },
    };
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');

    const bytes = signAndEncodeTicket(staticTicket, l1Key);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBeGreaterThan(100);
  });
});

describe('decode -> re-encode -> decode round-trip', () => {
  it('Solea ticket round-trips through encode/decode', () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    // Encode with new signatures
    const encoded = signAndEncodeTicket(ticket, l1Key, l2Key);

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
    const ticket = decodeTicket(CTS_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(ticket, l1Key, l2Key);
    const decoded = decodeTicketFromBytes(encoded);

    expect(decoded.format).toBe('U2');
    expect(decoded.level2SignedData.level1Data.dataSequence).toHaveLength(1);
    expect(decoded.level2SignedData.level1Data.dataSequence[0].decoded!.issuingDetail!.intercodeIssuing).toBeDefined();
  });

  it('Sample ticket round-trips through encode/decode', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(ticket, l1Key, l2Key);
    const decoded = decodeTicketFromBytes(encoded);

    expect(decoded.level2SignedData.level1Data.dataSequence).toHaveLength(1);
    const rt = decoded.level2SignedData.level1Data.dataSequence[0].decoded!;
    expect(rt.issuingDetail!.intercodeIssuing).toBeDefined();
    expect(decoded.level2SignedData.level2Data?.decoded).toBeDefined();
  });
});

describe('signature verification on re-encoded tickets', () => {
  it('Level 1 signature verifies on re-encoded Solea ticket', async () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(ticket, l1Key, l2Key);
    const result = await verifyLevel1Signature(encoded, l1Key.publicKey);

    expect(result.valid).toBe(true);
    expect(result.algorithm).toContain('ECDSA');
  });

  it('Level 2 signature verifies on re-encoded Solea ticket', async () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(ticket, l1Key, l2Key);
    const result = await verifyLevel2Signature(encoded);

    expect(result.valid).toBe(true);
    expect(result.algorithm).toContain('ECDSA');
  });

  it('both levels verify on re-encoded CTS ticket', async () => {
    const ticket = decodeTicket(CTS_TICKET_HEX);
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(ticket, l1Key, l2Key);

    const l1Result = await verifyLevel1Signature(encoded, l1Key.publicKey);
    const l2Result = await verifyLevel2Signature(encoded);

    expect(l1Result.valid).toBe(true);
    expect(l2Result.valid).toBe(true);
  });

  it('Level 1 only (static) verifies on re-encoded ticket', async () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const staticTicket: UicBarcodeTicket = {
      ...ticket,
      level2SignedData: { ...ticket.level2SignedData, level2Data: undefined },
    };
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');

    const encoded = signAndEncodeTicket(staticTicket, l1Key);
    const result = await verifyLevel1Signature(encoded, l1Key.publicKey);

    expect(result.valid).toBe(true);
  });

  it('P-384 signatures verify on re-encoded ticket', async () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const l1Key = generateKeyPair('P-384');
    const l2Key = generateKeyPair('P-384');

    const encoded = signAndEncodeTicket(ticket, l1Key, l2Key);

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
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const l1 = ticket.level2SignedData.level1Data;
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l1Curve = CURVES['P-256'];

    // Encode level1Data with the new primitive
    const level1Raw = encodeLevel1Data(
      { ...l1, level1KeyAlg: l1Curve.keyAlgOid, level1SigningAlg: l1Curve.sigAlgOid },
      ticket.format,
    );

    // Encode via old path and extract level1DataBytes for comparison
    const withOids: UicBarcodeTicket = {
      ...ticket,
      level2SignedData: {
        ...ticket.level2SignedData,
        level1Data: { ...l1, level1KeyAlg: l1Curve.keyAlgOid, level1SigningAlg: l1Curve.sigAlgOid },
      },
    };
    const l1Sig = signLevel1(withOids, l1Key.privateKey, 'P-256');
    const fullBytes = encodeTicketToBytes({
      ...withOids,
      level2SignedData: { ...withOids.level2SignedData, level1Signature: l1Sig },
      level2Signature: new Uint8Array(0),
    });
    const extracted = extractSignedData(fullBytes);

    expect(level1Raw.data).toEqual(extracted.level1DataBytes);
  });

  it('produces bytes matching extractSignedData for CTS ticket', () => {
    const ticket = decodeTicket(CTS_TICKET_HEX);
    const l1 = ticket.level2SignedData.level1Data;
    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l1Curve = CURVES['P-256'];

    const level1Raw = encodeLevel1Data(
      { ...l1, level1KeyAlg: l1Curve.keyAlgOid, level1SigningAlg: l1Curve.sigAlgOid },
      ticket.format,
    );

    const withOids: UicBarcodeTicket = {
      ...ticket,
      level2SignedData: {
        ...ticket.level2SignedData,
        level1Data: { ...l1, level1KeyAlg: l1Curve.keyAlgOid, level1SigningAlg: l1Curve.sigAlgOid },
      },
    };
    const l1Sig = signLevel1(withOids, l1Key.privateKey, 'P-256');
    const fullBytes = encodeTicketToBytes({
      ...withOids,
      level2SignedData: { ...withOids.level2SignedData, level1Signature: l1Sig },
      level2Signature: new Uint8Array(0),
    });
    const extracted = extractSignedData(fullBytes);

    expect(level1Raw.data).toEqual(extracted.level1DataBytes);
  });
});

describe('composable flow end-to-end', () => {
  it('produces a ticket with verifiable L1 and L2 signatures', async () => {
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    // Remove level2Data so we use the new path
    const l1 = ticket.level2SignedData.level1Data;

    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');
    const l1Curve = CURVES['P-256'];
    const l2Curve = CURVES['P-256'];

    // Step 1: Encode level1Data
    const level1Raw = encodeLevel1Data(
      {
        ...l1,
        level1KeyAlg: l1Curve.keyAlgOid,
        level2KeyAlg: l2Curve.keyAlgOid,
        level1SigningAlg: l1Curve.sigAlgOid,
        level2SigningAlg: l2Curve.sigAlgOid,
        level2PublicKey: l2Key.publicKey,
      },
      ticket.format,
    );

    // Step 2: Sign level1Data
    const level1Sig = signPayload(level1Raw.data, l1Key.privateKey, 'P-256');

    // Step 3: Encode level2SignedData
    const headerVersion = parseInt(ticket.format.replace('U', ''), 10);
    const level2Raw = encodeLevel2SignedData({
      headerVersion,
      level1Data: level1Raw,
      level1Signature: level1Sig,
    });

    // Step 4: Sign level2SignedData
    const level2Sig = signPayload(level2Raw.data, l2Key.privateKey, 'P-256');

    // Step 5: Encode final barcode
    const barcode = encodeUicBarcode({
      format: ticket.format,
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
    const ticket = decodeTicket(SOLEA_TICKET_HEX);
    const l1 = ticket.level2SignedData.level1Data;
    const l2 = ticket.level2SignedData.level2Data;
    // Solea ticket has FDC1 dynamic content
    expect(l2).toBeDefined();
    expect(l2!.dataFormat).toBe('FDC1');

    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l2Key = makeKeyPair(FIPS_L2_PRIV, 'P-256');
    const l1Curve = CURVES['P-256'];
    const l2Curve = CURVES['P-256'];

    // Step 1: Encode level1Data
    const level1Raw = encodeLevel1Data(
      {
        ...l1,
        level1KeyAlg: l1Curve.keyAlgOid,
        level2KeyAlg: l2Curve.keyAlgOid,
        level1SigningAlg: l1Curve.sigAlgOid,
        level2SigningAlg: l2Curve.sigAlgOid,
        level2PublicKey: l2Key.publicKey,
      },
      ticket.format,
    );

    // Step 2: Sign level1Data
    const level1Sig = signPayload(level1Raw.data, l1Key.privateKey, 'P-256');

    // Step 3: Encode level2Data (FDC1)
    const level2Data = encodeLevel2Data(l2!, ticket.format);

    // Step 4: Encode level2SignedData with level2Data
    const headerVersion = parseInt(ticket.format.replace('U', ''), 10);
    const level2Raw = encodeLevel2SignedData({
      headerVersion,
      level1Data: level1Raw,
      level1Signature: level1Sig,
      level2Data,
    });

    // Step 5: Sign level2SignedData
    const level2Sig = signPayload(level2Raw.data, l2Key.privateKey, 'P-256');

    // Step 6: Encode final barcode
    const barcode = encodeUicBarcode({
      format: ticket.format,
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
    const ticket = decodeTicket(CTS_TICKET_HEX);
    const l1 = ticket.level2SignedData.level1Data;

    const l1Key = makeKeyPair(FIPS_L1_PRIV, 'P-256');
    const l1Curve = CURVES['P-256'];

    const level1Raw = encodeLevel1Data(
      { ...l1, level1KeyAlg: l1Curve.keyAlgOid, level1SigningAlg: l1Curve.sigAlgOid },
      ticket.format,
    );

    const level1Sig = signPayload(level1Raw.data, l1Key.privateKey, 'P-256');

    const headerVersion = parseInt(ticket.format.replace('U', ''), 10);
    const level2Raw = encodeLevel2SignedData({
      headerVersion,
      level1Data: level1Raw,
      level1Signature: level1Sig,
    });

    const barcode = encodeUicBarcode({
      format: ticket.format,
      level2SignedData: level2Raw,
    });

    const decoded = decodeTicketFromBytes(barcode);
    expect(decoded.format).toBe('U2');

    const l1Result = await verifyLevel1Signature(barcode, l1Key.publicKey);
    expect(l1Result.valid).toBe(true);
  });
});
