import {
  verifyLevel2Signature,
  verifyLevel1Signature,
  verifySignatures,
  extractSignedData,
  decodeTicket,
  findKeyInXml,
  parseKeysXml,
  SNCF_TER_TICKET_HEX,
  SOLEA_TICKET_HEX,
  CTS_TICKET_HEX,
  SNCF_TER_SIGNATURES,
  SOLEA_SIGNATURES,
  CTS_SIGNATURES,
} from '../src';
import { derToRaw, extractEcPublicKeyPoint } from '../src/signature-utils';
import { getSigningAlgorithm, getKeyAlgorithm, curveComponentLength } from '../src/oids';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  return new Uint8Array(clean.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// OID mapping tests
// ---------------------------------------------------------------------------

describe('OID mapping', () => {
  it('maps ECDSA with SHA-256 signing algorithm', () => {
    const alg = getSigningAlgorithm('1.2.840.10045.4.3.2');
    expect(alg).toEqual({ hash: 'SHA-256', type: 'ECDSA' });
  });

  it('maps DSA with SHA-224 signing algorithm', () => {
    const alg = getSigningAlgorithm('2.16.840.1.101.3.4.3.1');
    expect(alg).toEqual({ hash: 'SHA-224', type: 'DSA' });
  });

  it('maps P-256 key algorithm', () => {
    const alg = getKeyAlgorithm('1.2.840.10045.3.1.7');
    expect(alg).toEqual({ curve: 'P-256', type: 'EC' });
  });

  it('returns undefined for unknown OID', () => {
    expect(getSigningAlgorithm('1.2.3.4.5')).toBeUndefined();
    expect(getKeyAlgorithm('1.2.3.4.5')).toBeUndefined();
  });

  it('returns correct component lengths', () => {
    expect(curveComponentLength('P-256')).toBe(32);
    expect(curveComponentLength('P-384')).toBe(48);
    expect(curveComponentLength('P-521')).toBe(66);
  });
});

// ---------------------------------------------------------------------------
// DER-to-raw conversion tests
// ---------------------------------------------------------------------------

describe('derToRaw', () => {
  it('converts 71-byte ECDSA P-256 DER signature (one padded integer)', () => {
    const der = hexToBytes(SOLEA_SIGNATURES.level1SignatureHex);
    expect(der.length).toBe(71);

    const raw = derToRaw(der, 32);
    expect(raw.length).toBe(64);

    // r has 0x00 padding which should be stripped
    expect(toHex(raw.slice(0, 32))).toBe(
      'c02fa08b4a288401a053dd250c1f748ae51d16b9aac26eacc09056695f0abe68'
    );
    expect(toHex(raw.slice(32, 64))).toBe(
      '50c1f1b13a5e8e126441f84159e5b3188d505e73354492b8de369441daa7285b'
    );
  });

  it('converts 72-byte ECDSA P-256 DER signature (both padded)', () => {
    const der = hexToBytes(CTS_SIGNATURES.level1SignatureHex);
    expect(der.length).toBe(72);

    const raw = derToRaw(der, 32);
    expect(raw.length).toBe(64);

    expect(toHex(raw.slice(0, 32))).toBe(
      '8974af39d91452785b211f49ec2e36302b2b73ec3b99f5cdba5f1bf5c9e7cb72'
    );
    expect(toHex(raw.slice(32, 64))).toBe(
      'f468337ab677c729a43b601c8df31f0c9c9923be5711ace720943c1f99b2a34b'
    );
  });

  it('converts 46-byte DSA DER signature', () => {
    const der = hexToBytes(SNCF_TER_SIGNATURES.level1SignatureHex);
    expect(der.length).toBe(46);

    const raw = derToRaw(der, 20);
    expect(raw.length).toBe(40);

    expect(toHex(raw.slice(0, 20))).toBe(
      '7a71a4d9abdf2204ae40d6dd2dff4adb30df5e44'
    );
    expect(toHex(raw.slice(20, 40))).toBe(
      '66856f3933964f825f1c825da94a5e3868ffe649'
    );
  });

  it('rejects invalid DER', () => {
    expect(() => derToRaw(new Uint8Array([0x01, 0x02]), 32)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Public key extraction tests
// ---------------------------------------------------------------------------

describe('extractEcPublicKeyPoint', () => {
  it('passes through uncompressed point (65 bytes)', () => {
    const point = new Uint8Array(65);
    point[0] = 0x04;
    const result = extractEcPublicKeyPoint(point);
    expect(result).toBe(point);
  });

  it('passes through compressed point (33 bytes)', () => {
    const point = hexToBytes(
      '028f3d46312f69e918100e8c4ea1d3fb726d118271174fba406dd97e089c44d972'
    );
    expect(point.length).toBe(33);
    const result = extractEcPublicKeyPoint(point);
    expect(result).toBe(point);
  });
});

// ---------------------------------------------------------------------------
// Signed data extraction tests
// ---------------------------------------------------------------------------

describe('extractSignedData', () => {
  it('extracts signed bytes from SNCF TER ticket', () => {
    const bytes = hexToBytes(SNCF_TER_TICKET_HEX);
    const extracted = extractSignedData(bytes);

    expect(extracted.level1DataBytes).toBeInstanceOf(Uint8Array);
    expect(extracted.level1DataBytes.length).toBeGreaterThan(0);
    expect(extracted.level2SignedBytes).toBeInstanceOf(Uint8Array);
    expect(extracted.level2SignedBytes.length).toBeGreaterThan(0);
    expect(extracted.level2SignedBytes.length).toBeGreaterThan(extracted.level1DataBytes.length);
  });

  it('extracts correct security metadata from Soléa ticket', () => {
    const bytes = hexToBytes(SOLEA_TICKET_HEX);
    const extracted = extractSignedData(bytes);
    const ticket = decodeTicket(SOLEA_TICKET_HEX);

    // Verify extraction matches decodeTicket output
    expect(extracted.security.securityProviderNum).toBe(ticket.security.securityProviderNum);
    expect(extracted.security.keyId).toBe(ticket.security.keyId);
    expect(extracted.security.level1SigningAlg).toBe(ticket.security.level1SigningAlg);
    expect(extracted.security.level2SigningAlg).toBe(ticket.security.level2SigningAlg);
    expect(extracted.security.level1KeyAlg).toBe(ticket.security.level1KeyAlg);
    expect(extracted.security.level2KeyAlg).toBe(ticket.security.level2KeyAlg);

    // Also verify specific expected values
    expect(extracted.security.securityProviderNum).toBe(3703);
    expect(extracted.security.keyId).toBe(7);
    expect(extracted.security.level2SigningAlg).toBe('1.2.840.10045.4.3.2');
  });

  it('extracts signatures matching decoded ticket for CTS', () => {
    const bytes = hexToBytes(CTS_TICKET_HEX);
    const extracted = extractSignedData(bytes);
    const ticket = decodeTicket(CTS_TICKET_HEX);

    expect(extracted.security.level1Signature).toBeDefined();
    expect(toHex(extracted.security.level1Signature!)).toBe(
      toHex(ticket.security.level1Signature!)
    );

    expect(extracted.security.level2Signature).toBeDefined();
    expect(toHex(extracted.security.level2Signature!)).toBe(
      toHex(ticket.level2Signature!)
    );
  });
});

// ---------------------------------------------------------------------------
// Level 2 signature verification tests (self-contained)
// ---------------------------------------------------------------------------

describe('verifyLevel2Signature', () => {
  it('verifies Soléa level 2 signature', async () => {
    const bytes = hexToBytes(SOLEA_TICKET_HEX);
    const result = await verifyLevel2Signature(bytes);

    expect(result.algorithm).toContain('ECDSA');
    expect(result.algorithm).toContain('P-256');
    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('verifies CTS level 2 signature', async () => {
    const bytes = hexToBytes(CTS_TICKET_HEX);
    const result = await verifyLevel2Signature(bytes);

    expect(result.valid).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it('SNCF TER has no level 2 signature (v1 header)', async () => {
    const bytes = hexToBytes(SNCF_TER_TICKET_HEX);
    const result = await verifyLevel2Signature(bytes);

    // v1 headers don't have OID fields or level 2 signature
    expect(result.valid).toBe(false);
  });

  it('returns error for tampered data', async () => {
    const bytes = hexToBytes(SOLEA_TICKET_HEX);
    bytes[100] ^= 0xff;
    const result = await verifyLevel2Signature(bytes);

    expect(result.valid).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// XML key parsing tests
// ---------------------------------------------------------------------------

describe('findKeyInXml / parseKeysXml', () => {
  const sampleXml = `<?xml version="1.0"?>
<keys>
  <key>
    <issuerCode>1187</issuerCode>
    <issuerName>SNCF Voyageurs</issuerName>
    <id>1</id>
    <publicKey>MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE</publicKey>
    <signatureAlgorithm>SHA256withECDSA</signatureAlgorithm>
    <versionType>FCB</versionType>
    <barcodeVersion>2</barcodeVersion>
    <startDate>2020-01-01</startDate>
    <endDate>2025-12-31</endDate>
  </key>
  <key>
    <issuerCode>9999</issuerCode>
    <issuerName>Test Company</issuerName>
    <id>2</id>
    <publicKey>AAAA</publicKey>
    <signatureAlgorithm>SHA256withECDSA</signatureAlgorithm>
    <versionType>FCB</versionType>
    <barcodeVersion>2</barcodeVersion>
    <startDate>2020-01-01</startDate>
    <endDate>2025-12-31</endDate>
  </key>
</keys>`;

  it('finds key by issuer code and key ID', () => {
    const key = findKeyInXml(sampleXml, 1187, 1);
    expect(key).not.toBeNull();
    expect(key).toBeInstanceOf(Uint8Array);
  });

  it('returns null for non-matching key', () => {
    const key = findKeyInXml(sampleXml, 1187, 99);
    expect(key).toBeNull();
  });

  it('parses all keys', () => {
    const keys = parseKeysXml(sampleXml);
    expect(keys).toHaveLength(2);
    expect(keys[0].issuerCode).toBe(1187);
    expect(keys[0].issuerName).toBe('SNCF Voyageurs');
    expect(keys[0].id).toBe(1);
    expect(keys[1].issuerCode).toBe(9999);
  });
});

// ---------------------------------------------------------------------------
// Combined verification tests
// ---------------------------------------------------------------------------

describe('verifySignatures', () => {
  it('verifies level 2 without any options', async () => {
    const bytes = hexToBytes(SOLEA_TICKET_HEX);
    const result = await verifySignatures(bytes);

    expect(result.level2.valid).toBe(true);
    expect(result.level1.valid).toBe(false);
    expect(result.level1.error).toContain('No level 1 public key');
  });

  it('verifies both levels with key provider', async () => {
    const bytes = hexToBytes(SOLEA_TICKET_HEX);
    const result = await verifySignatures(bytes, {
      level1KeyProvider: {
        async getPublicKey() {
          return new Uint8Array(65);
        },
      },
    });

    expect(result.level2.valid).toBe(true);
    // Level 1 will fail because the dummy key is invalid
    expect(result.level1.valid).toBe(false);
  });
});
