import { resolveAlgorithms } from '../src/oids';

const ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const ECDSA_SHA384 = '1.2.840.10045.4.3.3';
const P256 = '1.2.840.10045.3.1.7';
const P384 = '1.3.132.0.34';
const DSA_SHA224 = '2.16.840.1.101.3.4.3.1';

describe('resolveAlgorithms — precedence', () => {
  it('uses the barcode OIDs when present', () => {
    const r = resolveAlgorithms({
      level: 1,
      barcodeSigningAlg: ECDSA_SHA256,
      barcodeKeyAlg: P256,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.source).toBe('barcode');
    expect(r.curve).toBe('P-256');
    expect(r.description).toBe('ECDSA P-256 with SHA-256');
  });

  it('falls back to configured OIDs when the barcode omits them', () => {
    const r = resolveAlgorithms({
      level: 1,
      configuredSigningAlg: ECDSA_SHA256,
      configuredKeyAlg: P256,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.source).toBe('configured');
    expect(r.description).toBe('ECDSA P-256 with SHA-256');
  });

  it('reports a mixed source when one field comes from each', () => {
    const r = resolveAlgorithms({
      level: 1,
      barcodeSigningAlg: ECDSA_SHA256,
      configuredKeyAlg: P256,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.source).toBe('mixed');
  });

  it('accepts a configured OID that agrees with the barcode', () => {
    const r = resolveAlgorithms({
      level: 1,
      barcodeSigningAlg: ECDSA_SHA256,
      barcodeKeyAlg: P256,
      configuredSigningAlg: ECDSA_SHA256,
      configuredKeyAlg: P256,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.source).toBe('barcode');
  });
});

describe('resolveAlgorithms — mismatch is a hard error', () => {
  it('rejects a signing algorithm that contradicts the barcode', () => {
    const r = resolveAlgorithms({
      level: 1,
      barcodeSigningAlg: ECDSA_SHA256,
      barcodeKeyAlg: P256,
      configuredSigningAlg: ECDSA_SHA384,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toContain('mismatch');
    expect(r.error).toContain('level1SigningAlg');
    expect(r.error).toContain(ECDSA_SHA256);
    expect(r.error).toContain(ECDSA_SHA384);
  });

  it('rejects a key algorithm that contradicts the barcode', () => {
    const r = resolveAlgorithms({
      level: 2,
      barcodeSigningAlg: ECDSA_SHA256,
      barcodeKeyAlg: P256,
      configuredKeyAlg: P384,
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toContain('mismatch');
    expect(r.error).toContain('level2KeyAlg');
  });
});

describe('resolveAlgorithms — failures', () => {
  // The CLI and the website both branch on `error.includes('Missing')` to
  // render "not present" rather than "invalid", so the prefix is load-bearing.
  it('reports a missing signing algorithm with a "Missing" prefix', () => {
    const r = resolveAlgorithms({ level: 1 });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error.startsWith('Missing')).toBe(true);
    expect(r.error).toContain('level1SigningAlg');
  });

  it('reports a missing key algorithm when ECDSA has no curve anywhere', () => {
    const r = resolveAlgorithms({ level: 1, barcodeSigningAlg: ECDSA_SHA256 });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error.startsWith('Missing')).toBe(true);
    expect(r.error).toContain('level1KeyAlg');
  });

  // Likewise `error.includes('Unsupported')` drives the website's "?" badge.
  it('reports an unknown barcode OID verbatim', () => {
    const r = resolveAlgorithms({ level: 1, barcodeSigningAlg: '1.2.3.4.5' });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toBe('Unsupported signing algorithm: 1.2.3.4.5');
  });

  it('rejects a configured value that is not a dotted-decimal OID', () => {
    const r = resolveAlgorithms({ level: 1, configuredSigningAlg: 'SHA256withECDSA' });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toContain('SHA256withECDSA');
    expect(r.error).toContain('dotted-decimal OID');
    expect(r.error).toContain('SIGNING_ALGORITHMS');
  });

  it('rejects a configured key algorithm that is not an OID', () => {
    const r = resolveAlgorithms({
      level: 1,
      configuredSigningAlg: ECDSA_SHA256,
      configuredKeyAlg: 'P-256',
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toContain('KEY_ALGORITHMS');
  });
});

describe('resolveAlgorithms — non-ECDSA', () => {
  it('resolves DSA without needing a curve', () => {
    const r = resolveAlgorithms({ level: 1, barcodeSigningAlg: DSA_SHA224 });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.curve).toBeUndefined();
    expect(r.description).toBe('DSA with SHA-224');
  });
});
