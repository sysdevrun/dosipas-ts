/**
 * OID-to-algorithm mapping for UIC barcode signature verification.
 *
 * Maps ASN.1 Object Identifiers to their corresponding signing/key algorithms
 * as specified in the UIC barcode standard.
 *
 * `SIGNING_ALGORITHMS` and `KEY_ALGORITHMS` below are the definitive list of
 * OIDs this library understands, and therefore the accepted values for the
 * `keyAlg` / `signingAlg` fields on `Level1KeyMaterial` and `Level2Algorithms`.
 */
import type { AlgorithmSource } from './types.js';

export interface SigningAlgorithm {
  hash: string;
  type: 'ECDSA' | 'DSA' | 'RSA';
}

export interface KeyAlgorithm {
  type: 'EC' | 'RSA';
  curve?: string;
}

/** OID → signing algorithm (hash + type). */
export const SIGNING_ALGORITHMS: Record<string, SigningAlgorithm> = {
  '1.2.840.10045.4.3.2': { hash: 'SHA-256', type: 'ECDSA' },
  '1.2.840.10045.4.3.3': { hash: 'SHA-384', type: 'ECDSA' },
  '1.2.840.10045.4.3.4': { hash: 'SHA-512', type: 'ECDSA' },
  '2.16.840.1.101.3.4.3.1': { hash: 'SHA-224', type: 'DSA' },
  '2.16.840.1.101.3.4.3.2': { hash: 'SHA-256', type: 'DSA' },
  '1.2.840.113549.1.1.11': { hash: 'SHA-256', type: 'RSA' },
};

/** OID → key algorithm (type + optional curve name). */
export const KEY_ALGORITHMS: Record<string, KeyAlgorithm> = {
  '1.2.840.10045.3.1.7': { curve: 'P-256', type: 'EC' },
  '1.3.132.0.34': { curve: 'P-384', type: 'EC' },
  '1.3.132.0.35': { curve: 'P-521', type: 'EC' },
  '1.2.840.113549.1.1.1': { type: 'RSA' },
};

/** Get signing algorithm details for an OID, or undefined if unknown. */
export function getSigningAlgorithm(oid: string): SigningAlgorithm | undefined {
  return SIGNING_ALGORITHMS[oid];
}

/** Get key algorithm details for an OID, or undefined if unknown. */
export function getKeyAlgorithm(oid: string): KeyAlgorithm | undefined {
  return KEY_ALGORITHMS[oid];
}

/**
 * Get the component byte length for a given curve name.
 * Used for DER-to-raw signature conversion.
 */
export function curveComponentLength(curve: string): number {
  switch (curve) {
    case 'P-256': return 32;
    case 'P-384': return 48;
    case 'P-521': return 66;
    default: throw new Error(`Unknown curve: ${curve}`);
  }
}

// ---------------------------------------------------------------------------
// Algorithm resolution
// ---------------------------------------------------------------------------

/** Successful resolution of the algorithms for one signature level. */
export interface ResolvedAlgorithms {
  ok: true;
  /** Resolved signing algorithm OID. */
  signingOid: string;
  signing: SigningAlgorithm;
  /** Resolved key algorithm OID, when one was available. */
  keyOid?: string;
  key?: KeyAlgorithm;
  /** Named curve. Guaranteed present when `signing.type === 'ECDSA'`. */
  curve?: string;
  /** e.g. 'ECDSA P-256 with SHA-256' or 'DSA with SHA-224'. */
  description: string;
  source: AlgorithmSource;
}

/** Either a successful resolution or an explanatory failure. */
export type AlgorithmResolution = ResolvedAlgorithms | { ok: false; error: string };

/** Inputs to {@link resolveAlgorithms} for one signature level. */
export interface ResolveAlgorithmsInput {
  /** 1 or 2 — used only to build error messages. */
  level: 1 | 2;
  /** OID from the barcode header (`levelNSigningAlg`), if present. */
  barcodeSigningAlg?: string;
  /** OID from the barcode header (`levelNKeyAlg`), if present. */
  barcodeKeyAlg?: string;
  /** OID supplied by the caller. */
  configuredSigningAlg?: string;
  /** OID supplied by the caller. */
  configuredKeyAlg?: string;
}

/** Matches a dotted-decimal object identifier, e.g. `1.2.840.10045.4.3.2`. */
const OID_PATTERN = /^\d+(?:\.\d+)+$/;

/** `'1.2.840.10045.4.3.2' (ECDSA with SHA-256)` — or just the OID if unknown. */
function describeOid(what: 'signing' | 'key', oid: string): string {
  if (what === 'signing') {
    const alg = getSigningAlgorithm(oid);
    return alg ? `'${oid}' (${alg.type} with ${alg.hash})` : `'${oid}'`;
  }
  const alg = getKeyAlgorithm(oid);
  return alg ? `'${oid}' (${alg.curve ?? alg.type})` : `'${oid}'`;
}

/**
 * Choose between the barcode's OID and a configured one for a single field.
 *
 * A disagreement is an error rather than a silent preference: the barcode's
 * OIDs live inside the signed data, so if they contradict what the operator
 * configured out of band, one of the two is wrong and the caller should know.
 */
function pickOid(
  level: 1 | 2,
  what: 'signing' | 'key',
  barcode: string | undefined,
  configured: string | undefined,
): { oid?: string; source?: AlgorithmSource; error?: string } {
  const field = `level${level}${what === 'signing' ? 'SigningAlg' : 'KeyAlg'}`;
  const table = what === 'signing' ? 'SIGNING_ALGORITHMS' : 'KEY_ALGORITHMS';
  const example = what === 'signing' ? '1.2.840.10045.4.3.2' : '1.2.840.10045.3.1.7';

  if (configured !== undefined && !OID_PATTERN.test(configured)) {
    return {
      error:
        `Invalid configured level ${level} ${what} algorithm: '${configured}'. ` +
        `Expected a dotted-decimal OID such as '${example}' — ` +
        `see ${table} in src/oids.ts for the accepted values.`,
    };
  }

  if (barcode !== undefined && configured !== undefined && barcode !== configured) {
    return {
      error:
        `Level ${level} ${what} algorithm mismatch: the barcode declares ` +
        `${describeOid(what, barcode)} in ${field}, but ` +
        `${describeOid(what, configured)} was configured. ` +
        `Remove the override, or fix it to match the barcode.`,
    };
  }

  if (barcode !== undefined) return { oid: barcode, source: 'barcode' };
  if (configured !== undefined) return { oid: configured, source: 'configured' };
  return {};
}

/**
 * Resolve the signing and key algorithms for one signature level.
 *
 * Precedence, applied to each field independently:
 *   1. the OID carried in the barcode
 *   2. the OID supplied by the caller
 *   3. failure, with an explanatory message
 *
 * When both are present and differ, resolution fails. Nothing is inferred
 * from key material. Never throws.
 */
export function resolveAlgorithms(input: ResolveAlgorithmsInput): AlgorithmResolution {
  const { level } = input;

  // --- signing algorithm ---------------------------------------------------
  const sig = pickOid(level, 'signing', input.barcodeSigningAlg, input.configuredSigningAlg);
  if (sig.error) return { ok: false, error: sig.error };
  if (!sig.oid) {
    return {
      ok: false,
      error:
        `Missing level ${level} signing algorithm: the barcode has no ` +
        `level${level}SigningAlg OID and no signingAlg was configured.`,
    };
  }
  const signing = getSigningAlgorithm(sig.oid);
  if (!signing) {
    return { ok: false, error: `Unsupported signing algorithm: ${sig.oid}` };
  }

  // --- key algorithm -------------------------------------------------------
  const keySel = pickOid(level, 'key', input.barcodeKeyAlg, input.configuredKeyAlg);
  if (keySel.error) return { ok: false, error: keySel.error };

  let key: KeyAlgorithm | undefined;
  if (keySel.oid) {
    key = getKeyAlgorithm(keySel.oid);
    if (!key) {
      return { ok: false, error: `Cannot determine curve from key algorithm: ${keySel.oid}` };
    }
  }
  const curve = key?.curve;

  if (signing.type === 'ECDSA' && !curve) {
    return {
      ok: false,
      error: keySel.oid
        ? `Cannot determine curve from key algorithm: ${keySel.oid}`
        : `Missing level ${level} key algorithm: the barcode has no ` +
          `level${level}KeyAlg OID and no keyAlg was configured. ` +
          `ECDSA verification needs it to identify the curve.`,
    };
  }

  const sources = [sig.source, keySel.source].filter(Boolean) as AlgorithmSource[];
  const source: AlgorithmSource = sources.every(s => s === sources[0]) ? sources[0] : 'mixed';

  return {
    ok: true,
    signingOid: sig.oid,
    signing,
    keyOid: keySel.oid,
    key,
    curve,
    description: curve
      ? `${signing.type} ${curve} with ${signing.hash}`
      : `${signing.type} with ${signing.hash}`,
    source,
  };
}
