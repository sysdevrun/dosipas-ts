/**
 * OID-to-algorithm mapping for UIC barcode signature verification.
 *
 * Maps ASN.1 Object Identifiers to their corresponding signing/key algorithms
 * as specified in the UIC barcode standard.
 */

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
