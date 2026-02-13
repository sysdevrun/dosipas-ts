/**
 * Signature verification for UIC barcode tickets.
 *
 * Supports two-level signature verification:
 * - Level 2: self-contained, uses the embedded `level2PublicKey`
 * - Level 1: requires an external public key (via provider or direct)
 *
 * Uses @noble/curves for ECDSA verification (works in both Node.js and browsers).
 */
import { p256, p384, p521 } from '@noble/curves/nist.js';

import { extractSignedData } from './signed-data';
import { getSigningAlgorithm, getKeyAlgorithm, curveComponentLength } from './oids';
import { derToRaw, extractEcPublicKeyPoint } from './signature-utils';
import type {
  SignatureVerificationResult,
  Level1KeyProvider,
  VerifyOptions,
} from './types';

// ---------------------------------------------------------------------------
// Curve dispatch helpers
// ---------------------------------------------------------------------------

interface CurveOps {
  /** Verify signature against message. @noble/curves handles hashing internally (prehash: true by default). */
  verify: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => boolean;
  componentLength: number;
}

// UIC barcode signatures may have non-normalized (high-S) values, so we
// disable the lowS check that @noble/curves enforces by default.
const VERIFY_OPTS = { lowS: false } as const;

function getCurveOps(curve: string): CurveOps {
  switch (curve) {
    case 'P-256':
      return {
        verify: (sig, msg, pk) => p256.verify(sig, msg, pk, VERIFY_OPTS),
        componentLength: 32,
      };
    case 'P-384':
      return {
        verify: (sig, msg, pk) => p384.verify(sig, msg, pk, VERIFY_OPTS),
        componentLength: 48,
      };
    case 'P-521':
      return {
        verify: (sig, msg, pk) => p521.verify(sig, msg, pk, VERIFY_OPTS),
        componentLength: 66,
      };
    default:
      throw new Error(`Unsupported curve: ${curve}`);
  }
}

// ---------------------------------------------------------------------------
// ECDSA verification
// ---------------------------------------------------------------------------

function verifyEcdsa(
  signatureBytes: Uint8Array,
  signedData: Uint8Array,
  publicKeyBytes: Uint8Array,
  curve: string,
): boolean {
  const curveOps = getCurveOps(curve);

  // Convert DER signature to raw (r || s) compact format
  const rawSig = derToRaw(signatureBytes, curveOps.componentLength);

  // Extract the raw EC point from potentially SPKI-wrapped key
  const rawPoint = extractEcPublicKeyPoint(publicKeyBytes);

  // Verify — @noble/curves hashes the message internally (prehash: true by default)
  return curveOps.verify(rawSig, signedData, rawPoint);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Verify Level 2 signature on a UIC barcode.
 *
 * Level 2 is self-contained: the public key is embedded in the barcode's
 * `level1Data.level2PublicKey` field.
 *
 * @param bytes - Raw barcode payload bytes.
 * @returns Verification result with valid flag and optional error.
 */
export async function verifyLevel2Signature(
  bytes: Uint8Array,
): Promise<{ valid: boolean; error?: string; algorithm?: string }> {
  try {
    const extracted = extractSignedData(bytes);
    const { security } = extracted;

    if (!security.level2Signature) {
      return { valid: false, error: 'Missing level 2 signature' };
    }

    if (!security.level2PublicKey) {
      return { valid: false, error: 'Missing level 2 public key' };
    }

    // Determine algorithms
    const sigAlg = security.level2SigningAlg
      ? getSigningAlgorithm(security.level2SigningAlg)
      : undefined;

    const keyAlg = security.level2KeyAlg
      ? getKeyAlgorithm(security.level2KeyAlg)
      : undefined;

    if (!sigAlg) {
      return {
        valid: false,
        error: security.level2SigningAlg
          ? `Unsupported signing algorithm: ${security.level2SigningAlg}`
          : 'Missing level 2 signing algorithm OID',
      };
    }

    if (sigAlg.type !== 'ECDSA') {
      return { valid: false, error: `Unsupported signing type for level 2: ${sigAlg.type}` };
    }

    const curve = keyAlg?.curve;
    if (!curve) {
      return {
        valid: false,
        error: security.level2KeyAlg
          ? `Cannot determine curve from key algorithm: ${security.level2KeyAlg}`
          : 'Missing level 2 key algorithm OID',
      };
    }

    const algorithmDesc = `${sigAlg.type} ${curve} with ${sigAlg.hash}`;

    const valid = verifyEcdsa(
      security.level2Signature,
      extracted.level2SignedBytes,
      security.level2PublicKey,
      curve,
    );

    return {
      valid,
      algorithm: algorithmDesc,
      ...(!valid && { error: `Level 2 signature verification failed (${algorithmDesc})` }),
    };
  } catch (e: unknown) {
    return { valid: false, error: e instanceof Error ? e.message : 'Verification failed' };
  }
}

/**
 * Verify Level 1 signature on a UIC barcode.
 *
 * Level 1 requires an externally-provided public key since it is not
 * embedded in the barcode.
 *
 * @param bytes - Raw barcode payload bytes.
 * @param publicKey - The Level 1 public key bytes.
 * @returns Verification result with valid flag and optional error.
 */
export async function verifyLevel1Signature(
  bytes: Uint8Array,
  publicKey: Uint8Array,
): Promise<{ valid: boolean; error?: string; algorithm?: string }> {
  try {
    const extracted = extractSignedData(bytes);
    const { security } = extracted;

    if (!security.level1Signature) {
      return { valid: false, error: 'Missing level 1 signature' };
    }

    // Determine algorithms
    const sigAlg = security.level1SigningAlg
      ? getSigningAlgorithm(security.level1SigningAlg)
      : undefined;

    const keyAlg = security.level1KeyAlg
      ? getKeyAlgorithm(security.level1KeyAlg)
      : undefined;

    if (!sigAlg) {
      return {
        valid: false,
        error: security.level1SigningAlg
          ? `Unsupported signing algorithm: ${security.level1SigningAlg}`
          : 'Missing level 1 signing algorithm OID',
      };
    }

    const algorithmDesc = `${sigAlg.type} with ${sigAlg.hash}`;

    if (sigAlg.type === 'ECDSA') {
      const curve = keyAlg?.curve;
      if (!curve) {
        return {
          valid: false,
          error: security.level1KeyAlg
            ? `Cannot determine curve from key algorithm: ${security.level1KeyAlg}`
            : 'Missing level 1 key algorithm OID',
        };
      }

      const l1AlgorithmDesc = `ECDSA ${curve} with ${sigAlg.hash}`;
      const valid = verifyEcdsa(
        security.level1Signature,
        extracted.level1DataBytes,
        publicKey,
        curve,
      );
      return {
        valid,
        algorithm: l1AlgorithmDesc,
        ...(!valid && { error: `Level 1 signature verification failed (${l1AlgorithmDesc})` }),
      };
    }

    if (sigAlg.type === 'DSA') {
      // DSA is not supported by @noble/curves
      // DSA signatures use the same DER format but different crypto primitives
      return {
        valid: false,
        error: `DSA verification not supported (algorithm: DSA with ${sigAlg.hash})`,
        algorithm: algorithmDesc,
      };
    }

    return { valid: false, error: `Unsupported algorithm type: ${sigAlg.type}` };
  } catch (e: unknown) {
    return { valid: false, error: e instanceof Error ? e.message : 'Verification failed' };
  }
}

/**
 * Verify both Level 1 and Level 2 signatures on a UIC barcode.
 *
 * @param bytes - Raw barcode payload bytes.
 * @param options - Verification options (key provider or explicit key).
 * @returns Combined verification results for both levels.
 */
export async function verifySignatures(
  bytes: Uint8Array,
  options?: VerifyOptions,
): Promise<SignatureVerificationResult> {
  // Level 2 verification (self-contained)
  const level2 = await verifyLevel2Signature(bytes);

  // Level 1 verification (needs external key)
  let level1: { valid: boolean; error?: string; algorithm?: string };

  if (options?.level1PublicKey) {
    level1 = await verifyLevel1Signature(bytes, options.level1PublicKey);
  } else if (options?.level1KeyProvider) {
    try {
      const extracted = extractSignedData(bytes);
      const { security } = extracted;
      const pubKey = await options.level1KeyProvider.getPublicKey(
        { num: security.securityProviderNum, ia5: security.securityProviderIA5 },
        security.keyId ?? 0,
        security.level1KeyAlg,
      );
      level1 = await verifyLevel1Signature(bytes, pubKey);
    } catch (e: unknown) {
      level1 = {
        valid: false,
        error: `Key provider error: ${e instanceof Error ? e.message : 'unknown error'}`,
      };
    }
  } else {
    level1 = {
      valid: false,
      error: 'No level 1 public key provided (use level1PublicKey or level1KeyProvider)',
    };
  }

  return { level1, level2 };
}

/**
 * Parse the UIC public key XML and find a key by issuer code and key ID.
 *
 * @param xml - XML string from https://railpublickey.uic.org/download.php
 * @param issuerCode - The issuer RICS code (securityProviderNum)
 * @param keyId - The key identifier
 * @returns The Base64-decoded public key bytes, or null if not found.
 */
export function findKeyInXml(xml: string, issuerCode: number, keyId: number): Uint8Array | null {
  // Simple regex-based XML parser (no DOM dependency for Node.js compatibility)
  const keyRegex = /<key>([\s\S]*?)<\/key>/g;
  let match: RegExpExecArray | null;

  while ((match = keyRegex.exec(xml)) !== null) {
    const block = match[1];

    const issuerMatch = block.match(/<issuerCode>\s*(\d+)\s*<\/issuerCode>/);
    const idMatch = block.match(/<id>\s*(\d+)\s*<\/id>/);
    const pubKeyMatch = block.match(/<publicKey>\s*([A-Za-z0-9+/=\s]+?)\s*<\/publicKey>/);

    if (issuerMatch && idMatch && pubKeyMatch) {
      const xmlIssuerCode = parseInt(issuerMatch[1], 10);
      const xmlKeyId = parseInt(idMatch[1], 10);

      if (xmlIssuerCode === issuerCode && xmlKeyId === keyId) {
        // Base64 decode
        const b64 = pubKeyMatch[1].replace(/\s+/g, '');
        return base64ToBytes(b64);
      }
    }
  }

  return null;
}

/**
 * Parse all keys from the UIC public key XML.
 *
 * @param xml - XML string from https://railpublickey.uic.org/download.php
 * @returns Array of parsed key entries.
 */
export function parseKeysXml(xml: string): UicPublicKeyEntry[] {
  const entries: UicPublicKeyEntry[] = [];
  const keyRegex = /<key>([\s\S]*?)<\/key>/g;
  let match: RegExpExecArray | null;

  while ((match = keyRegex.exec(xml)) !== null) {
    const block = match[1];

    const issuerCode = extractXmlInt(block, 'issuerCode');
    const id = extractXmlInt(block, 'id');
    const issuerName = extractXmlText(block, 'issuerName');
    const publicKeyB64 = extractXmlText(block, 'publicKey');
    const signatureAlgorithm = extractXmlText(block, 'signatureAlgorithm');
    const versionType = extractXmlText(block, 'versionType');
    const barcodeVersion = extractXmlText(block, 'barcodeVersion');
    const startDate = extractXmlText(block, 'startDate');
    const endDate = extractXmlText(block, 'endDate');

    if (issuerCode != null && id != null && publicKeyB64) {
      entries.push({
        issuerCode,
        id,
        issuerName: issuerName ?? '',
        publicKey: base64ToBytes(publicKeyB64.replace(/\s+/g, '')),
        publicKeyB64: publicKeyB64.replace(/\s+/g, ''),
        signatureAlgorithm: signatureAlgorithm ?? '',
        versionType: versionType ?? '',
        barcodeVersion: barcodeVersion ?? '',
        startDate: startDate ?? '',
        endDate: endDate ?? '',
      });
    }
  }

  return entries;
}

export interface UicPublicKeyEntry {
  issuerCode: number;
  id: number;
  issuerName: string;
  publicKey: Uint8Array;
  publicKeyB64: string;
  signatureAlgorithm: string;
  versionType: string;
  barcodeVersion: string;
  startDate: string;
  endDate: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractXmlText(block: string, tag: string): string | null {
  const re = new RegExp(`<${tag}>\\s*([\\s\\S]*?)\\s*</${tag}>`);
  const m = block.match(re);
  return m ? m[1].trim() : null;
}

function extractXmlInt(block: string, tag: string): number | null {
  const text = extractXmlText(block, tag);
  if (text === null) return null;
  const n = parseInt(text, 10);
  return isNaN(n) ? null : n;
}

function base64ToBytes(b64: string): Uint8Array {
  // Works in both Node.js and browsers
  if (typeof atob === 'function') {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  // Node.js fallback
  return new Uint8Array(Buffer.from(b64, 'base64'));
}
