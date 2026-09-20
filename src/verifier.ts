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

import { toExtractedTicket } from './signed-data.js';
import type { ExtractedTicket, SignatureKey } from './signed-data.js';
import { curveComponentLength, resolveAlgorithms } from './oids.js';
import type { ResolvedAlgorithms } from './oids.js';
import { derToRaw, extractEcPublicKeyPoint } from './signature-utils.js';
import type {
  SignatureVerificationResult,
  SignatureLevelResult,
  Level1KeyProvider,
  Level1KeyMaterial,
  Level2Algorithms,
  VerifyOptions,
} from './types.js';

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
        componentLength: curveComponentLength(curve),
      };
    case 'P-384':
      return {
        verify: (sig, msg, pk) => p384.verify(sig, msg, pk, VERIFY_OPTS),
        componentLength: curveComponentLength(curve),
      };
    case 'P-521':
      return {
        verify: (sig, msg, pk) => p521.verify(sig, msg, pk, VERIFY_OPTS),
        componentLength: curveComponentLength(curve),
      };
    default:
      throw new Error(`Unsupported curve: ${curve}`);
  }
}

/**
 * Run ECDSA verification and shape the result for one level.
 *
 * A configured algorithm that does not match the key makes @noble/curves throw
 * from deep inside `verifyEcdsa` (e.g. a P-384 curve against a 65-byte P-256
 * point). Catching here keeps the algorithm in the message, since with
 * configurable algorithms the caller's override is a likely culprit.
 */
function verifyEcdsaResult(
  level: 1 | 2,
  signature: Uint8Array,
  signedData: Uint8Array,
  publicKey: Uint8Array,
  resolved: ResolvedAlgorithms,
): SignatureLevelResult {
  const { description, source, curve } = resolved;
  try {
    const valid = verifyEcdsa(signature, signedData, publicKey, curve!);
    return {
      valid,
      algorithm: description,
      algorithmSource: source,
      ...(!valid && { error: `Level ${level} signature verification failed (${description})` }),
    };
  } catch (e: unknown) {
    return {
      valid: false,
      algorithm: description,
      algorithmSource: source,
      error:
        `Level ${level} signature verification error (${description}): ` +
        `${e instanceof Error ? e.message : 'unknown error'}`,
    };
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
 * `level1Data.level2PublicKey` field. Its algorithm OIDs can still be absent,
 * in which case they may be supplied via `algorithms`.
 *
 * @param input - Raw barcode payload bytes, or an already-extracted ticket.
 * @param algorithms - Algorithm OIDs to use when the barcode omits its own.
 * @returns Verification result with valid flag and optional error.
 */
export async function verifyLevel2Signature(
  input: Uint8Array | ExtractedTicket,
  algorithms?: Level2Algorithms,
): Promise<SignatureLevelResult> {
  try {
    const { level2 } = toExtractedTicket(input);

    if (!level2.signature) {
      return { valid: false, error: 'Missing level 2 signature' };
    }

    if (!level2.publicKey) {
      return { valid: false, error: 'Missing level 2 public key' };
    }

    const resolved = resolveAlgorithms({
      level: 2,
      barcodeSigningAlg: level2.signingAlg,
      barcodeKeyAlg: level2.keyAlg,
      configuredSigningAlg: algorithms?.signingAlg,
      configuredKeyAlg: algorithms?.keyAlg,
    });
    if (!resolved.ok) return { valid: false, error: resolved.error };

    if (resolved.signing.type !== 'ECDSA') {
      return {
        valid: false,
        error: `Unsupported signing type for level 2: ${resolved.signing.type}`,
        algorithm: resolved.description,
        algorithmSource: resolved.source,
      };
    }

    return verifyEcdsaResult(
      2,
      level2.signature,
      level2.signedBytes,
      level2.publicKey,
      resolved,
    );
  } catch (e: unknown) {
    return { valid: false, error: e instanceof Error ? e.message : 'Verification failed' };
  }
}

/**
 * Verify Level 1 signature on a UIC barcode.
 *
 * Level 1 requires externally-provided key material since the key is not
 * embedded in the barcode. When the barcode also omits its algorithm OIDs,
 * supply them on the key material.
 *
 * @param input - Raw barcode payload bytes, or an already-extracted ticket.
 * @param key - The Level 1 public key and, optionally, its algorithms.
 * @returns Verification result with valid flag and optional error.
 */
export async function verifyLevel1Signature(
  input: Uint8Array | ExtractedTicket,
  key: Level1KeyMaterial,
): Promise<SignatureLevelResult> {
  try {
    const { level1 } = toExtractedTicket(input);

    if (!level1.signature) {
      return { valid: false, error: 'Missing level 1 signature' };
    }

    const resolved = resolveAlgorithms({
      level: 1,
      barcodeSigningAlg: level1.signingAlg,
      barcodeKeyAlg: level1.keyAlg,
      configuredSigningAlg: key.signingAlg,
      configuredKeyAlg: key.keyAlg,
    });
    if (!resolved.ok) return { valid: false, error: resolved.error };

    if (resolved.signing.type === 'DSA') {
      // DSA is not supported by @noble/curves
      // DSA signatures use the same DER format but different crypto primitives
      return {
        valid: false,
        error: `DSA verification not supported (algorithm: ${resolved.description})`,
        algorithm: resolved.description,
        algorithmSource: resolved.source,
      };
    }

    if (resolved.signing.type !== 'ECDSA') {
      return { valid: false, error: `Unsupported algorithm type: ${resolved.signing.type}` };
    }

    return verifyEcdsaResult(
      1,
      level1.signature,
      level1.signedBytes,
      key.publicKey,
      resolved,
    );
  } catch (e: unknown) {
    return { valid: false, error: e instanceof Error ? e.message : 'Verification failed' };
  }
}

/**
 * Verify both Level 1 and Level 2 signatures on a UIC barcode.
 *
 * @param input - Raw barcode payload bytes, or an already-extracted ticket.
 * @param options - Verification options (key provider or explicit key).
 * @returns Combined verification results for both levels.
 */
export async function verifySignatures(
  input: Uint8Array | ExtractedTicket,
  options?: VerifyOptions,
): Promise<SignatureVerificationResult> {
  let extracted: ExtractedTicket;
  try {
    extracted = toExtractedTicket(input);
  } catch (e: unknown) {
    const error = e instanceof Error ? e.message : 'Verification failed';
    return { level1: { valid: false, error }, level2: { valid: false, error } };
  }

  // Level 2 verification (self-contained)
  const level2 = await verifyLevel2Signature(extracted, options?.level2Algorithms);

  // Level 1 verification (needs external key material)
  let level1: SignatureLevelResult;

  if (options?.level1Key) {
    level1 = await verifyLevel1Signature(extracted, options.level1Key);
  } else if (options?.level1KeyProvider) {
    try {
      const material = await options.level1KeyProvider.getPublicKey(
        extracted.key,
        extracted.level1.keyAlg,
      );
      level1 = await verifyLevel1Signature(extracted, material);
    } catch (e: unknown) {
      level1 = {
        valid: false,
        error: `Key provider error: ${e instanceof Error ? e.message : 'unknown error'}`,
      };
    }
  } else {
    level1 = {
      valid: false,
      error: 'No level 1 public key provided (use level1Key or level1KeyProvider)',
    };
  }

  return { level1, level2 };
}

/**
 * Parse the UIC public key XML and find a key by issuer code and key ID.
 *
 * The registry records no algorithm metadata this library can use — its
 * `signatureAlgorithm` element is free-form vendor text (`'SHA1withDSA'`,
 * `'DSA1024'`, ...) and never identifies a curve — so `keyAlg` and
 * `signingAlg` are left unset. For a barcode that omits its own OIDs, add
 * them yourself:
 *
 * ```ts
 * const key = findKeyInXml(xml, issuerCode, keyId);
 * if (!key) throw new Error('Key not found');
 * return { ...key, signingAlg: '1.2.840.10045.4.3.2' };
 * ```
 *
 * @param xml - XML string from https://railpublickey.uic.org/download.php
 * @param issuerCode - The issuer RICS code (securityProviderNum), or a
 *   {@link SignatureKey} (e.g. from an extracted ticket or a signature group)
 * @param keyId - The key identifier (omitted when a SignatureKey is passed)
 * @returns Key material holding the decoded public key, or null if not found.
 *   A SignatureKey identifying its issuer with an IA5 string yields null:
 *   the registry is keyed by numeric RICS codes.
 */
export function findKeyInXml(xml: string, key: SignatureKey): Level1KeyMaterial | null;
export function findKeyInXml(xml: string, issuerCode: number, keyId: number): Level1KeyMaterial | null;
export function findKeyInXml(
  xml: string,
  keyOrIssuer: SignatureKey | number,
  maybeKeyId?: number,
): Level1KeyMaterial | null {
  const issuerCode = typeof keyOrIssuer === 'number'
    ? keyOrIssuer
    : keyOrIssuer.securityProviderNum;
  const keyId = typeof keyOrIssuer === 'number' ? maybeKeyId! : keyOrIssuer.keyId;
  if (issuerCode == null || keyId == null) return null;
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
        try {
          return { publicKey: base64ToBytes(b64) };
        } catch {
          // A corrupt entry must not look like a missing one.
          throw new Error(
            `Malformed base64 public key for issuer ${issuerCode}, key ${keyId}`,
          );
        }
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
      // The live registry contains at least one entry whose base64 is
      // truncated (length 1 mod 4). Skip those rather than losing every key.
      let publicKey: Uint8Array;
      try {
        publicKey = base64ToBytes(publicKeyB64.replace(/\s+/g, ''));
      } catch {
        continue;
      }
      entries.push({
        issuerCode,
        id,
        issuerName: issuerName ?? '',
        publicKey,
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
