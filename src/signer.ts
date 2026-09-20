/**
 * Signing helpers for UIC barcode tickets.
 *
 * Signing goes through the {@link Signer} interface — the signing-side
 * counterpart of `Level1KeyProvider` on the verification side. A signer
 * wraps wherever the private key actually lives: in memory
 * ({@link localSigner}), in WebCrypto, in an HSM or a cloud KMS. All
 * signing entry points are asynchronous for that reason.
 *
 * Algorithm policy mirrors the verifier's "a disagreement is an error"
 * rule:
 *
 * - {@link signAndEncodeTicket} (high level) is authoritative: it writes the
 *   algorithm OIDs — and the Level 2 public key — from the signers into the
 *   header it encodes, so its output is always self-consistent.
 * - {@link signLevel1} / {@link signLevel2} (low level) sign the ticket's
 *   data exactly as given, because the caller controls the final encoding:
 *   an OID present on the ticket that contradicts the signer's curve is an
 *   error, and a missing OID stays missing (that is how barcodes whose
 *   algorithms are shared out of band are produced).
 */
import { p256, p384, p521 } from '@noble/curves/nist.js';

import { encodeLevel1Data, encodeLevel2Data, encodeLevel2SignedData, encodeUicBarcode } from './encoder.js';
import { rawToDer } from './signature-utils.js';
import type { RawBytes } from 'asn1-per-ts';
import type { UicBarcodeTicket, Level1Data } from './types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Supported ECDSA curve names. */
export type CurveName = 'P-256' | 'P-384' | 'P-521';

/** Curve configuration with OIDs for encoding into ticket headers. */
export interface CurveConfig {
  name: CurveName;
  /** Key algorithm OID (e.g. P-256 = 1.2.840.10045.3.1.7). */
  keyAlgOid: string;
  /** Signing algorithm OID (e.g. ECDSA-SHA256 = 1.2.840.10045.4.3.2). */
  sigAlgOid: string;
}

/** An ECDSA key pair, as returned by {@link generateKeyPair}. */
export interface SigningKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  curve: CurveName;
}

/**
 * A signing capability: the signing-side counterpart of `Level1KeyProvider`.
 *
 * Implement it over whatever holds the private key — {@link localSigner}
 * for a raw key in memory, or your own wrapper over WebCrypto
 * (non-extractable keys), an HSM or a cloud KMS.
 */
export interface Signer {
  /**
   * The ECDSA curve this signer signs with. It decides the algorithm OIDs
   * written into headers and the hash applied to the data (SHA-256 for
   * P-256, SHA-384 for P-384, SHA-512 for P-521).
   */
  readonly curve: CurveName;

  /**
   * Sign data and return a DER-encoded ECDSA signature.
   *
   * @param data - The bytes to sign; the implementation hashes them with
   *   the curve's associated hash before signing.
   */
  sign(data: Uint8Array): Promise<Uint8Array>;

  /**
   * The signer's public key (uncompressed EC point or SPKI DER).
   *
   * Optional: only required when the signer is used for Level 2, whose
   * public key is embedded in the barcode. A Level 1 signer can omit it.
   */
  getPublicKey?(): Promise<Uint8Array>;
}

// ---------------------------------------------------------------------------
// Curve registry
// ---------------------------------------------------------------------------

/** Curve configurations indexed by curve name. */
export const CURVES: Record<CurveName, CurveConfig> = {
  'P-256': {
    name: 'P-256',
    keyAlgOid: '1.2.840.10045.3.1.7',
    sigAlgOid: '1.2.840.10045.4.3.2',
  },
  'P-384': {
    name: 'P-384',
    keyAlgOid: '1.3.132.0.34',
    sigAlgOid: '1.2.840.10045.4.3.3',
  },
  'P-521': {
    name: 'P-521',
    keyAlgOid: '1.3.132.0.35',
    sigAlgOid: '1.2.840.10045.4.3.4',
  },
};

type CurveInstance = typeof p256;

function getCurve(curve: CurveName): CurveInstance {
  switch (curve) {
    case 'P-256': return p256;
    case 'P-384': return p384;
    case 'P-521': return p521;
  }
}

/** Component byte length for each curve. */
function componentLength(curve: CurveName): number {
  switch (curve) {
    case 'P-256': return 32;
    case 'P-384': return 48;
    case 'P-521': return 66;
  }
}

/**
 * Sign data with ECDSA and return a DER-encoded signature.
 *
 * @noble/curves returns compact (r || s) format, so we convert to DER
 * for compatibility with the UIC barcode standard.
 */
function ecSign(data: Uint8Array, privateKey: Uint8Array, curve: CurveName): Uint8Array {
  const c = getCurve(curve);
  const compactSig = c.sign(data, privateKey, { prehash: true, lowS: false });
  return rawToDer(compactSig, componentLength(curve));
}

// ---------------------------------------------------------------------------
// Signers
// ---------------------------------------------------------------------------

/**
 * A {@link Signer} over a raw private key held in memory.
 *
 * @param privateKey - The ECDSA private key bytes.
 * @param curve - The ECDSA curve to sign with.
 */
export function localSigner(privateKey: Uint8Array, curve: CurveName): Signer {
  return {
    curve,
    async sign(data: Uint8Array): Promise<Uint8Array> {
      return ecSign(data, privateKey, curve);
    },
    async getPublicKey(): Promise<Uint8Array> {
      return getCurve(curve).getPublicKey(privateKey, false);
    },
  };
}

/**
 * Sign arbitrary data with ECDSA and return a DER-encoded signature.
 *
 * This is the low-level synchronous signing primitive over a raw private
 * key; {@link localSigner} wraps it. It hashes the data with the curve's
 * associated hash (SHA-256 for P-256, etc.).
 *
 * @param data - The bytes to sign (will be hashed internally).
 * @param privateKey - The ECDSA private key bytes.
 * @param curve - The ECDSA curve to use.
 * @returns DER-encoded signature bytes.
 */
export function signPayload(
  data: Uint8Array,
  privateKey: Uint8Array,
  curve: CurveName,
): Uint8Array {
  return ecSign(data, privateKey, curve);
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

/**
 * Generate a new random ECDSA key pair.
 *
 * @param curve - The curve to use.
 * @returns A new key pair with uncompressed public key.
 */
export function generateKeyPair(curve: CurveName): SigningKeyPair {
  const c = getCurve(curve);
  const privateKey = c.utils.randomSecretKey();
  const publicKey = c.getPublicKey(privateKey, false);
  return { privateKey, publicKey, curve };
}

/**
 * Derive the uncompressed public key from a private key.
 *
 * @param privateKey - The private key bytes.
 * @param curve - The curve.
 * @returns Uncompressed public key bytes (0x04 || x || y).
 */
export function derivePublicKey(privateKey: Uint8Array, curve: CurveName): Uint8Array {
  const c = getCurve(curve);
  return c.getPublicKey(privateKey, false);
}

// ---------------------------------------------------------------------------
// Algorithm OID policy
// ---------------------------------------------------------------------------

/**
 * Error when a ticket carries an algorithm OID that contradicts the signer's
 * curve. A missing OID is fine here — the low-level functions sign the data
 * as given, and omitting the OIDs is how out-of-band-algorithm barcodes are
 * produced.
 */
function assertOidsMatchCurve(
  level: 1 | 2,
  keyAlg: string | undefined,
  signingAlg: string | undefined,
  curve: CurveName,
): void {
  const config = CURVES[curve];
  if (keyAlg !== undefined && keyAlg !== config.keyAlgOid) {
    throw new Error(
      `Ticket level${level}KeyAlg is ${keyAlg}, but the signer's curve ` +
      `${curve} implies ${config.keyAlgOid}. Fix the ticket's OIDs or use a ` +
      `signer for the matching curve — a silently divergent header would ` +
      `not verify.`,
    );
  }
  if (signingAlg !== undefined && signingAlg !== config.sigAlgOid) {
    throw new Error(
      `Ticket level${level}SigningAlg is ${signingAlg}, but the signer's ` +
      `curve ${curve} implies ${config.sigAlgOid}. Fix the ticket's OIDs or ` +
      `use a signer for the matching curve — a silently divergent header ` +
      `would not verify.`,
    );
  }
}

// ---------------------------------------------------------------------------
// Public API — individual level signing
// ---------------------------------------------------------------------------

/**
 * Sign the Level 1 data of a ticket, exactly as it stands.
 *
 * The ticket's `level1Data` is encoded as given and signed — nothing is
 * added or rewritten, so the bytes signed here are the bytes a final encode
 * of the same ticket will carry. In particular, absent algorithm OIDs stay
 * absent (the out-of-band-algorithm case); an OID that contradicts the
 * signer's curve is an error.
 *
 * @param ticket - The ticket whose `level1Data` to sign.
 * @param signer - The Level 1 signer.
 * @returns DER-encoded Level 1 signature bytes.
 */
export async function signLevel1(
  ticket: UicBarcodeTicket,
  signer: Signer,
): Promise<Uint8Array> {
  const l1 = ticket.level2SignedData.level1Data;
  assertOidsMatchCurve(1, l1.level1KeyAlg, l1.level1SigningAlg, signer.curve);
  const level1Raw = encodeLevel1Data(l1, ticket.format);
  return signer.sign(level1Raw.data);
}

/**
 * Sign the Level 2 data of a ticket, exactly as it stands.
 *
 * Encodes `level2SignedData` (level1Data + level1Signature + level2Data) as
 * given and signs it. Same as-given policy as {@link signLevel1}: absent
 * Level 2 algorithm OIDs stay absent, contradictory ones are an error.
 *
 * @param ticket - Ticket with `level2SignedData.level1Signature` already set.
 * @param signer - The Level 2 signer.
 * @returns DER-encoded Level 2 signature bytes.
 */
export async function signLevel2(
  ticket: UicBarcodeTicket,
  signer: Signer,
): Promise<Uint8Array> {
  const { level1Data, level1Signature, level2Data } = ticket.level2SignedData;
  if (!level1Signature) {
    throw new Error('Level 1 signature must be set before signing Level 2');
  }
  assertOidsMatchCurve(2, level1Data.level2KeyAlg, level1Data.level2SigningAlg, signer.curve);

  const headerVersion = parseInt(ticket.format.replace('U', ''), 10);
  const level1Raw = encodeLevel1Data(level1Data, ticket.format);
  const level2Raw = encodeLevel2SignedData({
    headerVersion,
    level1Data: level1Raw,
    level1Signature,
    level2Data: level2Data ? encodeLevel2Data(level2Data, ticket.format) : undefined,
  });
  return signer.sign(level2Raw.data);
}

/**
 * Sign and encode a complete ticket with both Level 1 and Level 2 signatures.
 *
 * The signers are authoritative for the header's security claims: the
 * algorithm OIDs are written from each signer's curve, and the Level 2
 * public key from the Level 2 signer, whatever the input ticket carried —
 * the output is always self-consistent. When `keys.level2` is omitted, only
 * Level 1 signing is performed (static barcode mode) and the ticket's
 * Level 2 fields are kept as-is.
 *
 * Flow, using the composable encoding primitives:
 * 1. Encode level1Data → sign → level1Signature
 * 2. Encode level2SignedData (with level1Data + signature) → sign → level2Signature
 * 3. Encode final UicBarcodeHeader
 *
 * @param ticket - Ticket data to encode (signature fields are overwritten).
 * @param keys - The Level 1 signer, and optionally the Level 2 signer. The
 *   Level 2 signer must expose `getPublicKey` — its key is embedded in the
 *   barcode.
 * @returns Encoded ticket bytes with valid signatures.
 */
export async function signAndEncodeTicket(
  ticket: UicBarcodeTicket,
  keys: { level1: Signer; level2?: Signer },
): Promise<Uint8Array> {
  const { level1, level2 } = keys;
  const l1Curve = CURVES[level1.curve];
  const l1 = ticket.level2SignedData.level1Data;

  let level2PublicKey = l1.level2PublicKey;
  if (level2) {
    if (!level2.getPublicKey) {
      throw new Error(
        'The Level 2 signer must expose getPublicKey(): its public key is embedded in the barcode',
      );
    }
    level2PublicKey = await level2.getPublicKey();
  }

  // Build level1Data with the signers' algorithm OIDs and the L2 public key.
  // The signers are authoritative — existing values are overwritten.
  const level1Data: Level1Data = {
    ...l1,
    level1KeyAlg: l1Curve.keyAlgOid,
    level2KeyAlg: level2 ? CURVES[level2.curve].keyAlgOid : l1.level2KeyAlg,
    level1SigningAlg: l1Curve.sigAlgOid,
    level2SigningAlg: level2 ? CURVES[level2.curve].sigAlgOid : l1.level2SigningAlg,
    level2PublicKey,
  };

  // Step 1: Encode level1Data
  const level1Raw = encodeLevel1Data(level1Data, ticket.format);

  // Step 2: Sign level1Data
  const level1Sig = await level1.sign(level1Raw.data);

  // Step 3: Build level2Data if present
  let level2DataEncoded: RawBytes | undefined;
  const l2 = ticket.level2SignedData.level2Data;
  if (l2) {
    level2DataEncoded = encodeLevel2Data(l2, ticket.format);
  }

  // Step 4: Encode level2SignedData
  const headerVersion = parseInt(ticket.format.replace('U', ''), 10);
  const level2Raw = encodeLevel2SignedData({
    headerVersion,
    level1Data: level1Raw,
    level1Signature: level1Sig,
    level2Data: level2DataEncoded,
  });

  // Step 5: Sign level2SignedData (if a Level 2 signer is provided)
  let level2Sig: Uint8Array | undefined;
  if (level2) {
    level2Sig = await level2.sign(level2Raw.data);
  }

  // Step 6: Encode final barcode
  return encodeUicBarcode({
    format: ticket.format,
    level2SignedData: level2Raw,
    level2Signature: level2Sig,
  });
}
