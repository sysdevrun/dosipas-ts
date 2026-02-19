/**
 * Signing helpers for UIC barcode tickets.
 *
 * Provides functions to sign Level 1 data, Level 2 data, or both, using
 * ECDSA private keys. The two-pass signing flow is:
 *
 * 1. Encode with placeholder (zero) signatures
 * 2. Extract signed data bytes, sign Level 1
 * 3. Re-encode with real Level 1 + placeholder Level 2
 * 4. Extract signed data bytes, sign Level 2
 * 5. Final encode with both real signatures
 */
import { p256, p384, p521 } from '@noble/curves/nist.js';

import { encodeLevel1Data, encodeLevel2Data, encodeLevel2SignedData, encodeUicBarcode, encodeTicketToBytes } from './encoder';
import { extractSignedData } from './signed-data';
import { rawToDer } from './signature-utils';
import type { UicBarcodeTicket, Level1Data } from './types';

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

/** An ECDSA key pair for signing. */
export interface SigningKeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  curve: CurveName;
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

/** Maximum DER signature size for each curve. */
function maxDerSigSize(curve: CurveName): number {
  switch (curve) {
    case 'P-256': return 72;
    case 'P-384': return 104;
    case 'P-521': return 139;
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
// Public signing primitive
// ---------------------------------------------------------------------------

/**
 * Sign arbitrary data with ECDSA and return a DER-encoded signature.
 *
 * This is the low-level signing primitive used by the composable encoding flow.
 * It hashes the data with the curve's associated hash (SHA-256 for P-256, etc.)
 * and returns a DER-encoded ECDSA signature.
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
// Key generation helper
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
export function getPublicKey(privateKey: Uint8Array, curve: CurveName): Uint8Array {
  const c = getCurve(curve);
  return c.getPublicKey(privateKey, false);
}

// ---------------------------------------------------------------------------
// Public API — individual level signing
// ---------------------------------------------------------------------------

/**
 * Sign Level 1 data of a ticket.
 *
 * Encodes the ticket with a zero-filled Level 1 signature placeholder,
 * extracts the Level 1 signed data, and produces the DER signature.
 *
 * @param ticket - Ticket (level1Signature will be overwritten with a zero placeholder).
 * @param privateKey - Level 1 private key bytes.
 * @param curve - The ECDSA curve.
 * @returns DER-encoded Level 1 signature bytes.
 */
export function signLevel1(
  ticket: UicBarcodeTicket,
  privateKey: Uint8Array,
  curve: CurveName,
): Uint8Array {
  const curveConfig = CURVES[curve];
  const zeroSig = new Uint8Array(maxDerSigSize(curve));
  const l1 = ticket.level2SignedData.level1Data;

  const prepared: UicBarcodeTicket = {
    ...ticket,
    level2SignedData: {
      ...ticket.level2SignedData,
      level1Data: {
        ...l1,
        level1KeyAlg: l1.level1KeyAlg ?? curveConfig.keyAlgOid,
        level1SigningAlg: l1.level1SigningAlg ?? curveConfig.sigAlgOid,
      },
      level1Signature: zeroSig,
    },
    level2Signature: ticket.level2Signature ?? new Uint8Array(0),
  };

  const bytes = encodeTicketToBytes(prepared);
  const extracted = extractSignedData(bytes);
  return ecSign(extracted.level1DataBytes, privateKey, curve);
}

/**
 * Sign Level 2 data of a ticket.
 *
 * Encodes the ticket with the provided Level 1 signature and a zero-filled
 * Level 2 placeholder, extracts the Level 2 signed data, and produces the
 * DER signature.
 *
 * @param ticket - Ticket with `level2SignedData.level1Signature` already set.
 * @param privateKey - Level 2 private key bytes.
 * @param curve - The ECDSA curve.
 * @returns DER-encoded Level 2 signature bytes.
 */
export function signLevel2(
  ticket: UicBarcodeTicket,
  privateKey: Uint8Array,
  curve: CurveName,
): Uint8Array {
  if (!ticket.level2SignedData.level1Signature) {
    throw new Error('Level 1 signature must be set before signing Level 2');
  }

  const curveConfig = CURVES[curve];
  const zeroSig = new Uint8Array(maxDerSigSize(curve));
  const l1 = ticket.level2SignedData.level1Data;

  const prepared: UicBarcodeTicket = {
    ...ticket,
    level2SignedData: {
      ...ticket.level2SignedData,
      level1Data: {
        ...l1,
        level2KeyAlg: l1.level2KeyAlg ?? curveConfig.keyAlgOid,
        level2SigningAlg: l1.level2SigningAlg ?? curveConfig.sigAlgOid,
      },
    },
    level2Signature: zeroSig,
  };

  const bytes = encodeTicketToBytes(prepared);
  const extracted = extractSignedData(bytes);
  return ecSign(extracted.level2SignedBytes, privateKey, curve);
}

/**
 * Sign and encode a complete ticket with both Level 1 and Level 2 signatures.
 *
 * Uses the composable encoding primitives:
 * 1. Encode level1Data → sign → level1Signature
 * 2. Encode level2SignedData (with level1Data + signature) → sign → level2Signature
 * 3. Encode final UicBarcodeHeader
 *
 * When `level2Key` is omitted, only Level 1 signing is performed (static barcode mode).
 *
 * @param ticket - Ticket data to encode (signature fields are overwritten).
 * @param level1Key - Level 1 signing key pair.
 * @param level2Key - Optional Level 2 signing key pair.
 * @returns Encoded ticket bytes with valid signatures.
 */
export function signAndEncodeTicket(
  ticket: UicBarcodeTicket,
  level1Key: SigningKeyPair,
  level2Key?: SigningKeyPair,
): Uint8Array {
  const l1Curve = CURVES[level1Key.curve];
  const l1 = ticket.level2SignedData.level1Data;

  // Build level1Data with algorithm OIDs and L2 public key.
  // Always set OIDs from the key pair (overriding any existing values from a decoded ticket).
  const level1Data: Level1Data = {
    ...l1,
    level1KeyAlg: l1Curve.keyAlgOid,
    level2KeyAlg: level2Key ? CURVES[level2Key.curve].keyAlgOid : l1.level2KeyAlg,
    level1SigningAlg: l1Curve.sigAlgOid,
    level2SigningAlg: level2Key ? CURVES[level2Key.curve].sigAlgOid : l1.level2SigningAlg,
    level2PublicKey: level2Key ? level2Key.publicKey : l1.level2PublicKey,
  };

  // Step 1: Encode level1Data
  const level1Raw = encodeLevel1Data(level1Data, ticket.format);

  // Step 2: Sign level1Data
  const level1Sig = signPayload(level1Raw.data, level1Key.privateKey, level1Key.curve);

  // Step 3: Build level2Data if present
  let level2DataEncoded: { dataFormat: string; data: Uint8Array } | undefined;
  const l2 = ticket.level2SignedData.level2Data;
  if (l2) {
    level2DataEncoded = encodeLevel2Data(l2);
  }

  // Step 4: Encode level2SignedData
  const headerVersion = parseInt(ticket.format.replace('U', ''), 10);
  const level2Raw = encodeLevel2SignedData({
    headerVersion,
    level1Data: level1Raw,
    level1Signature: level1Sig,
    level2Data: level2DataEncoded,
  });

  // Step 5: Sign level2SignedData (if level2Key provided)
  let level2Sig: Uint8Array | undefined;
  if (level2Key) {
    level2Sig = signPayload(level2Raw.data, level2Key.privateKey, level2Key.curve);
  }

  // Step 6: Encode final barcode
  return encodeUicBarcode({
    format: ticket.format,
    level2SignedData: level2Raw,
    level2Signature: level2Sig,
  });
}
