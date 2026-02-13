import { p256, p384, p521 } from '@noble/curves/nist.js';
import { encodeTicketToBytes, extractSignedData } from 'dosipas-ts';
import type { UicBarcodeTicketInput } from 'dosipas-ts';

export interface CurveConfig {
  name: string;
  keyAlgOid: string;
  sigAlgOid: string;
}

export const CURVES: Record<string, CurveConfig> = {
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

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  curve: string;
}

type CurveInstance = typeof p256;

function getCurve(curve: string): CurveInstance {
  switch (curve) {
    case 'P-256': return p256;
    case 'P-384': return p384;
    case 'P-521': return p521;
    default: throw new Error(`Unsupported curve: ${curve}`);
  }
}

export function generateKeyPair(curve: string): KeyPair {
  const c = getCurve(curve);
  const privateKey = c.utils.randomSecretKey();
  const publicKey = c.getPublicKey(privateKey, false);
  return { privateKey, publicKey, curve };
}

export function getPublicKey(privateKeyHex: string, curve: string): Uint8Array {
  const c = getCurve(curve);
  const privBytes = hexToBytes(privateKeyHex);
  return c.getPublicKey(privBytes, false);
}

function signData(data: Uint8Array, privateKey: Uint8Array, curve: string): Uint8Array {
  const c = getCurve(curve);
  return c.sign(data, privateKey, { prehash: true, lowS: false });
}

/**
 * Two-pass signing flow:
 * 1. Encode with zero signatures -> extract signed data -> sign L1
 * 2. Encode with real L1 + zero L2 -> extract signed data -> sign L2
 * 3. Encode final with both real signatures
 *
 * When level2Key is undefined, only L1 signing is performed (static barcode mode).
 */
export function signTicket(
  input: UicBarcodeTicketInput,
  level1Key: KeyPair,
  level2Key?: KeyPair,
): Uint8Array {
  const l1Curve = CURVES[level1Key.curve];

  const baseInput: UicBarcodeTicketInput = {
    ...input,
    level1KeyAlg: l1Curve.keyAlgOid,
    level1SigningAlg: l1Curve.sigAlgOid,
  };

  if (level2Key) {
    const l2Curve = CURVES[level2Key.curve];
    baseInput.level2KeyAlg = l2Curve.keyAlgOid;
    baseInput.level2SigningAlg = l2Curve.sigAlgOid;
    baseInput.level2PublicKey = level2Key.publicKey;
  }

  // Pass 1: encode with zero sigs, sign L1
  const zeroL1Size = level1Key.curve === 'P-521' ? 139 : level1Key.curve === 'P-384' ? 104 : 72;
  const zeroL1 = new Uint8Array(zeroL1Size);
  const zeroL2 = new Uint8Array(level2Key
    ? (level2Key.curve === 'P-521' ? 139 : level2Key.curve === 'P-384' ? 104 : 72)
    : 0,
  );

  const pass1Bytes = encodeTicketToBytes({
    ...baseInput,
    level1Signature: zeroL1,
    level2Signature: zeroL2,
  });

  const extracted1 = extractSignedData(pass1Bytes);
  const level1Sig = signData(extracted1.level1DataBytes, level1Key.privateKey, level1Key.curve);

  if (!level2Key) {
    // Static barcode: only L1 signed
    return encodeTicketToBytes({
      ...baseInput,
      level1Signature: level1Sig,
      level2Signature: zeroL2,
    });
  }

  // Pass 2: encode with real L1 + zero L2, sign L2
  const pass2Bytes = encodeTicketToBytes({
    ...baseInput,
    level1Signature: level1Sig,
    level2Signature: zeroL2,
  });

  const extracted2 = extractSignedData(pass2Bytes);
  const level2Sig = signData(extracted2.level2SignedBytes, level2Key.privateKey, level2Key.curve);

  // Final: encode with both real sigs
  return encodeTicketToBytes({
    ...baseInput,
    level1Signature: level1Sig,
    level2Signature: level2Sig,
  });
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
