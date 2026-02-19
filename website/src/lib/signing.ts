import {
  signAndEncodeTicket,
  signLevel1 as libSignLevel1,
  signLevel2 as libSignLevel2,
  encodeTicketToBytes as libEncodeTicketToBytes,
  getPublicKey as libGetPublicKey,
  generateKeyPair as libGenerateKeyPair,
  CURVES,
} from 'dosipas-ts';
import type { UicBarcodeTicket, CurveName, SigningKeyPair } from 'dosipas-ts';

export type { CurveName, SigningKeyPair as KeyPair };
export { CURVES };

export function generateKeyPair(curve: string): SigningKeyPair {
  return libGenerateKeyPair(curve as CurveName);
}

export function getPublicKey(privateKeyHex: string, curve: string): Uint8Array {
  return libGetPublicKey(hexToBytes(privateKeyHex), curve as CurveName);
}

/**
 * Sign and encode a ticket using the library's two-pass signing flow.
 *
 * When level2Key is undefined, only L1 signing is performed (static barcode mode).
 */
export function signTicket(
  ticket: UicBarcodeTicket,
  level1Key: SigningKeyPair,
  level2Key?: SigningKeyPair,
): Uint8Array {
  return signAndEncodeTicket(ticket, level1Key, level2Key);
}

/** Sign Level 1 data and return the DER-encoded signature bytes. */
export function signLevel1Data(
  ticket: UicBarcodeTicket,
  privateKeyHex: string,
  curve: string,
): Uint8Array {
  return libSignLevel1(ticket, hexToBytes(privateKeyHex), curve as CurveName);
}

/** Sign Level 2 data and return the DER-encoded signature bytes. */
export function signLevel2Data(
  ticket: UicBarcodeTicket,
  privateKeyHex: string,
  curve: string,
): Uint8Array {
  return libSignLevel2(ticket, hexToBytes(privateKeyHex), curve as CurveName);
}

/** Encode a ticket to bytes (with signatures already set). */
export function encodeTicket(ticket: UicBarcodeTicket): Uint8Array {
  return libEncodeTicketToBytes(ticket);
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
