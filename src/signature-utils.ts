/**
 * Signature format utilities for UIC barcode verification.
 *
 * Handles DER-to-raw and raw-to-DER conversion for ECDSA/DSA signatures
 * and public key format detection/extraction.
 */

/**
 * Parse a DER-encoded ECDSA/DSA signature into raw (r || s) concatenation.
 *
 * DER format:
 *   SEQUENCE { INTEGER r, INTEGER s }
 *
 * Raw format:
 *   r (componentLength bytes) || s (componentLength bytes)
 *
 * @param der - DER-encoded signature bytes
 * @param componentLength - Byte length of each component (32 for P-256, 48 for P-384, etc.)
 * @returns Raw (r || s) bytes
 */
export function derToRaw(der: Uint8Array, componentLength: number): Uint8Array {
  if (der[0] !== 0x30) {
    throw new Error(`Invalid DER signature: expected SEQUENCE tag 0x30, got 0x${der[0].toString(16)}`);
  }

  // Parse SEQUENCE length
  let offset = 1;
  let seqLen = der[offset++];
  if (seqLen & 0x80) {
    const lenBytes = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < lenBytes; i++) {
      seqLen = (seqLen << 8) | der[offset++];
    }
  }

  // Parse r INTEGER
  if (der[offset++] !== 0x02) {
    throw new Error('Invalid DER signature: expected INTEGER tag for r');
  }
  const rLen = der[offset++];
  const rStart = offset;
  offset += rLen;

  // Parse s INTEGER
  if (der[offset++] !== 0x02) {
    throw new Error('Invalid DER signature: expected INTEGER tag for s');
  }
  const sLen = der[offset++];
  const sStart = offset;

  const raw = new Uint8Array(componentLength * 2);

  // Copy r: strip leading 0x00 padding, right-align into componentLength bytes
  const rPad = rLen > componentLength ? rLen - componentLength : 0;
  const rDst = componentLength - (rLen - rPad);
  raw.set(der.slice(rStart + rPad, rStart + rLen), rDst);

  // Copy s: strip leading 0x00 padding, right-align into componentLength bytes
  const sPad = sLen > componentLength ? sLen - componentLength : 0;
  const sDst = componentLength + componentLength - (sLen - sPad);
  raw.set(der.slice(sStart + sPad, sStart + sLen), sDst);

  return raw;
}

/**
 * Convert a raw (r || s) ECDSA signature to DER format.
 *
 * This is the inverse of {@link derToRaw}.
 *
 * @param raw - Raw (r || s) signature bytes (2 * componentLength)
 * @param componentLength - Byte length of each component (32 for P-256, 48 for P-384, etc.)
 * @returns DER-encoded signature bytes
 */
export function rawToDer(raw: Uint8Array, componentLength: number): Uint8Array {
  const r = raw.slice(0, componentLength);
  const s = raw.slice(componentLength, componentLength * 2);

  const rInt = integerToDer(r);
  const sInt = integerToDer(s);

  const seqLen = rInt.length + sInt.length;
  const seqHeader = seqLen < 128
    ? new Uint8Array([0x30, seqLen])
    : new Uint8Array([0x30, 0x81, seqLen]);

  const der = new Uint8Array(seqHeader.length + seqLen);
  der.set(seqHeader, 0);
  der.set(rInt, seqHeader.length);
  der.set(sInt, seqHeader.length + rInt.length);
  return der;
}

/** Encode an unsigned big-endian integer as a DER INTEGER (tag 0x02 + length + value). */
function integerToDer(value: Uint8Array): Uint8Array {
  // Strip leading zeros
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) start++;

  // Add 0x00 prefix if high bit is set (to keep positive)
  const needsPad = value[start] & 0x80;
  const len = value.length - start + (needsPad ? 1 : 0);

  const result = new Uint8Array(2 + len);
  result[0] = 0x02; // INTEGER tag
  result[1] = len;
  if (needsPad) {
    result[2] = 0x00;
    result.set(value.slice(start), 3);
  } else {
    result.set(value.slice(start), 2);
  }
  return result;
}

/** SPKI header for EC P-256 (26 bytes: SEQUENCE > SEQUENCE > OID ecPublicKey > OID P-256 > BIT STRING). */
const SPKI_P256_HEADER = new Uint8Array([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
  0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
  0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
  0x42, 0x00,
]);

/**
 * Extract the raw EC public key point from a key that may be in SPKI DER format
 * or already a raw point (compressed or uncompressed).
 *
 * @param keyBytes - Public key bytes (SPKI DER or raw point)
 * @returns Raw EC point bytes (compressed or uncompressed)
 */
export function extractEcPublicKeyPoint(keyBytes: Uint8Array): Uint8Array {
  // Already a raw point (uncompressed 0x04 or compressed 0x02/0x03)
  if (keyBytes[0] === 0x04 || keyBytes[0] === 0x02 || keyBytes[0] === 0x03) {
    return keyBytes;
  }

  // DER-encoded structure (starts with SEQUENCE tag 0x30)
  if (keyBytes[0] === 0x30 && keyBytes.length > 33) {
    // Check for P-256 SPKI header (91 bytes: 26 header + 65 point)
    if (keyBytes.length === 91 && startsWith(keyBytes, SPKI_P256_HEADER)) {
      return keyBytes.slice(26);
    }

    // Could be an X.509 certificate or an SPKI structure.
    // Try extracting from X.509 first (certificates are longer, typically > 100 bytes),
    // fall back to SPKI extraction.
    if (keyBytes.length > 100) {
      try {
        return extractPointFromX509Certificate(keyBytes);
      } catch {
        // Not a valid certificate, try as SPKI
      }
    }

    return extractPointFromSpki(keyBytes);
  }

  throw new Error(`Unrecognized public key format: first byte 0x${keyBytes[0].toString(16)}, length ${keyBytes.length}`);
}

function startsWith(data: Uint8Array, prefix: Uint8Array): boolean {
  if (data.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (data[i] !== prefix[i]) return false;
  }
  return true;
}

/**
 * Extract EC point from a generic SPKI DER structure.
 * Walks the ASN.1 structure to find the BIT STRING containing the public key.
 */
function extractPointFromSpki(spki: Uint8Array): Uint8Array {
  let offset = 0;

  // Outer SEQUENCE
  if (spki[offset++] !== 0x30) throw new Error('Expected SEQUENCE');
  const outerLen = parseDerLength(spki, offset);
  offset = outerLen.offset;

  // AlgorithmIdentifier SEQUENCE (skip it)
  if (spki[offset++] !== 0x30) throw new Error('Expected AlgorithmIdentifier SEQUENCE');
  const algLen = parseDerLength(spki, offset);
  offset = algLen.offset + algLen.length;

  // BIT STRING containing the public key
  if (spki[offset++] !== 0x03) throw new Error('Expected BIT STRING');
  const bitStringLen = parseDerLength(spki, offset);
  offset = bitStringLen.offset;

  // Skip unused bits count byte (should be 0)
  offset++;

  // The rest is the raw public key point
  return spki.slice(offset, offset + bitStringLen.length - 1);
}

/**
 * Extract the EC public key point from a DER-encoded X.509 certificate.
 *
 * X.509 structure:
 *   SEQUENCE {
 *     SEQUENCE (tbsCertificate) {
 *       [0] EXPLICIT version, INTEGER serial, SEQUENCE algo,
 *       SEQUENCE issuer, SEQUENCE validity, SEQUENCE subject,
 *       SEQUENCE (subjectPublicKeyInfo) { ... }
 *     }
 *     SEQUENCE (signatureAlgorithm), BIT STRING (signature)
 *   }
 *
 * We walk through tbsCertificate fields to find the SPKI, then extract the key.
 */
function extractPointFromX509Certificate(cert: Uint8Array): Uint8Array {
  let offset = 0;

  // Outer SEQUENCE
  if (cert[offset++] !== 0x30) throw new Error('Expected SEQUENCE (certificate)');
  const certLen = parseDerLength(cert, offset);
  offset = certLen.offset;

  // tbsCertificate SEQUENCE
  if (cert[offset++] !== 0x30) throw new Error('Expected SEQUENCE (tbsCertificate)');
  const tbsLen = parseDerLength(cert, offset);
  offset = tbsLen.offset;

  // [0] EXPLICIT version (optional, tag = 0xA0)
  if (cert[offset] === 0xa0) {
    offset++;
    const vLen = parseDerLength(cert, offset);
    offset = vLen.offset + vLen.length;
  }

  // INTEGER serialNumber
  skipDerElement(cert, offset, (o) => { offset = o; });

  // SEQUENCE signature (algorithm)
  skipDerElement(cert, offset, (o) => { offset = o; });

  // SEQUENCE issuer
  skipDerElement(cert, offset, (o) => { offset = o; });

  // SEQUENCE validity
  skipDerElement(cert, offset, (o) => { offset = o; });

  // SEQUENCE subject
  skipDerElement(cert, offset, (o) => { offset = o; });

  // SEQUENCE subjectPublicKeyInfo — this is the SPKI
  if (cert[offset] !== 0x30) throw new Error('Expected SEQUENCE (subjectPublicKeyInfo)');
  const spkiStart = offset;
  const spkiTagLen = parseDerLength(cert, offset + 1);
  const spkiTotalLen = 1 + (spkiTagLen.offset - (offset + 1)) + spkiTagLen.length;
  const spki = cert.slice(spkiStart, spkiStart + spkiTotalLen);

  return extractPointFromSpki(spki);
}

function skipDerElement(data: Uint8Array, offset: number, cb: (newOffset: number) => void): void {
  offset++; // skip tag
  const len = parseDerLength(data, offset);
  cb(len.offset + len.length);
}

function parseDerLength(data: Uint8Array, offset: number): { length: number; offset: number } {
  let len = data[offset++];
  if (len & 0x80) {
    const numBytes = len & 0x7f;
    len = 0;
    for (let i = 0; i < numBytes; i++) {
      len = (len << 8) | data[offset++];
    }
  }
  return { length: len, offset };
}
