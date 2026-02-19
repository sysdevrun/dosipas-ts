/**
 * Composable encoding example — step-by-step ticket encoding and signing.
 *
 * This script demonstrates the low-level encoding primitives that
 * `signAndEncodeTicket` uses internally. Each step is explicit so you
 * can inspect or customise intermediate values.
 *
 * Run with:  npx tsx examples/encoder.ts
 */

import {
  generateKeyPair,
  CURVES,
  encodeLevel1Data,
  signPayload,
  encodeLevel2Data,
  encodeLevel2SignedData,
  encodeUicBarcode,
  decodeTicketFromBytes,
  verifyLevel1Signature,
  verifyLevel2Signature,
} from 'dosipas-ts';
import type { Level1Data, UicRailTicketData } from 'dosipas-ts';

// ── 1. Generate key pairs ───────────────────────────────────────────
// Level 1 key: held by the security provider (verified against external registry).
// Level 2 key: ephemeral, its public key is embedded in the barcode.

const l1Key = generateKeyPair('P-256');
const l2Key = generateKeyPair('P-256');

const l1Curve = CURVES['P-256'];
const l2Curve = CURVES['P-256'];

// ── 2. Build Level1Data ─────────────────────────────────────────────
// Contains security metadata, algorithm OIDs, the L2 public key, and
// a data sequence with the FCB3 rail ticket payload.

const railTicketData: UicRailTicketData = {
  issuingDetail: {
    issuerNum: 9901,
    issuingYear: 2025,
    issuingDay: 44,
    issuingTime: 720,
    activated: true,
    specimen: true,
    securePaperTicket: false,
  },
  travelerDetail: {
    traveler: [
      { firstName: 'Jane', lastName: 'Doe', ticketHolder: true },
    ],
  },
  transportDocument: [
    { ticket: { key: 'openTicket', value: { returnIncluded: false } } },
  ],
};

const level1Data: Level1Data = {
  securityProviderNum: 9901,
  keyId: 1,
  level1KeyAlg: l1Curve.keyAlgOid,
  level1SigningAlg: l1Curve.sigAlgOid,
  level2KeyAlg: l2Curve.keyAlgOid,
  level2SigningAlg: l2Curve.sigAlgOid,
  level2PublicKey: l2Key.publicKey,
  dataSequence: [
    { dataFormat: 'FCB3', decoded: railTicketData },
  ],
};

// ── 3. Encode Level1Data ────────────────────────────────────────────
// PER-encodes level1Data into a RawBytes object. The .data property
// holds the exact byte sequence that will be signed.

const format = 'U2';
const level1Raw = encodeLevel1Data(level1Data, format);

console.log('Level1Data encoded:', level1Raw.data.length, 'bytes');

// ── 4. Sign Level1Data ──────────────────────────────────────────────
// ECDSA signature over the encoded level1Data bytes.

const level1Sig = signPayload(level1Raw.data, l1Key.privateKey, 'P-256');

console.log('Level1 signature:', level1Sig.length, 'bytes (DER)');

// ── 5. Encode Level2Data (dynamic content) ──────────────────────────
// Optional dynamic barcode data (FDC1 format). This block changes on
// each scan and is signed by the Level 2 key.

const level2DataEncoded = encodeLevel2Data({
  dataFormat: 'FDC1',
  decoded: {
    dynamicContentTimeStamp: { day: 44, time: 720 },
  },
});

console.log('Level2Data encoded:', level2DataEncoded.data.length, 'bytes');

// ── 6. Encode Level2SignedData ──────────────────────────────────────
// Wraps level1Data (as RawBytes), the L1 signature, and the optional
// level2Data into a single ASN.1 SEQUENCE.

const level2Raw = encodeLevel2SignedData({
  level1Data: level1Raw,
  level1Signature: level1Sig,
  level2Data: level2DataEncoded,
});

console.log('Level2SignedData encoded:', level2Raw.data.length, 'bytes');

// ── 7. Sign Level2SignedData ────────────────────────────────────────
// ECDSA signature over the full level2SignedData bytes.

const level2Sig = signPayload(level2Raw.data, l2Key.privateKey, 'P-256');

console.log('Level2 signature:', level2Sig.length, 'bytes (DER)');

// ── 8. Encode UIC barcode header ────────────────────────────────────
// Produces the final barcode payload: header + level2SignedData + L2 sig.

const barcodeBytes = encodeUicBarcode({
  format,
  level2SignedData: level2Raw,
  level2Signature: level2Sig,
});

console.log('\nFinal barcode:', barcodeBytes.length, 'bytes');
console.log('Hex:', Buffer.from(barcodeBytes).toString('hex'));

// ── 9. Verify round-trip ────────────────────────────────────────────
// Decode the barcode and verify both signature levels.

const decoded = decodeTicketFromBytes(barcodeBytes);
console.log('\nDecoded format:', decoded.format);
console.log('Issuer:', decoded.level2SignedData.level1Data.securityProviderNum);
console.log('Data format:', decoded.level2SignedData.level1Data.dataSequence[0].dataFormat);

const l2Result = await verifyLevel2Signature(barcodeBytes);
console.log('\nLevel 2 signature valid:', l2Result.valid);

const l1Result = await verifyLevel1Signature(barcodeBytes, l1Key.publicKey);
console.log('Level 1 signature valid:', l1Result.valid);
